
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import current_user, login_required

from archive_handler import ArchiveValidationError, validate_zip_bytes
from analyzers.structure import analyze_structure
from analyzers.code_security import analyze_code_security
from analyzers.dependencies import analyze_dependencies
from analyzers.cicd import analyze_cicd

from auth import auth
from extensions import csrf, db, login_manager
from models import LoginEvent, Scan, User


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env", override=False)


def get_severity_counts(scans):
    """Count findings by severity across saved scan reports."""
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "other": 0,
    }

    for scan in scans:
        try:
            report = json.loads(scan.report_json or "{}")
        except (TypeError, json.JSONDecodeError):
            continue

        results = report.get("results", {})

        if not isinstance(results, dict):
            continue

        for analyzer_result in results.values():
            if not isinstance(analyzer_result, dict):
                continue

            findings = analyzer_result.get("findings", [])

            if not isinstance(findings, list):
                continue

            for finding in findings:
                if not isinstance(finding, dict):
                    continue

                severity = str(
                    finding.get("severity", "other")
                ).lower()

                if severity in counts:
                    counts[severity] += 1
                else:
                    counts["other"] += 1

    return counts


def create_app(test_config=None):
    app = Flask(
        __name__,
        instance_relative_config=True,
    )

    Path(app.instance_path).mkdir(
        parents=True,
        exist_ok=True,
    )

    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        SQLALCHEMY_DATABASE_URI=os.environ.get(
            "DATABASE_URL",
            "sqlite:///securedeps.db",
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,

        # Upload and session security.
        MAX_CONTENT_LENGTH=200 * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=(
            os.environ.get("COOKIE_SECURE", "false").lower()
            == "true"
        ),
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SECURE=(
            os.environ.get("COOKIE_SECURE", "false").lower()
            == "true"
        ),

        # CSRF and rate limiting.
        WTF_CSRF_TIME_LIMIT=3600,
        RATELIMIT_STORAGE_URI=os.environ.get(
            "RATELIMIT_STORAGE_URI",
            "memory://",
        ),
    )

    if test_config:
        app.config.update(test_config)

    if not app.config.get("SECRET_KEY"):
        if app.config.get("TESTING"):
            app.config["SECRET_KEY"] = "test-only-secret-key"
        else:
            raise RuntimeError(
                "SECRET_KEY is missing. Set it in your .env file."
            )

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=[
            "200 per day",
            "50 per hour",
        ],
        storage_uri=app.config["RATELIMIT_STORAGE_URI"],
    )
    limiter.init_app(app)

    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please log in to continue."
    login_manager.login_message_category = "error"

    @login_manager.user_loader
    def load_user(user_id):
        try:
            return db.session.get(User, int(user_id))
        except (TypeError, ValueError):
            return None

    @login_manager.unauthorized_handler
    def unauthorized():
        if request.path.startswith("/api/"):
            return jsonify({
                "error": "Authentication required."
            }), 401

        return redirect(url_for("auth.login"))

    app.register_blueprint(auth)

    # Authentication rate limits.
    limiter.limit("5 per hour")(
        app.view_functions["auth.signup"]
    )
    limiter.limit("5 per minute")(
        app.view_functions["auth.login"]
    )

    @app.get("/")
    def home():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        return redirect(url_for("auth.login"))

    @app.get("/api/health")
    def health_check():
        return jsonify({
            "status": "healthy",
            "application": "SecureDeps Cloud",
            "version": "0.3.0",
        }), 200

    @app.get("/dashboard")
    @login_required
    def dashboard():
        scans = (
            Scan.query
            .filter_by(user_id=current_user.id)
            .order_by(Scan.created_at.desc())
            .all()
        )

        recent_scans = scans[:5]
        severity_counts = get_severity_counts(scans)

        # Build the last seven calendar days, including today.
        today = datetime.now(timezone.utc).date()
        start_date = today - timedelta(days=6)

        daily_counts = {
            (start_date + timedelta(days=i)): 0
            for i in range(7)
        }

        for scan in scans:
            created_at = scan.created_at

            if created_at is None:
                continue

            # SQLite may return a naive datetime. Treat stored
            # timestamps as UTC when timezone information is absent.
            if created_at.tzinfo is None:
                created_at = created_at.replace(
                    tzinfo=timezone.utc
                )

            scan_date = created_at.astimezone(
                timezone.utc
            ).date()

            if scan_date in daily_counts:
                daily_counts[scan_date] += 1

        scan_labels = [
            day.strftime("%b %d")
            for day in daily_counts
        ]
        scan_values = list(daily_counts.values())

        return render_template(
            "dashboard.html",
            scans=recent_scans,
            recent_scans=recent_scans,
            total_scans=len(scans),
            severity_counts=severity_counts,
            scan_labels=scan_labels,
            scan_values=scan_values,
        )

    @app.get("/history")
    @login_required
    def history():
        scans = (
            Scan.query
            .filter_by(user_id=current_user.id)
            .order_by(Scan.created_at.desc())
            .all()
        )

        return render_template(
            "history.html",
            scans=scans,
        )

    @app.get("/history/<int:scan_id>")
    @login_required
    def scan_report(scan_id):
        # Users can only access their own reports.
        scan = Scan.query.filter_by(
            id=scan_id,
            user_id=current_user.id,
        ).first_or_404()

        try:
            report = json.loads(scan.report_json)
        except (TypeError, json.JSONDecodeError):
            abort(500)

        return render_template(
            "report.html",
            scan=scan,
            report=report,
        )

    @app.get("/security-activity")
    @login_required
    def security_activity():
        events = (
            LoginEvent.query
            .filter_by(user_id=current_user.id)
            .order_by(LoginEvent.created_at.desc())
            .limit(100)
            .all()
        )

        return render_template(
            "security_activity.html",
            events=events,
        )

    @app.post("/api/scan")
    @login_required
    def scan_project():
        uploaded_file = request.files.get("file")

        if uploaded_file is None:
            return jsonify({
                "error": (
                    "No file uploaded. "
                    "Use the form field named 'file'."
                )
            }), 400

        filename = (uploaded_file.filename or "").strip()

        if not filename:
            return jsonify({
                "error": "Please select a ZIP file."
            }), 400

        if not filename.lower().endswith(".zip"):
            return jsonify({
                "error": "Only .zip files are accepted."
            }), 400

        archive = None

        try:
            zip_data = uploaded_file.read()
            archive = validate_zip_bytes(zip_data)

            try:
                # Run all four analyzers against the validated ZIP.
                structure_result = analyze_structure(archive)
                code_result = analyze_code_security(archive)
                dependency_result = analyze_dependencies(archive)
                cicd_result = analyze_cicd(archive)

            finally:
                archive.close()
                archive = None

            # Combine findings from every implemented analyzer.
            findings = (
                structure_result["findings"]
                + code_result["findings"]
                + dependency_result["findings"]
                + cicd_result["findings"]
            )

            report = {
                "message": "Project analysis completed.",
                "analysis_status": "partial",

                "analyzers_completed": [
                    "structure",
                    "code_security",
                    "dependencies",
                    "cicd",
                ],

                "summary": {
                    "files_inspected": (
                        structure_result.get("files_inspected", 0)
                        + code_result.get("files_inspected", 0)
                        + cicd_result.get("files_inspected", 0)
                    ),
                    "requirements_files_found": len(
                        dependency_result.get(
                            "requirements_files_found", []
                        )
                    ),
                    "pinned_dependencies_checked": (
                        dependency_result.get(
                            "pinned_dependencies_checked", 0
                        )
                    ),
                    "cicd_files_inspected": (
                        cicd_result.get("files_inspected", 0)
                    ),
                    "total_findings": len(findings),
                },

                "results": {
                    "structure": structure_result,
                    "code_security": code_result,
                    "dependencies": dependency_result,
                    "cicd": cicd_result,
                },

                "note": (
                    "CI/CD checks inspect supported GitHub Actions, "
                    "GitLab CI, Jenkins, and Dockerfile patterns. "
                    "Documentation checks are not implemented yet. "
                    "Dependency checks cover supported requirements "
                    "files and exactly pinned package versions. "
                    "Pattern-based findings require manual review."
                ),
            }

            # Save the report for the authenticated user.
            scan = Scan(
                user_id=current_user.id,
                filename=Path(filename).name[:255],
                analysis_status=report["analysis_status"],
                findings_count=len(findings),
                report_json=json.dumps(report),
            )

            db.session.add(scan)
            db.session.commit()

            response = dict(report)
            response["scan_id"] = scan.id
            response["history_url"] = url_for(
                "scan_report",
                scan_id=scan.id,
            )

            return jsonify(response), 200

        except ArchiveValidationError as exc:
            return jsonify({
                "error": str(exc)
            }), 400

        except Exception:
            db.session.rollback()

            app.logger.exception(
                "Unexpected error while analyzing an upload."
            )

            return jsonify({
                "error": (
                    "An unexpected error occurred during analysis. "
                    "Please try again with a valid ZIP file."
                )
            }), 500

        finally:
            if archive is not None:
                archive.close()

    @app.errorhandler(413)
    def request_too_large(_error):
        return jsonify({
            "error": (
                "The upload is too large. "
                "The maximum size is 200 MB."
            )
        }), 413

    with app.app_context():
        db.create_all()

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000,
    )
