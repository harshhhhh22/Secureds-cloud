
import re

from flask import (
    Blueprint, current_app, flash, redirect, render_template,
    request, url_for,
)
from flask_login import current_user, login_user, logout_user

from extensions import db
from models import LoginEvent, User

auth = Blueprint("auth", __name__)

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def record_login_event(user, event_type):
    """Save a minimal login audit event without storing the raw IP address."""
    if user is None:
        return

    try:
        user_agent = request.headers.get("User-Agent", "")[:300] or None

        event = LoginEvent(
            user_id=user.id,
            event_type=event_type,
            user_agent=user_agent,
            # IP geolocation is intentionally not guessed.
            # Add an explicitly configured geolocation provider later.
            location=None,
        )
        db.session.add(event)
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Could not save login activity.")


@auth.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(email) > 254 or not EMAIL_PATTERN.fullmatch(email):
            flash("Enter a valid email address.", "error")
            return render_template("signup.html"), 400

        if len(password) < 12:
            flash("Your password must contain at least 12 characters.", "error")
            return render_template("signup.html"), 400

        if len(password) > 1024:
            flash("Your password is too long.", "error")
            return render_template("signup.html"), 400

        if password != confirm_password:
            flash("The passwords do not match.", "error")
            return render_template("signup.html"), 400

        if User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "error")
            return render_template("signup.html"), 409

        user = User(email=email)
        user.set_password(password)

        try:
            db.session.add(user)
            db.session.commit()
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Account registration failed.")
            flash("Registration failed. Please try again.", "error")
            return render_template("signup.html"), 500

        flash("Account created successfully. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("signup.html")


@auth.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user is None or not user.check_password(password):
            record_login_event(user, "failed")
            flash("Invalid email or password.", "error")
            return render_template("login.html"), 401

        try:
            if user.needs_password_rehash():
                user.set_password(password)

            login_user(user, remember=False, fresh=True)
            record_login_event(user, "success")
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Login processing failed.")
            flash("Login failed. Please try again.", "error")
            return render_template("login.html"), 500

        return redirect(url_for("dashboard"))

    return render_template("login.html")


@auth.route("/logout", methods=["POST"])
def logout():
    if current_user.is_authenticated:
        logout_user()

    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))
