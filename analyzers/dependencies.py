
import re
import zipfile
from pathlib import PurePosixPath

import requests


OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
REQUEST_TIMEOUT = 8

REQUIREMENTS_FILES = {
    "requirements.txt",
    "requirements-dev.txt",
    "dev-requirements.txt",
}


def _parse_requirement(line):
    """Return (package_name, exact_version) for a simple requirement."""
    line = line.split("#", 1)[0].strip()

    if not line or line.startswith(("-", "git+", "http:", "https:")):
        return None

    # This first version supports simple PyPI package pins such as:
    # requests==2.31.0
    match = re.match(
        r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*"
        r"(?:\[[^\]]+\])?\s*"
        r"(==|===|~=|!=|<=|>=|<|>)\s*"
        r"([A-Za-z0-9.*+!_-]+)",
        line,
    )

    if not match:
        return None

    name, operator, version = match.groups()

    if operator != "==" or "*" in version:
        return (name, None)

    return (name, version)


def _severity_for(vulnerability):
    """Use an explicit severity label when the OSV record provides one."""
    database_severity = vulnerability.get(
        "database_specific", {}
    ).get("severity")

    if isinstance(database_severity, str):
        normalized = database_severity.upper()

        if normalized in {"CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW"}:
            return {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "MODERATE": "medium",
                "LOW": "low",
            }[normalized]

    return "unknown"


def _fixed_versions(vulnerability, package_name):
    versions = set()

    for affected in vulnerability.get("affected", []):
        package = affected.get("package", {})

        if package.get("name", "").lower() != package_name.lower():
            continue

        for event in affected.get("ranges", []):
            for event_item in event.get("events", []):
                fixed = event_item.get("fixed")
                if fixed:
                    versions.add(fixed)

    return sorted(versions)


def analyze_dependencies(archive: zipfile.ZipFile):
    findings = []
    requirements_found = []
    packages_to_query = []
    packages_skipped = []

    for entry in archive.infolist():
        path = PurePosixPath(entry.filename)

        if entry.is_dir():
            continue

        if path.name.lower() not in REQUIREMENTS_FILES:
            continue

        if entry.file_size > 256 * 1024:
            findings.append({
                "category": "dependencies",
                "severity": "info",
                "title": "Requirements file skipped: size limit",
                "file": str(path),
                "line": None,
                "evidence": "The requirements file exceeds 256 KB.",
                "recommendation": "Review the file separately.",
                "confirmed_issue": False,
            })
            continue

        requirements_found.append(str(path))

        try:
            content = archive.read(entry).decode("utf-8-sig")
        except (UnicodeDecodeError, OSError, zipfile.BadZipFile):
            findings.append({
                "category": "dependencies",
                "severity": "info",
                "title": "Requirements file could not be decoded",
                "file": str(path),
                "line": None,
                "evidence": "The file could not be read as UTF-8 text.",
                "recommendation": "Check the file encoding.",
                "confirmed_issue": False,
            })
            continue

        for line_number, line in enumerate(content.splitlines(), start=1):
            parsed = _parse_requirement(line)

            if parsed is None:
                continue

            package_name, version = parsed

            if version is None:
                packages_skipped.append(package_name)
                findings.append({
                    "category": "dependencies",
                    "severity": "info",
                    "title": "Dependency version is not exactly pinned",
                    "file": str(path),
                    "line": line_number,
                    "evidence": (
                        f"{package_name} does not use a supported exact "
                        "version pin in this requirements file."
                    ),
                    "recommendation": (
                        "Pin and resolve the dependency version before "
                        "performing a version-specific vulnerability check."
                    ),
                    "confirmed_issue": False,
                })
                continue

            packages_to_query.append({
                "name": package_name,
                "version": version,
                "file": str(path),
                "line": line_number,
            })

    if not requirements_found:
        findings.append({
            "category": "dependencies",
            "severity": "info",
            "title": "No supported requirements file found",
            "file": None,
            "line": None,
            "evidence": (
                "No requirements.txt, requirements-dev.txt, or "
                "dev-requirements.txt file was found."
            ),
            "recommendation": (
                "If the project uses pip requirements files, consider "
                "including its dependency declarations."
            ),
            "confirmed_issue": False,
        })

    # Query OSV in batches. Never fail the whole scan if the service is down.
    if packages_to_query:
        payload = {
            "queries": [
                {
                    "package": {
                        "name": item["name"],
                        "ecosystem": "PyPI",
                    },
                    "version": item["version"],
                }
                for item in packages_to_query
            ]
        }

        try:
            response = requests.post(
                OSV_BATCH_URL,
                json=payload,
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            results = response.json().get("results", [])

            if len(results) != len(packages_to_query):
                raise ValueError("Unexpected OSV response length")

            for package, result in zip(packages_to_query, results):
                for vulnerability in result.get("vulns", []):
                    vuln_id = vulnerability.get("id", "Unknown ID")
                    summary = vulnerability.get(
                        "summary", "Known vulnerability"
                    )
                    fixed = _fixed_versions(vulnerability, package["name"])

                    recommendation = (
                        "Review the advisory and upgrade to a version "
                        "confirmed as fixed by the advisory."
                    )

                    if fixed:
                        recommendation = (
                            "Review the advisory and update to a fixed "
                            "version where compatible. Fixed version(s) "
                            "listed by the advisory: "
                            + ", ".join(fixed)
                        )

                    findings.append({
                        "category": "dependencies",
                        "severity": _severity_for(vulnerability),
                        "title": f"Known dependency vulnerability: {vuln_id}",
                        "file": package["file"],
                        "line": package["line"],
                        "evidence": (
                            f"{package['name']}=={package['version']}: "
                            f"{summary}"
                        ),
                        "recommendation": recommendation,
                        "vulnerability_id": vuln_id,
                        "confirmed_issue": True,
                    })

        except (requests.RequestException, ValueError, TypeError):
            findings.append({
                "category": "dependencies",
                "severity": "info",
                "title": "Dependency vulnerability lookup unavailable",
                "file": None,
                "line": None,
                "evidence": (
                    "OSV.dev could not be queried successfully. "
                    "Dependency vulnerability status is unknown."
                ),
                "recommendation": (
                    "Retry the scan when the vulnerability service is "
                    "available. Do not interpret this as a clean result."
                ),
                "confirmed_issue": False,
            })

    return {
        "analyzer": "dependencies",
        "requirements_files_found": sorted(set(requirements_found)),
        "pinned_dependencies_checked": len(packages_to_query),
        "dependencies_skipped": len(packages_skipped),
        "findings": findings,
    }
