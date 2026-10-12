
import re
from pathlib import PurePosixPath


MAX_CICD_FILES = 100
MAX_FILE_SIZE = 512 * 1024
MAX_TOTAL_SIZE = 5 * 1024 * 1024

WORKFLOW_PATTERNS = (
    re.compile(r"^\.github/workflows/[^/]+\.(?:yml|yaml)$", re.I),
    re.compile(r"^\.gitlab-ci\.yml$", re.I),
    re.compile(r"(^|/)Jenkinsfile$", re.I),
    re.compile(r"(^|/)Dockerfile(?:\.[^/]*)?$", re.I),
)

SECRET_PATTERNS = (
    re.compile(r"""(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)\b\s*[:=]\s*["']?([^\s"'${}]+)"""),
    re.compile(r"(?i)\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)


def _finding(severity, title, file_path, explanation, recommendation):
    return {
        "severity": severity,
        "title": title,
        "file": file_path,
        "description": explanation,
        "recommendation": recommendation,
    }


def _safe_name(name):
    path = PurePosixPath(name.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        return None
    return str(path)


def analyze_cicd(archive):
    """Inspect CI/CD and container configuration files inside an open ZIP archive.

    The function reads files only. It does not extract or execute uploaded content.
    """
    findings = []
    files_inspected = 0
    total_bytes = 0

    candidates = []

    for info in archive.infolist():
        if info.is_dir():
            continue

        safe_name = _safe_name(info.filename)
        if not safe_name or safe_name.endswith("/"):
            continue

        if any(pattern.search(safe_name) for pattern in WORKFLOW_PATTERNS):
            candidates.append((safe_name, info))

    candidates.sort(key=lambda item: item[0].lower())

    if len(candidates) > MAX_CICD_FILES:
        findings.append(_finding(
            "medium",
            "Too many CI/CD configuration files",
            None,
            f"Found more than {MAX_CICD_FILES} candidate files. Only the first {MAX_CICD_FILES} will be inspected.",
            "Review the project's pipeline and container configuration files."
        ))
        candidates = candidates[:MAX_CICD_FILES]

    for file_path, info in candidates:
        if info.file_size > MAX_FILE_SIZE:
            findings.append(_finding(
                "low",
                "CI/CD file skipped due to size",
                file_path,
                "This configuration file exceeds the analyzer's size limit.",
                "Review the file manually and keep pipeline configuration files reasonably small."
            ))
            continue

        if total_bytes + info.file_size > MAX_TOTAL_SIZE:
            findings.append(_finding(
                "low",
                "CI/CD inspection size limit reached",
                file_path,
                "The analyzer reached its total CI/CD content limit.",
                "Review remaining pipeline configuration files manually."
            ))
            break

        try:
            with archive.open(info) as stream:
                content = stream.read(MAX_FILE_SIZE + 1)

            if len(content) > MAX_FILE_SIZE:
                continue

            text = content.decode("utf-8", errors="replace")
        except (OSError, RuntimeError, ValueError):
            findings.append(_finding(
                "low",
                "CI/CD file could not be read",
                file_path,
                "The configuration file could not be read safely.",
                "Check the file format and inspect it manually."
            ))
            continue

        files_inspected += 1
        total_bytes += len(content)
        lower = text.lower()
        filename_lower = file_path.lower()

        # GitHub Actions: broad workflow permissions.
        if filename_lower.startswith(".github/workflows/"):
            if re.search(r"(?m)^\s*permissions\s*:\s*write-all\s*(?:#.*)?$", text):
                findings.append(_finding(
                    "high",
                    "Broad GitHub Actions permissions",
                    file_path,
                    "The workflow grants write access broadly to its GitHub token.",
                    "Use the minimum required permissions, such as read-only defaults with specific job-level grants."
                ))
            elif not re.search(r"(?m)^\s*permissions\s*:", text):
                findings.append(_finding(
                    "medium",
                    "Workflow permissions are not explicitly defined",
                    file_path,
                    "No explicit permissions block was detected. Effective permissions may depend on repository settings.",
                    "Define a minimal permissions block at workflow or job level."
                ))

            # Third-party actions that do not use a full commit SHA.
            for line_number, line in enumerate(text.splitlines(), start=1):
                match = re.search(r"\buses\s*:\s*['\"]?([^'\"\s#]+)", line)
                if not match:
                    continue

                action_ref = match.group(1).strip()
                if action_ref.startswith("./") or action_ref.startswith("docker://"):
                    continue

                if "@" not in action_ref:
                    continue

                version = action_ref.rsplit("@", 1)[1]
                if not re.fullmatch(r"[0-9a-fA-F]{40}", version):
                    findings.append(_finding(
                        "medium",
                        "GitHub Action is not pinned to a full commit SHA",
                        file_path,
                        f"Line {line_number} references '{action_ref}', which may move when its tag or branch changes.",
                        "Pin third-party actions to a verified full commit SHA and update it deliberately."
                    ))

        # Common hard-coded secret indicators.
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                findings.append(_finding(
                    "high",
                    "Possible hard-coded secret in CI/CD configuration",
                    file_path,
                    "A pattern resembling a credential or private key was detected. This may be a false positive.",
                    "Remove real credentials from the file, rotate any exposed secret, and use your CI platform's secret store."
                ))
                break

        # Avoid floating container image versions.
        if "dockerfile" in PurePosixPath(file_path).name.lower():
            for line_number, line in enumerate(text.splitlines(), start=1):
                match = re.match(r"^\s*FROM\s+(\S+)", line, flags=re.I)
                if match:
                    image = match.group(1)
                    if image.lower() == "scratch" or image.startswith("--platform="):
                        continue
                    image_name = image.split("@", 1)[0]
                    if ":" not in image_name.rsplit("/", 1)[-1]:
                        findings.append(_finding(
                            "medium",
                            "Container base image has no explicit tag",
                            file_path,
                            f"Line {line_number} uses '{image}', which may resolve to a moving default tag.",
                            "Choose a deliberate base image version and consider pinning its digest."
                        ))

    return {
        "files_inspected": files_inspected,
        "findings": findings,
    }
