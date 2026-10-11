
from pathlib import PurePosixPath


EXPECTED_FILES = {
    "README.md": "Project documentation",
    "requirements.txt": "Python dependency list",
    ".gitignore": "Git ignore configuration",
}

TEST_DIRECTORIES = {"tests", "test"}
TEST_FILE_PREFIXES = ("test_",)
MAX_RECOMMENDED_FILE_SIZE = 1 * 1024 * 1024  # 1 MB

IGNORED_DIRECTORIES = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
}


def analyze_structure(archive):
    """
    Inspect ZIP entry names and metadata without extracting or
    executing the uploaded project.
    """
    findings = []
    files = []
    directories = set()

    for entry in archive.infolist():
        path = PurePosixPath(entry.filename)

        # Ignore empty names and directory entries.
        if not entry.filename or entry.is_dir():
            continue

        # Ignore generated folders when checking project conventions.
        if any(part in IGNORED_DIRECTORIES for part in path.parts):
            continue

        files.append((path, entry.file_size))

        for parent in path.parents:
            if str(parent) != ".":
                directories.add(str(parent))

    root_files = {
        str(path).lower(): (path, size)
        for path, size in files
        if len(path.parts) == 1
    }

    for expected, purpose in EXPECTED_FILES.items():
        if expected.lower() not in root_files:
            findings.append({
                "category": "structure",
                "severity": "info",
                "title": f"Recommended file missing: {expected}",
                "file": expected,
                "line": None,
                "evidence": f"{purpose} file was not found at the project root.",
                "recommendation": (
                    f"Consider adding {expected} if appropriate for this project."
                ),
                "confirmed_issue": False,
            })

    has_tests = any(
        any(part.lower() in TEST_DIRECTORIES for part in path.parts[:-1])
        or path.name.lower().startswith(TEST_FILE_PREFIXES)
        for path, _size in files
    )

    if not has_tests:
        findings.append({
            "category": "testing",
            "severity": "low",
            "title": "No recognizable test files found",
            "file": None,
            "line": None,
            "evidence": (
                "No files were found inside a tests/test directory or "
                "with a test_ filename prefix."
            ),
            "recommendation": (
                "Consider adding automated tests for important application behavior."
            ),
            "confirmed_issue": False,
        })

    for path, size in files:
        if size > MAX_RECOMMENDED_FILE_SIZE:
            findings.append({
                "category": "structure",
                "severity": "info",
                "title": "Large project file",
                "file": str(path),
                "line": None,
                "evidence": f"File size is {size} bytes.",
                "recommendation": (
                    "Review whether this file needs to be stored in the source "
                    "archive or can be separated into smaller components."
                ),
                "confirmed_issue": False,
            })

    return {
        "analyzer": "structure",
        "files_inspected": len(files),
        "directories_found": sorted(directories),
        "findings": findings,
    }
