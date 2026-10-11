
import ast
import io
import zipfile
from pathlib import PurePosixPath


MAX_SOURCE_BYTES = 1 * 1024 * 1024  # 1 MB per Python source file


def _call_name(node):
    """Return a readable name for a function or method call."""
    if isinstance(node, ast.Name):
        return node.id

    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr

    return ""


def analyze_code_security(archive: zipfile.ZipFile):
    """
    Inspect Python source files in a validated ZIP archive.
    Uploaded source code is parsed, never executed.
    """
    findings = []
    files_inspected = 0
    parse_errors = 0

    for entry in archive.infolist():
        path = PurePosixPath(entry.filename)

        if entry.is_dir() or path.suffix.lower() != ".py":
            continue

        # Avoid scanning generated environments and vendored dependencies.
        if any(
            part.lower() in {
                ".git", ".venv", "venv", "__pycache__", "site-packages"
            }
            for part in path.parts
        ):
            continue

        if entry.file_size > MAX_SOURCE_BYTES:
            findings.append({
                "category": "code_security",
                "severity": "info",
                "title": "Python source file skipped: size limit",
                "file": str(path),
                "line": None,
                "evidence": "The source file exceeds the 1 MB analyzer limit.",
                "recommendation": "Review this file separately if it needs analysis.",
                "confirmed_issue": False,
            })
            continue

        try:
            source_bytes = archive.read(entry)
            source = source_bytes.decode("utf-8-sig")
        except (UnicodeDecodeError, OSError, zipfile.BadZipFile):
            findings.append({
                "category": "code_security",
                "severity": "info",
                "title": "Python source file could not be decoded",
                "file": str(path),
                "line": None,
                "evidence": "The file could not be read as UTF-8 source text.",
                "recommendation": "Check the file encoding and inspect it manually.",
                "confirmed_issue": False,
            })
            continue

        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as exc:
            parse_errors += 1
            findings.append({
                "category": "code_security",
                "severity": "low",
                "title": "Python syntax error",
                "file": str(path),
                "line": exc.lineno,
                "evidence": exc.msg,
                "recommendation": "Correct the syntax error and run the project's tests.",
                "confirmed_issue": True,
            })
            continue

        files_inspected += 1

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            name = _call_name(node.func)
            line = getattr(node, "lineno", None)

            if name in {"eval", "exec"}:
                findings.append({
                    "category": "code_security",
                    "severity": "medium",
                    "title": f"Dynamic code execution using {name}()",
                    "file": str(path),
                    "line": line,
                    "evidence": (
                        f"The code calls {name}(). Risk depends on where "
                        "the evaluated input comes from."
                    ),
                    "recommendation": (
                        "Avoid evaluating dynamic code. If input is untrusted, "
                        "use a narrowly defined parser or explicit allowlist."
                    ),
                    "confirmed_issue": False,
                })

            elif name in {"pickle.load", "pickle.loads"}:
                findings.append({
                    "category": "code_security",
                    "severity": "high",
                    "title": "Potentially unsafe pickle deserialization",
                    "file": str(path),
                    "line": line,
                    "evidence": (
                        f"The code calls {name}(). Deserializing untrusted "
                        "pickle data can execute arbitrary code."
                    ),
                    "recommendation": (
                        "Never load pickle data from an untrusted source. "
                        "Use a safer data format when possible."
                    ),
                    "confirmed_issue": False,
                })

            elif name in {"subprocess.run", "subprocess.call",
                          "subprocess.Popen", "subprocess.check_output"}:
                shell_enabled = any(
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                    for keyword in node.keywords
                )

                if shell_enabled:
                    findings.append({
                        "category": "code_security",
                        "severity": "high",
                        "title": "Subprocess call enables shell=True",
                        "file": str(path),
                        "line": line,
                        "evidence": (
                            "A subprocess call sets shell=True. Risk is higher "
                            "when command input can be influenced by users."
                        ),
                        "recommendation": (
                            "Prefer an argument list with shell=False. "
                            "Validate any externally supplied arguments."
                        ),
                        "confirmed_issue": False,
                    })

            elif name == "yaml.load":
                has_safe_loader = any(
                    keyword.arg == "Loader"
                    and isinstance(keyword.value, ast.Attribute)
                    and keyword.value.attr == "SafeLoader"
                    for keyword in node.keywords
                )

                if not has_safe_loader:
                    findings.append({
                        "category": "code_security",
                        "severity": "medium",
                        "title": "Review YAML deserialization",
                        "file": str(path),
                        "line": line,
                        "evidence": (
                            "yaml.load() is used without an explicitly "
                            "recognized yaml.SafeLoader argument."
                        ),
                        "recommendation": (
                            "Use yaml.safe_load() for untrusted YAML, "
                            "or explicitly configure a safe loader."
                        ),
                        "confirmed_issue": False,
                    })

    return {
        "analyzer": "code_security",
        "files_inspected": files_inspected,
        "parse_errors": parse_errors,
        "findings": findings,
    }
