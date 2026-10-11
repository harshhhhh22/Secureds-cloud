
import io
import zipfile

from analyzers.code_security import analyze_code_security


def make_zip(files):
    buffer = io.BytesIO()

    with zipfile.ZipFile(buffer, "w") as archive:
        for filename, content in files.items():
            archive.writestr(filename, content)

    buffer.seek(0)
    return zipfile.ZipFile(buffer)


def test_detects_dynamic_execution():
    archive = make_zip({
        "app.py": "result = eval(user_input)\n",
    })

    try:
        result = analyze_code_security(archive)

        assert result["files_inspected"] == 1
        assert any(
            finding["title"] == "Dynamic code execution using eval()"
            for finding in result["findings"]
        )
    finally:
        archive.close()


def test_detects_shell_true():
    archive = make_zip({
        "worker.py": (
            "import subprocess\n"
            "subprocess.run(command, shell=True)\n"
        ),
    })

    try:
        result = analyze_code_security(archive)

        assert any(
            finding["title"] == "Subprocess call enables shell=True"
            for finding in result["findings"]
        )
    finally:
        archive.close()


def test_does_not_flag_simple_arithmetic():
    archive = make_zip({
        "calculator.py": "result = 2 + 3\n",
    })

    try:
        result = analyze_code_security(archive)

        assert result["files_inspected"] == 1
        assert result["findings"] == []
    finally:
        archive.close()


def test_detects_python_syntax_error():
    archive = make_zip({
        "broken.py": "def broken(:\n    pass\n",
    })

    try:
        result = analyze_code_security(archive)

        assert result["parse_errors"] == 1
        assert any(
            finding["title"] == "Python syntax error"
            for finding in result["findings"]
        )
    finally:
        archive.close()
