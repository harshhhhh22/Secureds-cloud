
import io
import zipfile

from analyzers.structure import analyze_structure


def make_zip(files):
    buffer = io.BytesIO()

    with zipfile.ZipFile(buffer, "w") as archive:
        for filename, content in files.items():
            archive.writestr(filename, content)

    buffer.seek(0)
    return zipfile.ZipFile(buffer)


def test_structure_detects_missing_recommended_files():
    archive = make_zip({
        "app.py": "print('hello')",
    })

    try:
        result = analyze_structure(archive)

        assert result["analyzer"] == "structure"
        assert result["files_inspected"] == 1
        assert any(
            "README.md" in finding["title"]
            for finding in result["findings"]
        )
    finally:
        archive.close()


def test_structure_recognizes_tests():
    archive = make_zip({
        "app.py": "print('hello')",
        "tests/test_app.py": "def test_example(): pass",
        "README.md": "# Example",
        "requirements.txt": "Flask",
        ".gitignore": ".venv/",
    })

    try:
        result = analyze_structure(archive)

        assert not any(
            finding["title"] == "No recognizable test files found"
            for finding in result["findings"]
        )
    finally:
        archive.close()
