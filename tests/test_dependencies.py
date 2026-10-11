
import io
import zipfile
from unittest.mock import Mock, patch

from analyzers.dependencies import analyze_dependencies


def make_zip(files):
    buffer = io.BytesIO()

    with zipfile.ZipFile(buffer, "w") as archive:
        for filename, content in files.items():
            archive.writestr(filename, content)

    buffer.seek(0)
    return zipfile.ZipFile(buffer)


@patch("analyzers.dependencies.requests.post")
def test_reports_vulnerability_from_osv(mock_post):
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "results": [
            {
                "vulns": [
                    {
                        "id": "PYSEC-TEST-2026-001",
                        "summary": "Test vulnerability",
                        "database_specific": {"severity": "HIGH"},
                        "affected": [
                            {
                                "package": {
                                    "name": "example-package",
                                    "ecosystem": "PyPI",
                                },
                                "ranges": [
                                    {
                                        "events": [
                                            {"introduced": "0"},
                                            {"fixed": "2.0.0"},
                                        ]
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        ]
    }
    mock_post.return_value = response

    archive = make_zip({
        "requirements.txt": "example-package==1.0.0\n"
    })

    try:
        result = analyze_dependencies(archive)

        assert result["pinned_dependencies_checked"] == 1
        assert any(
            finding.get("vulnerability_id") == "PYSEC-TEST-2026-001"
            for finding in result["findings"]
        )
        mock_post.assert_called_once()
    finally:
        archive.close()


@patch("analyzers.dependencies.requests.post")
def test_unpinned_dependency_is_not_claimed_checked(mock_post):
    archive = make_zip({
        "requirements.txt": "requests>=2.0\n"
    })

    try:
        result = analyze_dependencies(archive)

        assert result["pinned_dependencies_checked"] == 0
        assert result["dependencies_skipped"] == 1
        assert any(
            "not exactly pinned" in finding["title"]
            for finding in result["findings"]
        )
        mock_post.assert_not_called()
    finally:
        archive.close()


def test_missing_requirements_file_is_reported():
    archive = make_zip({"app.py": "print('hello')\n"})

    try:
        result = analyze_dependencies(archive)

        assert any(
            "No supported requirements file" in finding["title"]
            for finding in result["findings"]
        )
    finally:
        archive.close()
