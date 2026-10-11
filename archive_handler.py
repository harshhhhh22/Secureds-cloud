
import io
import stat
import zipfile
from pathlib import PurePosixPath


# Maximum compressed ZIP upload: 200 MB
MAX_ARCHIVE_SIZE = 200 * 1024 * 1024

# Safety limits for the archive after extraction
MAX_ENTRIES = 5000
MAX_TOTAL_UNCOMPRESSED_SIZE = 500 * 1024 * 1024
MAX_SINGLE_FILE_SIZE = 50 * 1024 * 1024

# Reject suspicious compression ratios for sufficiently large files.
MAX_COMPRESSION_RATIO = 200
RATIO_CHECK_MIN_SIZE = 1 * 1024 * 1024


class ArchiveValidationError(ValueError):
    """Raised when an uploaded ZIP archive fails validation."""


def validate_zip_bytes(data):
    """
    Validate uploaded ZIP bytes and return an open ZipFile.

    The caller is responsible for closing the returned archive.
    Uploaded project code is never executed.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ArchiveValidationError("The uploaded file is invalid.")

    if not data:
        raise ArchiveValidationError("The uploaded ZIP file is empty.")

    if len(data) > MAX_ARCHIVE_SIZE:
        raise ArchiveValidationError(
            "The ZIP file exceeds the 200 MB upload limit."
        )

    buffer = io.BytesIO(data)

    try:
        archive = zipfile.ZipFile(buffer, mode="r")
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        buffer.close()
        raise ArchiveValidationError(
            "The uploaded file is not a valid ZIP archive."
        ) from exc

    try:
        entries = archive.infolist()

        if len(entries) > MAX_ENTRIES:
            raise ArchiveValidationError(
                f"The ZIP contains too many entries. "
                f"The maximum is {MAX_ENTRIES}."
            )

        total_uncompressed_size = 0
        seen_paths = set()

        for entry in entries:
            name = entry.filename

            if not name or "\x00" in name:
                raise ArchiveValidationError(
                    "The ZIP contains an invalid file path."
                )

            # ZIP filenames use forward slashes. Also inspect backslashes
            # to prevent Windows-style traversal paths.
            normalized_name = name.replace("\\", "/")
            path = PurePosixPath(normalized_name)

            if (
                path.is_absolute()
                or normalized_name.startswith("/")
                or any(part == ".." for part in normalized_name.split("/"))
                or (path.parts and ":" in path.parts[0])
            ):
                raise ArchiveValidationError(
                    "The ZIP contains an unsafe file path."
                )

            normalized_key = normalized_name.rstrip("/").casefold()
            if normalized_key in seen_paths:
                raise ArchiveValidationError(
                    "The ZIP contains duplicate file paths."
                )
            seen_paths.add(normalized_key)

            if entry.flag_bits & 0x1:
                raise ArchiveValidationError(
                    "Password-protected ZIP entries are not supported."
                )

            if entry.file_size < 0 or entry.compress_size < 0:
                raise ArchiveValidationError(
                    "The ZIP contains invalid file size metadata."
                )

            if entry.file_size > MAX_SINGLE_FILE_SIZE:
                raise ArchiveValidationError(
                    "A file inside the ZIP exceeds the 50 MB per-file limit."
                )

            total_uncompressed_size += entry.file_size

            if total_uncompressed_size > MAX_TOTAL_UNCOMPRESSED_SIZE:
                raise ArchiveValidationError(
                    "The ZIP expands beyond the 500 MB total limit."
                )

            # Reject symlinks and special files; accept regular files
            # and directory entries.
            unix_mode = (entry.external_attr >> 16) & 0xFFFF
            file_type = stat.S_IFMT(unix_mode)

            if file_type not in (
                0,
                stat.S_IFREG,
                stat.S_IFDIR,
            ):
                raise ArchiveValidationError(
                    "The ZIP contains a symbolic link or special file."
                )

            if entry.file_size >= RATIO_CHECK_MIN_SIZE:
                if entry.compress_size == 0:
                    raise ArchiveValidationError(
                        "The ZIP contains a suspicious compression ratio."
                    )

                ratio = entry.file_size / entry.compress_size

                if ratio > MAX_COMPRESSION_RATIO:
                    raise ArchiveValidationError(
                        "The ZIP contains a suspicious compression ratio."
                    )

        # Read every file to check its CRC and detect corrupt entries.
        bad_entry = archive.testzip()

        if bad_entry is not None:
            raise ArchiveValidationError(
                "The ZIP archive is corrupted or failed its integrity check."
            )

        return archive

    except ArchiveValidationError:
        archive.close()
        raise
    except (zipfile.BadZipFile, OSError, RuntimeError, EOFError) as exc:
        archive.close()
        raise ArchiveValidationError(
            "The ZIP archive could not be safely validated."
        ) from exc
