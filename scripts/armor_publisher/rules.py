"""Validation rules for ARMOR artifacts: the single source of truth.

Used by the validate job (full checks on untrusted archives) and again by the
upload job (structural re-check of the validated bundle before anything is
sent to S3).
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

# --------------------------------------------------------------------------
# Artifacts we fetch. Every repo uploads these exact names.
# --------------------------------------------------------------------------
API_ARTIFACT = "apichecker-reports"
ABI_ARTIFACT = "abichecker-reports"
KIND_BY_ARTIFACT = {API_ARTIFACT: "api", ABI_ARTIFACT: "abi"}
API_METADATA = "metadata.json"
ABI_METADATA = "abi_metadata.json"

# Only plain-data file types. ".log" is ARMOR's plain-text diagnostics log
# (debug_output/logs/diagnostics.log); it gets exactly the same text checks.
ALLOWED_EXTENSIONS = (".json", ".html", ".txt", ".log")

# --------------------------------------------------------------------------
# Limits
# --------------------------------------------------------------------------
MAX_ZIP_BYTES = 100 * 1024 * 1024          # compressed artifact download
MAX_ENTRIES = 5000                         # zip entries per artifact
MAX_FILE_BYTES = 25 * 1024 * 1024          # one uncompressed file
MAX_TOTAL_BYTES = 300 * 1024 * 1024        # all uncompressed files of one artifact
MAX_RATIO = 200                            # uncompressed / compressed ...
RATIO_MIN_BYTES = 1024 * 1024              # ... checked for files above 1 MiB
MAX_PATH_LEN = 512
MAX_DEPTH = 8
MAX_JSON_DEPTH = 64
MAX_METADATA_BYTES = 5 * 1024 * 1024
MAX_LIST_ITEMS = 20000
MAX_STRING = 16384

_COMPONENT_RE = re.compile(r"[A-Za-z0-9_.+-]{1,255}")
SHA_RE = re.compile(r"[0-9a-f]{40}")
_REF_LIKE_RE = re.compile(r"[A-Za-z0-9._/+-]{1,255}")

API_ROOT_FILES = {API_METADATA, "incompatible_blocking.txt", "incompatible_nonblocking.txt", "others.txt"}
API_NESTED_DIRS = {"armor_reports", "debug_output"}

# Status values written by ARMOR / run_armor.sh (incl. its "Unknown" defaults).
ARMOR_STATUSES = {
    "FATAL_ERRORS", "BACKWARD_COMPATIBLE", "BACKWARD_INCOMPATIBLE", "UNSUPPORTED_UPDATES",
    "COMMENTS_UPDATED", "NON_FUNCTIONAL_CHANGES", "IN_ACTIVE", "CATEGORIZATION_ERROR",
    "SUPPORTED_UPDATES", "NOT_CATEGORIZED", "UNKNOWN_STATUS", "Unknown", "unknown",
}
# Values written by abi_checker/scripts/run_abi_checks.sh ("" appears when a
# versioning reason spans several lines and splits a row).
ABI_COMPATIBILITY = {"compatible (no-diff)", "compatible (abidiff-change)", "incompatible", "error", ""}
ABI_VERSIONING = {"PASS", "PASS (Blocked for maintainer review)", "FAIL", "WARN", "N/A", ""}

# File signatures that must never appear in a data file.
_MAGIC = (
    (b"\x7fELF", "elf-executable"),
    (b"MZ", "windows-executable"),
    (b"\xfe\xed\xfa\xce", "macho-executable"), (b"\xfe\xed\xfa\xcf", "macho-executable"),
    (b"\xce\xfa\xed\xfe", "macho-executable"), (b"\xcf\xfa\xed\xfe", "macho-executable"),
    (b"\xca\xfe\xba\xbe", "macho-or-java-binary"),
    (b"#!", "script-shebang"),
    (b"PK\x03\x04", "zip-archive"), (b"PK\x05\x06", "zip-archive"),
    (b"\x1f\x8b", "gzip-archive"), (b"BZh", "bzip2-archive"),
    (b"\xfd7zXZ\x00", "xz-archive"), (b"7z\xbc\xaf\x27\x1c", "7z-archive"),
    (b"\x28\xb5\x2f\xfd", "zstd-archive"), (b"Rar!", "rar-archive"),
    (b"\x00asm", "wasm-binary"),
)


class Rejected(Exception):
    """Raised when an artifact fails validation. ``code`` is a fixed reason code."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------
# Paths and layout
# --------------------------------------------------------------------------
def check_relpath(path: str) -> None:
    """Reject anything that is not a plain, relative, allowlisted file path."""
    if not isinstance(path, str) or not path:
        raise Rejected("bad-path", "empty path")
    if len(path) > MAX_PATH_LEN:
        raise Rejected("bad-path", "path too long")
    if "\\" in path or path.startswith("/") or "//" in path:
        raise Rejected("bad-path", "absolute path, backslash or empty component")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in path):
        raise Rejected("bad-path", "control character in path")
    parts = path.split("/")
    if len(parts) > MAX_DEPTH:
        raise Rejected("bad-path", "path too deep")
    for part in parts:
        if part in (".", ".."):
            raise Rejected("bad-path", "path traversal")
        if part.startswith("."):
            raise Rejected("unexpected-file", "hidden file or directory")
        if not _COMPONENT_RE.fullmatch(part):
            raise Rejected("bad-path", "unsupported character in path")
    if os.path.splitext(parts[-1])[1].lower() not in ALLOWED_EXTENSIONS:
        raise Rejected("unexpected-file-type", "only .json, .html, .txt, .log files are allowed")


def check_layout(kind: str, path: str) -> None:
    """Files must sit where the ARMOR checker writes them."""
    parts = path.split("/")
    ext = os.path.splitext(parts[-1])[1].lower()
    if kind == "api":
        if len(parts) == 1:
            if path not in API_ROOT_FILES:
                raise Rejected("unexpected-file", "unexpected top-level file in API artifact")
            return
        if len(parts) < 3 or parts[1] not in API_NESTED_DIRS:
            raise Rejected("unexpected-file", "unexpected location in API artifact")
        if ext == ".log" and parts[1] != "debug_output":
            raise Rejected("unexpected-file", ".log files are only allowed under debug_output/")
        return
    if kind == "abi":
        if len(parts) != 1 or ext not in (".json", ".txt"):
            raise Rejected("unexpected-file", "ABI artifact must hold abi_metadata.json and .txt reports only")
        if ext == ".json" and path != ABI_METADATA:
            raise Rejected("unexpected-file", "unexpected JSON file in ABI artifact")
        return
    raise Rejected("unknown-artifact-kind")


def api_header_dir(header: str) -> str:
    """Directory name run_armor.sh uses for a header (sed 's/[^A-Za-z0-9_.-]/_/g')."""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", header)


def abi_report_name(binary: str) -> str:
    """Report file name run_abi_checks.sh uses for a binary (${name//\\//__}.txt)."""
    return binary.replace("/", "__") + ".txt"


# --------------------------------------------------------------------------
# Content
# --------------------------------------------------------------------------
def check_content(data: bytes, path: str) -> str:
    """Data files must be UTF-8 text without binary or executable signatures."""
    for magic, code in _MAGIC:
        if data.startswith(magic):
            raise Rejected("executable-or-archive", code)
    if len(data) > 262 and data[257:262] == b"ustar":
        raise Rejected("executable-or-archive", "tar-archive")
    if b"\x00" in data:
        raise Rejected("binary-content", "NUL byte in text file")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise Rejected("binary-content", "file is not valid UTF-8") from None
    # Tool output (.txt/.log) may carry colour escape codes; nothing else may.
    allowed = "\t\n\r\f\x1b" if os.path.splitext(path)[1].lower() in (".txt", ".log") else "\t\n\r\f"
    if any((ord(ch) < 32 and ch not in allowed) or ord(ch) == 127 for ch in text):
        raise Rejected("binary-content", "control characters in text file")
    return text


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-standard JSON constant {name}")


def _no_duplicate_keys(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _depth_ok(value: Any) -> bool:
    stack = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            return False
        if isinstance(node, dict):
            stack.extend((child, depth + 1) for child in node.values())
        elif isinstance(node, list):
            stack.extend((child, depth + 1) for child in node)
    return True


def parse_strict_json(text: str) -> Any:
    try:
        value = json.loads(text, object_pairs_hook=_no_duplicate_keys, parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:
        raise Rejected("invalid-json", type(exc).__name__) from None
    if not _depth_ok(value):
        raise Rejected("invalid-json", "JSON nested too deeply")
    return value


# --------------------------------------------------------------------------
# Small type helpers for the metadata schema
# --------------------------------------------------------------------------
def is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def require_str(obj: dict, key: str, limit: int = 1024) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or len(value) > limit:
        raise Rejected("schema-mismatch", f"'{key}' must be a string")
    return value


def require_str_list(obj: dict, key: str) -> list:
    value = obj.get(key)
    if not isinstance(value, list) or len(value) > MAX_LIST_ITEMS:
        raise Rejected("schema-mismatch", f"'{key}' must be a list")
    for item in value:
        if not isinstance(item, str) or len(item) > MAX_STRING:
            raise Rejected("schema-mismatch", f"'{key}' must contain strings")
    return value


def optional_ref_like(value: str) -> bool:
    return value == "" or bool(_REF_LIKE_RE.fullmatch(value))
