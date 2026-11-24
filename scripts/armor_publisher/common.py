"""Shared helpers: JSON files, hashing, GitHub Actions outputs, safe logging.

Strings that come from artifacts or from attacker-influenced API fields (branch
names, file names) must never reach logs, step summaries or GITHUB_OUTPUT
unfiltered. Use ``safe_text`` for anything that is not a fixed string, number or
reason code.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import secrets
from typing import Any, Optional

_SAFE_CHARS = re.compile(r"[^A-Za-z0-9 _.,/#@()+=:-]")


def utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)


def parse_github_time(value: str) -> _dt.datetime:
    """Parse a GitHub API timestamp such as ``2026-11-23T03:17:05Z``."""
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("unexpected timestamp format")
    return _dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc)


def format_github_time(value: _dt.datetime) -> str:
    return value.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_bytes(path: str, limit: Optional[int] = None) -> bytes:
    with open(path, "rb") as handle:
        data = handle.read(limit + 1 if limit is not None else -1)
    if limit is not None and len(data) > limit:
        raise ValueError(f"file larger than {limit} bytes")
    return data


def read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: str, data: Any) -> bytes:
    """Write deterministic JSON and return the exact bytes written."""
    payload = (json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(payload)
    return payload


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_verified_json(path: str, expected_sha256: str) -> Any:
    """Load a JSON file handed over from another job and check it was not altered.

    The expected hash travels through a job output, which later jobs cannot
    modify, while the file itself travels as a run artifact.
    """
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256 or ""):
        raise ValueError("missing or malformed expected sha256")
    data = read_bytes(path, limit=50 * 1024 * 1024)
    if sha256_bytes(data) != expected_sha256:
        raise ValueError(f"{os.path.basename(path)} does not match the hash published by the collect job")
    return json.loads(data.decode("utf-8"))


def safe_text(value: Any, limit: int = 160) -> str:
    """Reduce an untrusted value to a short, inert string for logs and summaries."""
    text = _SAFE_CHARS.sub("?", str(value))
    text = text.replace("::", ": :")
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


def _escape_command_data(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def log(message: str) -> None:
    print(message, flush=True)


def warning(message: str) -> None:
    print(f"::warning::{_escape_command_data(message)}", flush=True)


def error(message: str) -> None:
    print(f"::error::{_escape_command_data(message)}", flush=True)


def set_output(name: str, value: Any) -> None:
    """Write a single-line step output (values here are numbers, hashes or flags)."""
    text = str(value)
    if not re.fullmatch(r"[A-Za-z0-9_-]+", name) or "\n" in text or "\r" in text:
        raise ValueError("invalid step output")
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        log(f"[output] {name}={text}")
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(f"{name}={text}\n")


def append_summary(markdown: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        log(markdown)
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(markdown)
        if not markdown.endswith("\n"):
            handle.write("\n")


def random_token() -> str:
    return secrets.token_hex(8)
