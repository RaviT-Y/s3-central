"""Validate one downloaded ARMOR artifact. Everything inside the zip is untrusted.

The archive is checked entry by entry before anything is extracted. Files are
written one by one with streaming size limits (sizes declared in the zip are
never trusted), then every file is checked as data, the metadata is checked
against the expected schema, and finally the metadata is compared with the
trusted run information fetched from the GitHub API by the collect job.

Nothing from the artifact is ever executed, sourced, rendered or used to build
an S3 key.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import os
import re
import stat
import zipfile
import zlib
from typing import Any, Dict, List, Optional

import rules
from common import parse_github_time
from rules import Rejected

_LIST_LINE_RE = re.compile(r"\[([A-Za-z_]+)\](.+)")
_API_REQUIRED = {"project_url", "branch", "github_event", "pr_number", "timestamp",
                 "head_sha", "base_sha", "artifacts", "headers"}
_ABI_REQUIRED = {"project_url", "branch", "github_event", "pr_number", "timestamp",
                 "head_sha", "base_sha", "artifacts", "changed_files", "binaries"}
# Provenance fields added by newer armor-checkers releases; checked when present.
_OPTIONAL = {"schema_version", "checker", "repository", "run_id", "run_attempt", "run_head_sha"}
_CLOCK_SKEW = _dt.timedelta(minutes=10)


def validate_artifact(zip_path: str, kind: str, ctx: Dict[str, Any], out_dir: str) -> Dict[str, Any]:
    """Validate ``zip_path`` and extract it into the new directory ``out_dir``.

    Returns ``{"files": [...], "pr_number": ...}``; raises ``Rejected``.
    """
    os.makedirs(out_dir, exist_ok=False)
    try:
        archive = zipfile.ZipFile(zip_path)
    except (zipfile.BadZipFile, OSError, ValueError, EOFError):
        raise Rejected("not-a-zip", "artifact is not a valid zip archive") from None
    try:
        with archive:
            members = _check_entries(archive, kind)
            files = _extract(archive, members, out_dir)
    except (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError, RuntimeError, OSError):
        raise Rejected("corrupt-archive", "archive could not be read safely") from None

    texts = {}
    for name, entry in files.items():
        with open(entry["path"], "rb") as handle:
            data = handle.read(rules.MAX_FILE_BYTES + 1)
        texts[name] = rules.check_content(data, name)
        if name.endswith(".json"):
            value = rules.parse_strict_json(texts[name])
            if "/armor_reports/json_reports/" in name and not isinstance(value, dict):
                raise Rejected("schema-mismatch", "ARMOR JSON report must be an object")

    metadata_name = rules.API_METADATA if kind == "api" else rules.ABI_METADATA
    if files[metadata_name]["size"] > rules.MAX_METADATA_BYTES:
        raise Rejected("file-too-large", "metadata file too large")
    metadata = rules.parse_strict_json(texts[metadata_name])
    check_metadata_schema(metadata, kind)
    check_cross_references(metadata, kind, texts)
    pr_number = check_provenance(metadata, kind, ctx)

    return {
        "pr_number": pr_number,
        "files": sorted(
            ({"path": name, "size": entry["size"], "sha256": entry["sha256"]} for name, entry in files.items()),
            key=lambda item: item["path"],
        ),
    }


# --------------------------------------------------------------------------
# Archive structure
# --------------------------------------------------------------------------
def _check_entries(archive: zipfile.ZipFile, kind: str) -> List[zipfile.ZipInfo]:
    infos = archive.infolist()
    if len(infos) > rules.MAX_ENTRIES:
        raise Rejected("too-many-files", f"more than {rules.MAX_ENTRIES} entries")
    seen, seen_folded, members = set(), set(), []
    declared_total = 0
    for info in infos:
        name = info.filename
        if info.flag_bits & 0x1:
            raise Rejected("encrypted-entry", "encrypted zip entries are not allowed")
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise Rejected("unsupported-compression")
        mode = info.external_attr >> 16
        if info.create_system == 3 and mode:          # Unix attributes present
            file_type = stat.S_IFMT(mode)
            if name.endswith("/"):
                if file_type not in (0, stat.S_IFDIR):
                    raise Rejected("not-a-regular-file", "special file in archive")
            else:
                if file_type not in (0, stat.S_IFREG):
                    raise Rejected("not-a-regular-file", "symlink or special file in archive")
                if mode & 0o111:
                    raise Rejected("executable-file", "file has execute permission")
        if name.endswith("/"):
            _check_directory_entry(name)
            continue
        rules.check_relpath(name)
        rules.check_layout(kind, name)
        if name in seen or name.casefold() in seen_folded:
            raise Rejected("duplicate-entry", "duplicate file name in archive")
        seen.add(name)
        seen_folded.add(name.casefold())
        if info.file_size > rules.MAX_FILE_BYTES:
            raise Rejected("file-too-large", f"file larger than {rules.MAX_FILE_BYTES} bytes")
        declared_total += info.file_size
        if declared_total > rules.MAX_TOTAL_BYTES:
            raise Rejected("artifact-too-large", "uncompressed artifact too large")
        members.append(info)
    if not members:
        raise Rejected("empty-artifact")
    metadata_name = rules.API_METADATA if kind == "api" else rules.ABI_METADATA
    if metadata_name not in seen:
        raise Rejected("missing-metadata", f"{metadata_name} not found at the artifact root")
    return members


def _check_directory_entry(name: str) -> None:
    path = name[:-1]
    if not path:
        raise Rejected("bad-path", "empty directory entry")
    # Reuse the file rules on a fake file name inside the directory.
    rules.check_relpath(path + "/x.txt")


def _extract(archive: zipfile.ZipFile, members: List[zipfile.ZipInfo], out_dir: str) -> Dict[str, Dict[str, Any]]:
    real_root = os.path.realpath(out_dir)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    total = 0
    files: Dict[str, Dict[str, Any]] = {}
    for info in members:
        dest = os.path.join(out_dir, *info.filename.split("/"))
        parent = os.path.dirname(dest)
        os.makedirs(parent, mode=0o755, exist_ok=True)
        real_parent = os.path.realpath(parent)
        if real_parent != real_root and not real_parent.startswith(real_root + os.sep):
            raise Rejected("bad-path", "path escapes the extraction directory")
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o644)
        digest, size = hashlib.sha256(), 0
        with os.fdopen(fd, "wb") as out, archive.open(info) as src:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                total += len(chunk)
                if size > rules.MAX_FILE_BYTES:
                    raise Rejected("file-too-large", "file larger than allowed while extracting")
                if total > rules.MAX_TOTAL_BYTES:
                    raise Rejected("artifact-too-large", "artifact larger than allowed while extracting")
                out.write(chunk)
                digest.update(chunk)
        if size > rules.RATIO_MIN_BYTES and size > rules.MAX_RATIO * max(info.compress_size, 1):
            raise Rejected("zip-bomb", "compression ratio too high")
        files[info.filename] = {"path": dest, "size": size, "sha256": digest.hexdigest()}
    return files


# --------------------------------------------------------------------------
# Metadata schema
# --------------------------------------------------------------------------
def check_metadata_schema(meta: Any, kind: str) -> None:
    if not isinstance(meta, dict):
        raise Rejected("schema-mismatch", "metadata must be a JSON object")
    required = _API_REQUIRED if kind == "api" else _ABI_REQUIRED
    keys = set(meta)
    if required - keys:
        raise Rejected("schema-mismatch", "metadata is missing required keys")
    if keys - required - _OPTIONAL:
        raise Rejected("schema-mismatch", "metadata has unexpected keys")
    for key in ("project_url", "branch", "github_event", "timestamp", "head_sha", "base_sha", "artifacts"):
        rules.require_str(meta, key)
    pr_number = meta["pr_number"]
    if pr_number is not None and not (rules.is_int(pr_number) and pr_number > 0):
        raise Rejected("schema-mismatch", "'pr_number' must be a positive integer or null")

    if kind == "api":
        headers = meta["headers"]
        if not isinstance(headers, list) or len(headers) > rules.MAX_LIST_ITEMS:
            raise Rejected("schema-mismatch", "'headers' must be a list")
        for item in headers:
            if not isinstance(item, dict) or set(item) != {"header", "api_names", "compatibility"}:
                raise Rejected("schema-mismatch", "unexpected 'headers' entry")
            rules.require_str(item, "header")
            rules.require_str_list(item, "api_names")
            if item["compatibility"] not in rules.ARMOR_STATUSES:
                raise Rejected("schema-mismatch", "unknown ARMOR compatibility status")
    else:
        rules.require_str_list(meta, "changed_files")
        binaries = meta["binaries"]
        if not isinstance(binaries, list) or len(binaries) > rules.MAX_LIST_ITEMS:
            raise Rejected("schema-mismatch", "'binaries' must be a list")
        for item in binaries:
            if not isinstance(item, dict) or set(item) != {"binary", "compatibility", "versioning_result", "versioning_reason"}:
                raise Rejected("schema-mismatch", "unexpected 'binaries' entry")
            rules.require_str(item, "binary")
            rules.require_str(item, "versioning_reason", limit=rules.MAX_STRING)
            if item["compatibility"] not in rules.ABI_COMPATIBILITY:
                raise Rejected("schema-mismatch", "unknown ABI compatibility value")
            if item["versioning_result"] not in rules.ABI_VERSIONING:
                raise Rejected("schema-mismatch", "unknown ABI versioning result")

    if "schema_version" in meta and meta["schema_version"] != 1:
        raise Rejected("schema-mismatch", "unsupported schema_version")
    if "checker" in meta and meta["checker"] != kind:
        raise Rejected("schema-mismatch", "'checker' does not match the artifact")
    for key in ("repository", "run_head_sha"):
        if key in meta:
            rules.require_str(meta, key)
    for key in ("run_id", "run_attempt"):
        if key in meta and not (rules.is_int(meta[key]) and meta[key] > 0):
            raise Rejected("schema-mismatch", f"'{key}' must be a positive integer")


def check_cross_references(meta: Dict[str, Any], kind: str, texts: Dict[str, str]) -> None:
    """Every report file must belong to an entry listed in the metadata."""
    if kind == "api":
        headers = {item["header"] for item in meta["headers"]}
        expected_dirs = {rules.api_header_dir(header) for header in headers}
        for name in texts:
            if "/" in name and name.split("/", 1)[0] not in expected_dirs:
                raise Rejected("unexpected-file", "report directory not listed in metadata.json")
        for list_name in ("incompatible_blocking.txt", "incompatible_nonblocking.txt", "others.txt"):
            for line in texts.get(list_name, "").splitlines():
                if not line.strip():
                    continue
                match = _LIST_LINE_RE.fullmatch(line.rstrip("\r"))
                if not match or match.group(1) not in rules.ARMOR_STATUSES:
                    raise Rejected("schema-mismatch", f"malformed line in {list_name}")
                if list_name != "others.txt" and match.group(1) != "BACKWARD_INCOMPATIBLE":
                    raise Rejected("schema-mismatch", f"unexpected status in {list_name}")
                if match.group(2) not in headers:
                    raise Rejected("schema-mismatch", f"{list_name} names a header missing from metadata.json")
    else:
        expected = {rules.abi_report_name(item["binary"]) for item in meta["binaries"]}
        for name in texts:
            if name.endswith(".txt") and name not in expected:
                raise Rejected("unexpected-file", "ABI report not listed in abi_metadata.json")


# --------------------------------------------------------------------------
# Provenance: metadata must match the trusted run information
# --------------------------------------------------------------------------
def check_provenance(meta: Dict[str, Any], kind: str, ctx: Dict[str, Any]) -> Optional[int]:
    server = ctx["server_url"].rstrip("/")
    repo = ctx["repo"]
    run_id = ctx["run_id"]
    event = ctx["event"]

    if meta["project_url"].lower() != f"{server}/{repo}".lower():
        raise Rejected("provenance-repository", "project_url does not match the repository")
    if meta["artifacts"].lower() != f"{server}/{repo}/actions/runs/{run_id}#artifacts".lower():
        raise Rejected("provenance-run-id", "artifacts URL does not match the workflow run")
    if meta["github_event"] != event:
        raise Rejected("provenance-event", "github_event does not match the workflow run")

    pr_number = meta["pr_number"]
    if event == "pull_request":
        trusted_prs = {pr["number"]: pr["base_ref"] for pr in ctx.get("prs", [])}
        if pr_number not in trusted_prs:
            raise Rejected("provenance-pr", "pr_number is not a pull request of this run")
        if meta["branch"] != trusted_prs[pr_number]:
            raise Rejected("provenance-branch", "branch does not match the pull request base branch")
    else:
        if pr_number is not None:
            raise Rejected("provenance-pr", "pr_number set for a non pull_request run")
        if event == "push" and meta["branch"] != ctx["head_branch"]:
            raise Rejected("provenance-branch", "branch does not match the pushed branch")
        if event == "workflow_dispatch" and not rules.optional_ref_like(meta["branch"]):
            raise Rejected("provenance-branch", "branch is not a valid ref name")

    head_sha, base_sha = meta["head_sha"], meta["base_sha"]
    if event == "push":
        if head_sha != ctx["head_sha"] and not (kind == "api" and head_sha == "unknown"):
            raise Rejected("provenance-commit", "head_sha does not match the pushed commit")
    elif event == "pull_request":
        allowed = bool(rules.SHA_RE.fullmatch(head_sha))
        allowed = allowed or (kind == "abi" and head_sha == f"refs/pull/{pr_number}/merge")
        allowed = allowed or (kind == "api" and head_sha == "unknown")
        if not allowed:
            raise Rejected("provenance-commit", "head_sha is not this pull request's merge commit")
    elif not (head_sha == "unknown" or rules.optional_ref_like(head_sha)):
        raise Rejected("provenance-commit", "head_sha is not a valid commit or ref")
    if event in ("push", "pull_request"):
        if base_sha and not rules.SHA_RE.fullmatch(base_sha):
            raise Rejected("provenance-commit", "base_sha is not a commit SHA")
    elif not rules.optional_ref_like(base_sha):
        raise Rejected("provenance-commit", "base_sha is not a valid commit or ref")

    try:
        stamp = parse_github_time(meta["timestamp"])
    except ValueError:
        raise Rejected("provenance-timestamp", "timestamp is not in YYYY-MM-DDTHH:MM:SSZ format") from None
    earliest = parse_github_time(ctx["created_at"]) - _CLOCK_SKEW
    latest = parse_github_time(ctx["updated_at"]) + _CLOCK_SKEW
    if not earliest <= stamp <= latest:
        raise Rejected("provenance-timestamp", "timestamp is outside the workflow run")

    # Fields written by newer armor-checkers releases.
    if "repository" in meta and meta["repository"].lower() != repo.lower():
        raise Rejected("provenance-repository", "repository does not match")
    if "run_id" in meta and meta["run_id"] != run_id:
        raise Rejected("provenance-run-id", "run_id does not match")
    if "run_attempt" in meta and meta["run_attempt"] > ctx["run_attempt"]:
        raise Rejected("provenance-run-id", "run_attempt is newer than the workflow run")
    if "run_head_sha" in meta and meta["run_head_sha"] != ctx["head_sha"]:
        raise Rejected("provenance-commit", "run_head_sha does not match the workflow run")
    return pr_number
