"""Shared test fixtures: realistic ARMOR artifacts built in code."""

from __future__ import annotations

import json
import os
import sys
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "armor_publisher"))

SERVER = "https://github.com"
REPO = "qualcomm/fastrpc"
RUN_ID = 1234567890
HEAD_SHA = "a" * 40
HDR_DIR = "inc_remote.h"
ABI_BINARY = "src/.libs/libadsprpc.so"


def ctx(event: str = "pull_request", **overrides) -> dict:
    data = {
        "server_url": SERVER,
        "repo": REPO,
        "run_id": RUN_ID,
        "run_attempt": 1,
        "event": event,
        "head_sha": HEAD_SHA,
        "head_branch": "feature/x" if event != "push" else "development",
        "created_at": "2026-11-20T10:00:00Z",
        "updated_at": "2026-11-20T10:30:00Z",
        "prs": [{"number": 42, "base_ref": "development"}] if event == "pull_request" else [],
    }
    data.update(overrides)
    return data


def _common_meta(event: str) -> dict:
    return {
        "project_url": f"{SERVER}/{REPO}",
        "branch": "development",
        "github_event": event,
        "pr_number": 42 if event == "pull_request" else None,
        "timestamp": "2026-11-20T10:20:00Z",
        "base_sha": "c" * 40,
        "artifacts": f"{SERVER}/{REPO}/actions/runs/{RUN_ID}#artifacts",
    }


def api_metadata(event: str = "pull_request", **overrides) -> dict:
    meta = _common_meta(event)
    meta["head_sha"] = "b" * 40 if event == "pull_request" else HEAD_SHA
    meta["headers"] = [{"header": "inc/remote.h", "api_names": ["remote_handle_open"],
                        "compatibility": "BACKWARD_COMPATIBLE"}]
    meta.update(overrides)
    return meta


def abi_metadata(event: str = "pull_request", **overrides) -> dict:
    meta = _common_meta(event)
    meta["head_sha"] = "refs/pull/42/merge" if event == "pull_request" else HEAD_SHA
    meta["changed_files"] = ["inc/remote.h", "src/fastrpc_apps_user.c"]
    meta["binaries"] = [{"binary": ABI_BINARY, "compatibility": "compatible (no-diff)",
                         "versioning_result": "PASS", "versioning_reason": "No ABI differences, version unchanged"}]
    meta.update(overrides)
    return meta


def api_files(meta: dict = None) -> dict:
    meta = meta if meta is not None else api_metadata()
    return {
        "metadata.json": json.dumps(meta).encode(),
        "incompatible_blocking.txt": b"",
        "incompatible_nonblocking.txt": b"",
        "others.txt": b"[BACKWARD_COMPATIBLE]inc/remote.h\n",
        f"{HDR_DIR}/armor_reports/json_reports/api_diff_report_remote.h.json":
            json.dumps({"api_diff": [], "overall_status": "BACKWARD_COMPATIBLE"}).encode(),
        f"{HDR_DIR}/armor_reports/html_reports/api_diff_report_remote.h.html":
            b"<!DOCTYPE html><html><body>No API changes</body></html>\n",
        f"{HDR_DIR}/debug_output/logs/diagnostics.log": b"[INFO] analysis finished\n",
    }


def abi_files(meta: dict = None) -> dict:
    meta = meta if meta is not None else abi_metadata()
    return {
        "abi_metadata.json": json.dumps(meta).encode(),
        "src__.libs__libadsprpc.so.txt": b"### Header staging details\nNo ABI differences detected.\n",
    }


def make_zip(path: str, files: dict, modes: dict = None, flags: dict = None) -> str:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in files.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 20, 10, 0, 0))
            info.create_system = 3
            info.external_attr = (modes or {}).get(name, 0o100644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    if flags:
        _patch_central_flags(path, flags)
    return path


def _patch_central_flags(path: str, flags: dict) -> None:
    """zipfile resets flag bits on write; set them in the central directory afterwards."""
    import struct
    with zipfile.ZipFile(path) as archive:
        start = archive.start_dir
    with open(path, "r+b") as handle:
        blob = bytearray(handle.read())
        pos = start
        while blob[pos:pos + 4] == b"PK\x01\x02":
            name_len, extra_len, comment_len = struct.unpack("<HHH", blob[pos + 28:pos + 34])
            name = bytes(blob[pos + 46:pos + 46 + name_len]).decode()
            if name in flags:
                current = struct.unpack("<H", blob[pos + 8:pos + 10])[0]
                blob[pos + 8:pos + 10] = struct.pack("<H", current | flags[name])
            pos += 46 + name_len + extra_len + comment_len
        handle.seek(0)
        handle.write(blob)
