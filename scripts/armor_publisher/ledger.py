"""Processed-runs ledger, carried from one publisher run to the next as an artifact.

A run is recorded once all of its ARMOR artifacts reached a final state
(``published`` or ``ignored``). Transient errors are not recorded, so those
runs are retried by the next publisher run while they are inside the lookback
window. The ledger is only ever read from earlier runs of this same workflow on
the default branch, triggered by ``schedule`` or ``workflow_dispatch``.
"""

from __future__ import annotations

import datetime as _dt
import io
import json
import os
import re
import tempfile
import zipfile
from typing import Any, Dict

from common import format_github_time, log, parse_github_time, warning

LEDGER_ARTIFACT = "armor-publisher-ledger"
LEDGER_FILE = "ledger.json"
FINAL_STATES = {"published", "ignored"}
_KEY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+#[0-9]+")
_MAX_LEDGER_BYTES = 20 * 1024 * 1024


def empty() -> Dict[str, Any]:
    return {"version": 1, "runs": {}}


def run_key(repo: str, run_id: int) -> str:
    return f"{repo.lower()}#{int(run_id)}"


def parse(data: Any) -> Dict[str, Any]:
    """Strictly check the ledger structure; raises ValueError."""
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("runs"), dict):
        raise ValueError("unexpected ledger structure")
    for key, entry in data["runs"].items():
        if not _KEY_RE.fullmatch(key) or not isinstance(entry, dict):
            raise ValueError("unexpected ledger entry")
        if not isinstance(entry.get("attempt"), int) or not isinstance(entry.get("created_at"), str):
            raise ValueError("unexpected ledger entry")
        parse_github_time(entry["created_at"])
        artifacts = entry.get("artifacts")
        if not isinstance(artifacts, dict) or any(k not in ("api", "abi") for k in artifacts):
            raise ValueError("unexpected ledger entry")
    return data


def is_done(ledger: Dict[str, Any], key: str, attempt: int) -> bool:
    entry = ledger["runs"].get(key)
    return bool(entry) and entry["attempt"] >= attempt


def record(ledger: Dict[str, Any], key: str, attempt: int, created_at: str,
           artifacts: Dict[str, str], now: _dt.datetime) -> None:
    ledger["runs"][key] = {
        "attempt": int(attempt),
        "created_at": created_at,
        "artifacts": dict(artifacts),
        "processed_at": format_github_time(now),
    }


def prune(ledger: Dict[str, Any], now: _dt.datetime, keep_days: int) -> None:
    cutoff = now - _dt.timedelta(days=keep_days)
    ledger["runs"] = {
        key: entry for key, entry in ledger["runs"].items()
        if parse_github_time(entry["created_at"]) >= cutoff
    }


def load_previous(client, central_repo: str, workflow_file: str, default_branch: str,
                  current_run_id: int, max_runs: int = 30) -> Dict[str, Any]:
    """Return the ledger written by the newest earlier publisher run (or an empty one)."""
    data = client.get_json(
        f"/repos/{central_repo}/actions/workflows/{workflow_file}/runs",
        {"branch": default_branch, "status": "completed", "per_page": max_runs},
    )
    for run in data.get("workflow_runs", []):
        if run.get("id") == current_run_id or run.get("event") not in ("schedule", "workflow_dispatch"):
            continue
        if run.get("head_branch") != default_branch:
            continue
        head_repo = (run.get("head_repository") or {}).get("full_name", "")
        if head_repo.lower() != central_repo.lower():
            continue
        artifacts = client.get_json(
            f"/repos/{central_repo}/actions/runs/{int(run['id'])}/artifacts",
            {"name": LEDGER_ARTIFACT, "per_page": 10},
        ).get("artifacts", [])
        for artifact in artifacts:
            if artifact.get("expired") or artifact.get("name") != LEDGER_ARTIFACT:
                continue
            try:
                ledger = _download_ledger(client, central_repo, int(artifact["id"]))
            except (ValueError, KeyError, zipfile.BadZipFile, OSError) as exc:
                warning(f"Ignoring unreadable ledger from run {int(run['id'])}: {type(exc).__name__}")
                continue
            log(f"Loaded ledger from publisher run {int(run['id'])} ({len(ledger['runs'])} runs recorded)")
            return ledger
    log("No previous ledger found; starting with an empty ledger (lookback window only)")
    return empty()


def _download_ledger(client, central_repo: str, artifact_id: int) -> Dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "ledger.zip")
        client.download_artifact_zip(central_repo, artifact_id, path, _MAX_LEDGER_BYTES)
        with zipfile.ZipFile(path) as archive:
            info = archive.getinfo(LEDGER_FILE)
            if info.file_size > _MAX_LEDGER_BYTES:
                raise ValueError("ledger too large")
            with archive.open(info) as handle:
                raw = handle.read(_MAX_LEDGER_BYTES + 1)
    if len(raw) > _MAX_LEDGER_BYTES:
        raise ValueError("ledger too large")
    return parse(json.load(io.BytesIO(raw)))
