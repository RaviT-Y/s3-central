"""Collect job: find ARMOR runs that still need publishing and download their artifacts.

Only trusted data from the GitHub API is used here. Downloaded zips are kept
as opaque bytes; they are never opened in this job.
"""

from __future__ import annotations

import datetime as _dt
import os
import re
from typing import Any, Dict, List, Optional

import ledger as ledger_mod
import rules
from common import (error, log, parse_github_time, safe_text, set_output, sha256_bytes,
                    utcnow, format_github_time, write_json)
from github_api import GitHubClient, GitHubError

DEFAULT_ARMOR_WORKFLOWS = "qualcomm/armor-checkers/.github/workflows/armor-checker.yml"
SUPPORTED_EVENTS = {"pull_request", "push", "workflow_dispatch"}
_REPO_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
_WORKFLOW_REF_RE = re.compile(r"[^/]+/[^/]+/\.github/workflows/([A-Za-z0-9_.-]+\.ya?ml)@.+")


def read_repos_file(path: str) -> List[str]:
    """``owner/repo`` per line; blank lines and ``#`` comments are ignored."""
    repos, seen = [], set()
    with open(path, "r", encoding="utf-8") as handle:
        for number, raw in enumerate(handle, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if not _REPO_RE.fullmatch(line) or any(part in (".", "..") for part in line.split("/")):
                raise ValueError(f"{path}:{number}: expected 'owner/repo'")
            if line.lower() in seen:
                raise ValueError(f"{path}:{number}: repository listed twice")
            seen.add(line.lower())
            repos.append(line)
    if not repos:
        raise ValueError(f"{path}: no repositories listed")
    return repos


def workflow_file_from_ref(workflow_ref: str) -> str:
    match = _WORKFLOW_REF_RE.fullmatch(workflow_ref or "")
    if not match:
        raise ValueError("cannot determine this workflow's file name from GITHUB_WORKFLOW_REF")
    return match.group(1)


def parse_allowed_workflows(value: str) -> set:
    allowed = {item.strip().lower() for item in re.split(r"[\s,]+", value or "") if item.strip()}
    return allowed or {DEFAULT_ARMOR_WORKFLOWS}


def references_armor(run: Dict[str, Any], allowed: set) -> bool:
    for ref in run.get("referenced_workflows") or []:
        path = str(ref.get("path") or "").split("@", 1)[0].lower()
        if path in allowed:
            return True
    return False


def trusted_prs(client: GitHubClient, repo: str, repo_id: int, run: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Pull requests this run belongs to, from the API only.

    ``run.pull_requests`` is empty for PRs from forks, so fall back to looking
    up PRs whose head is the run's head repository and branch.
    """
    found: Dict[int, str] = {}
    for pr in run.get("pull_requests") or []:
        base = pr.get("base") or {}
        if (base.get("repo") or {}).get("id") == repo_id and rules.is_int(pr.get("number")):
            found[pr["number"]] = str(base.get("ref") or "")
    if found:
        return [{"number": n, "base_ref": ref} for n, ref in sorted(found.items())]

    head_repo = run.get("head_repository") or {}
    owner = (head_repo.get("owner") or {}).get("login")
    branch = run.get("head_branch")
    if not owner or not branch:
        return []
    params = {"state": "all", "head": f"{owner}:{branch}", "per_page": 100}
    for pr in client.paginate(f"/repos/{repo}/pulls", params, key=None, max_pages=3):
        head = pr.get("head") or {}
        base = pr.get("base") or {}
        if ((head.get("repo") or {}).get("full_name", "").lower() == str(head_repo.get("full_name", "")).lower()
                and (base.get("repo") or {}).get("id") == repo_id and rules.is_int(pr.get("number"))):
            found[pr["number"]] = str(base.get("ref") or "")
    return [{"number": n, "base_ref": ref} for n, ref in sorted(found.items())]


class Collector:
    def __init__(self, source: GitHubClient, ledger: Dict[str, Any], out_dir: str,
                 cutoff: _dt.datetime, allowed_workflows: set) -> None:
        self.source = source
        self.ledger = ledger
        self.out_dir = out_dir
        self.cutoff = cutoff
        self.allowed = allowed_workflows
        self.runs: List[Dict[str, Any]] = []
        self.repo_errors: List[Dict[str, Any]] = []
        self.stats = {"repos": 0, "pending_runs": 0, "already_processed": 0, "downloaded": 0}

    # ------------------------------------------------------------- per repo
    def collect_repo(self, repo: str) -> None:
        self.stats["repos"] += 1
        try:
            info = self.source.get_json(f"/repos/{repo}")
            canonical, repo_id = info["full_name"], info["id"]
            if not _REPO_RE.fullmatch(canonical) or not rules.is_int(repo_id):
                raise GitHubError("unexpected repository data")
            groups = self._artifacts_by_run(canonical)
            for run_id in sorted(groups):
                self._collect_run(canonical, repo_id, run_id, groups[run_id])
        except GitHubError as exc:
            error(f"{safe_text(repo)}: GitHub API error ({safe_text(exc)})")
            self.repo_errors.append({"repo": repo, "reason": "github-api-error", "detail": safe_text(exc)})
        except (ValueError, KeyError, TypeError) as exc:
            error(f"{safe_text(repo)}: unexpected GitHub API data ({type(exc).__name__})")
            self.repo_errors.append({"repo": repo, "reason": "unexpected-api-data", "detail": type(exc).__name__})

    def _artifacts_by_run(self, repo: str) -> Dict[int, Dict[str, Dict[str, Any]]]:
        groups: Dict[int, Dict[str, Dict[str, Any]]] = {}

        def all_older(items: list) -> bool:
            return all(parse_github_time(item["created_at"]) < self.cutoff
                       for item in items if isinstance(item.get("created_at"), str))

        for name, kind in rules.KIND_BY_ARTIFACT.items():
            params = {"name": name, "per_page": 100}
            for art in self.source.paginate(f"/repos/{repo}/actions/artifacts", params, "artifacts", stop=all_older):
                if art.get("name") != name or not isinstance(art.get("created_at"), str):
                    continue
                if parse_github_time(art["created_at"]) < self.cutoff:
                    continue
                run_id = (art.get("workflow_run") or {}).get("id")
                if not rules.is_int(run_id) or not rules.is_int(art.get("id")):
                    continue
                current = groups.setdefault(run_id, {}).get(kind)
                # A re-run can leave one artifact per attempt: keep the newest.
                if current is None or (art["created_at"], art["id"]) > (current["created_at"], current["id"]):
                    groups[run_id][kind] = art
        return groups

    # -------------------------------------------------------------- per run
    def _collect_run(self, repo: str, repo_id: int, run_id: int, artifacts: Dict[str, Dict[str, Any]]) -> None:
        run = self.source.get_json(f"/repos/{repo}/actions/runs/{run_id}")
        if run.get("status") != "completed":
            self.stats["pending_runs"] += 1          # picked up by a later publisher run
            return
        attempt = run.get("run_attempt") if rules.is_int(run.get("run_attempt")) else 1
        key = ledger_mod.run_key(repo, run_id)
        if ledger_mod.is_done(self.ledger, key, attempt):
            self.stats["already_processed"] += 1
            return

        event = run.get("event")
        head_repo = (run.get("head_repository") or {}).get("full_name") or ""
        entry: Dict[str, Any] = {
            "key": key,
            "dir": f"{repo.replace('/', '__')}__{run_id}",
            "repo": repo,
            "repo_id": repo_id,
            "run_id": run_id,
            "run_attempt": attempt,
            "event": safe_text(event, 64),
            "head_sha": run.get("head_sha"),
            "head_branch": run.get("head_branch"),
            "head_repository": head_repo,
            "is_fork": bool(head_repo) and head_repo.lower() != repo.lower(),
            "created_at": run.get("created_at"),
            "updated_at": run.get("updated_at"),
            "prs": [],
            "artifacts": [],
        }

        run_reason = None
        if (run.get("repository") or {}).get("id") != repo_id:
            run_reason = "run-repository-mismatch"
        elif event not in SUPPORTED_EVENTS:
            run_reason = "unsupported-event"
        elif not references_armor(run, self.allowed):
            run_reason = "not-armor-checker-run"
        elif not self._run_data_ok(run):
            run_reason = "unexpected-run-data"
        elif event == "pull_request":
            entry["prs"] = trusted_prs(self.source, repo, repo_id, run)
            if not entry["prs"]:
                run_reason = "pr-unresolvable"

        for kind in sorted(artifacts):
            entry["artifacts"].append(self._collect_artifact(repo, repo_id, run, entry, kind, artifacts[kind], run_reason))
        self.runs.append(entry)
        log(f"{repo} run {run_id} (attempt {attempt}, {entry['event']}): "
            + ", ".join(f"{a['kind']}={a['status']}" for a in entry["artifacts"]))

    @staticmethod
    def _run_data_ok(run: Dict[str, Any]) -> bool:
        try:
            parse_github_time(run.get("created_at"))
            parse_github_time(run.get("updated_at"))
        except (ValueError, TypeError):
            return False
        return bool(rules.SHA_RE.fullmatch(str(run.get("head_sha") or "")))

    def _collect_artifact(self, repo: str, repo_id: int, run: Dict[str, Any], entry: Dict[str, Any],
                          kind: str, art: Dict[str, Any], run_reason: Optional[str]) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "kind": kind,
            "name": art.get("name"),
            "artifact_id": art.get("id"),
            "size": art.get("size_in_bytes"),
            "digest": art.get("digest") if isinstance(art.get("digest"), str) else None,
        }
        workflow_run = art.get("workflow_run") or {}
        if run_reason:
            return dict(result, status="ignored", reason=run_reason)
        if (workflow_run.get("id") != run["id"] or workflow_run.get("repository_id") != repo_id
                or workflow_run.get("head_sha") != run.get("head_sha")):
            return dict(result, status="ignored", reason="artifact-run-mismatch")
        if art.get("expired"):
            return dict(result, status="ignored", reason="artifact-expired")
        if not rules.is_int(art.get("size_in_bytes")) or art["size_in_bytes"] > rules.MAX_ZIP_BYTES:
            return dict(result, status="ignored", reason="artifact-too-large")

        rel = f"raw/{entry['dir']}/{kind}.zip"
        dest = os.path.join(self.out_dir, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        try:
            sha, size = self.source.download_artifact_zip(repo, art["id"], dest, rules.MAX_ZIP_BYTES)
        except GitHubError as exc:
            if os.path.exists(dest):
                os.remove(dest)
            reason = "artifact-too-large" if "larger than" in str(exc) else "artifact-download-failed"
            status = "ignored" if reason == "artifact-too-large" else "error"
            return dict(result, status=status, reason=reason, detail=safe_text(exc))
        digest = result["digest"] or ""
        if digest.startswith("sha256:") and digest[len("sha256:"):].lower() != sha:
            os.remove(dest)
            return dict(result, status="ignored", reason="artifact-digest-mismatch")
        self.stats["downloaded"] += 1
        return dict(result, status="downloaded", file=rel, sha256=sha, downloaded_size=size)


def run_collect(repos_file: str, out_dir: str, lookback_hours: int, env: Dict[str, str]) -> None:
    if not 1 <= lookback_hours <= 24 * 90:
        raise ValueError("lookback-hours must be between 1 and 2160")
    server_url = env.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    api_url = env.get("GITHUB_API_URL", "https://api.github.com")
    central_repo = env["GITHUB_REPOSITORY"]
    current_run_id = int(env["GITHUB_RUN_ID"])
    workflow_file = workflow_file_from_ref(env.get("GITHUB_WORKFLOW_REF", ""))

    central = GitHubClient(env["CENTRAL_TOKEN"], api_url)
    source = GitHubClient(env.get("SOURCE_TOKEN") or env["CENTRAL_TOKEN"], api_url)

    default_branch = central.get_json(f"/repos/{central_repo}")["default_branch"]
    if env.get("GITHUB_REF") != f"refs/heads/{default_branch}":
        raise SystemExit("The publisher only runs from the default branch of the central repository.")

    previous = ledger_mod.load_previous(central, central_repo, workflow_file, default_branch, current_run_id)
    repos = read_repos_file(repos_file)
    now = utcnow()
    collector = Collector(source, previous, out_dir, now - _dt.timedelta(hours=lookback_hours),
                          parse_allowed_workflows(env.get("ARMOR_CHECKER_WORKFLOWS", "")))
    for repo in repos:
        collector.collect_repo(repo)

    candidates = {
        "version": 1,
        "generated_at": format_github_time(now),
        "server_url": server_url,
        "central_repo": central_repo,
        "central_run_id": current_run_id,
        "lookback_hours": lookback_hours,
        "ledger": previous,
        "stats": collector.stats,
        "runs": collector.runs,
        "repo_errors": collector.repo_errors,
    }
    payload = write_json(os.path.join(out_dir, "candidates.json"), candidates)
    set_output("candidates_sha256", sha256_bytes(payload))
    set_output("downloaded", collector.stats["downloaded"])
    log(f"Repositories: {collector.stats['repos']}, runs to process: {len(collector.runs)}, "
        f"artifacts downloaded: {collector.stats['downloaded']}, in-progress runs skipped: "
        f"{collector.stats['pending_runs']}, already processed: {collector.stats['already_processed']}")
