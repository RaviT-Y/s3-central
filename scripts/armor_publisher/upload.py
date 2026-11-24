"""Upload job: send validated ARMOR files to S3 (runs on the AWS self-hosted runner).

* S3 keys come only from the trusted run data in candidates.json (hash-checked
  against the collect job's output) and the bucket from repository config.
* The validated bundle is re-checked (paths, file types, sizes, regular files,
  content signatures, hashes) before anything is staged, so even a faulty
  validate job cannot push unexpected files.
* Uses ``aws s3 cp`` with the runner's ambient credentials, as the old in-PR
  upload did.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import rules
import s3_keys
from common import (error, format_github_time, log, read_json, safe_text, sha256_file, utcnow, write_json)
from rules import Rejected

_BUCKET_RE = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")
_ACCOUNT_RE = re.compile(r"[0-9]{12}")


class UploadError(ValueError):
    pass


def recheck_tree(root: str, kind: str, expected: List[Dict[str, Any]]) -> List[Tuple[str, str, int]]:
    """Return ``[(relpath, abspath, size)]`` after re-validating every file."""
    expected_map = {item["path"]: item for item in expected}
    found: Dict[str, Tuple[str, int]] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames:
            if os.path.islink(os.path.join(dirpath, name)):
                raise Rejected("not-a-regular-file", "symlink in validated bundle")
        for name in filenames:
            path = os.path.join(dirpath, name)
            info = os.lstat(path)
            if not stat.S_ISREG(info.st_mode):
                raise Rejected("not-a-regular-file", "non-regular file in validated bundle")
            if info.st_mode & 0o111:
                raise Rejected("executable-file", "executable file in validated bundle")
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            rules.check_relpath(rel)
            rules.check_layout(kind, rel)
            if info.st_size > rules.MAX_FILE_BYTES:
                raise Rejected("file-too-large")
            with open(path, "rb") as handle:
                rules.check_content(handle.read(rules.MAX_FILE_BYTES + 1), rel)
            found[rel] = (path, info.st_size)
    if set(found) != set(expected_map):
        raise Rejected("bundle-mismatch", "validated bundle does not match the validation report")
    for rel, (path, size) in found.items():
        if size != expected_map[rel]["size"] or sha256_file(path) != expected_map[rel]["sha256"]:
            raise Rejected("bundle-mismatch", "validated file changed after validation")
    return sorted((rel, path, size) for rel, (path, size) in found.items())


def choose_pr(run: Dict[str, Any], entries: List[Dict[str, Any]]) -> Optional[int]:
    if run["event"] != "pull_request":
        return None
    trusted = {pr["number"] for pr in run["prs"]}
    claimed = {entry.get("pr_number") for entry in entries}
    if len(claimed) != 1:
        raise UploadError("artifacts of one run name different pull requests")
    pr = claimed.pop()
    if pr not in trusted:
        raise UploadError("pull request is not one of the run's pull requests")
    return pr


def _destinations(kind: str, rel: str) -> str:
    """Where a validated file goes below <run prefix>/files/ (same names as the old upload)."""
    if kind == "api":
        return rel
    if rel == rules.ABI_METADATA:
        return rules.ABI_METADATA
    return f"abi_reports/{rel}"


class S3Uploader:
    def __init__(self, bucket: str, expected_owner: str = "", dry_run: bool = False,
                 runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        if not _BUCKET_RE.fullmatch(bucket or ""):
            raise UploadError("invalid S3 bucket name")
        if expected_owner and not _ACCOUNT_RE.fullmatch(expected_owner):
            raise UploadError("invalid expected bucket owner (12-digit AWS account id)")
        self.bucket = bucket
        self.expected_owner = expected_owner
        self.dry_run = dry_run
        self._run = runner
        self._sleep = sleep
        if not dry_run and shutil.which("aws") is None:
            raise UploadError("aws CLI not found on the upload runner")

    def copy(self, src: str, key: str, content_type: str, recursive: bool = False) -> None:
        dest = f"s3://{self.bucket}/{key}"
        if self.dry_run:
            log(f"[dry-run] aws s3 cp {'--recursive ' if recursive else ''}... {dest}")
            return
        cmd = ["aws", "s3", "cp", src, dest, "--content-type", content_type, "--only-show-errors"]
        if recursive:
            cmd.append("--recursive")
        if self.expected_owner:
            cmd += ["--expected-bucket-owner", self.expected_owner]
        last = ""
        for attempt in range(3):
            proc = self._run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            if proc.returncode == 0:
                return
            lines = (proc.stderr or "").strip().splitlines()
            last = safe_text(lines[-1] if lines else "no error output", 300)
            if attempt < 2:
                self._sleep(5)
        raise UploadError(f"aws s3 cp failed: {last}")


def run_upload(candidates: Dict[str, Any], bundle_dir: str, staging_dir: str, uploader: S3Uploader,
               out_path: str, publisher_url: str) -> int:
    validation = load_validation(os.path.join(bundle_dir, "validation.json"))
    runs = {run["key"]: run for run in candidates["runs"]}
    server_url = candidates["server_url"]

    accepted: Dict[str, List[Dict[str, Any]]] = {}
    for entry in validation:
        run = runs.get(entry.get("key"))
        if entry.get("status") != "accepted" or run is None:
            continue
        downloaded = {a["kind"] for a in run["artifacts"] if a["status"] == "downloaded"}
        if entry.get("kind") in downloaded:
            accepted.setdefault(run["key"], []).append(entry)

    results: List[Dict[str, Any]] = []
    failures = 0
    for key in sorted(accepted):
        run, entries = runs[key], sorted(accepted[key], key=lambda e: e["kind"])
        try:
            pr = choose_pr(run, entries)
            prefix = s3_keys.run_prefix(run, server_url, pr)
        except (UploadError, s3_keys.KeyError_) as exc:
            failures += len(entries)
            error(f"{run['repo']} run {run['run_id']}: cannot build S3 key ({safe_text(exc)})")
            results += [{"key": key, "kind": e["kind"], "status": "error", "reason": "s3-key-invalid"} for e in entries]
            continue

        manifest_artifacts = []
        for entry in entries:
            kind = entry["kind"]
            source_dir = os.path.join(bundle_dir, "validated", run["dir"], kind)
            try:
                files = recheck_tree(source_dir, kind, entry.get("files", []))
                objects = _stage_and_upload(uploader, run, kind, files, prefix, staging_dir)
            except (Rejected, UploadError, OSError) as exc:
                failures += 1
                reason = exc.code if isinstance(exc, Rejected) else "s3-upload-failed"
                error(f"{run['repo']} run {run['run_id']} {kind}: upload failed ({reason})")
                results.append({"key": key, "kind": kind, "status": "error", "reason": reason})
                continue
            artifact = next(a for a in run["artifacts"] if a["kind"] == kind)
            manifest_artifacts.append({
                "kind": kind,
                "artifact_name": artifact["name"],
                "artifact_id": artifact["artifact_id"],
                "artifact_digest": artifact.get("digest"),
                "objects": objects,
            })
            results.append({"key": key, "kind": kind, "status": "dry-run" if uploader.dry_run else "published",
                            "prefix": prefix, "objects": len(objects)})
            log(f"{run['repo']} run {run['run_id']} {kind}: {len(objects)} objects -> s3://{uploader.bucket}/{prefix}/files/")

        if manifest_artifacts:
            try:
                _upload_manifest(uploader, run, pr, prefix, manifest_artifacts, staging_dir, publisher_url)
            except (UploadError, OSError):
                failures += len(manifest_artifacts)
                for item in results:
                    if item["key"] == key and item["status"] == "published":
                        item.update(status="error", reason="s3-manifest-failed")

    write_json(out_path, {"version": 1, "results": results})
    return failures


def load_validation(path: str) -> List[Dict[str, Any]]:
    data = read_json(path)
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise UploadError("validation report has an unexpected structure")
    return data["results"]


def _stage_and_upload(uploader: S3Uploader, run: Dict[str, Any], kind: str,
                      files: List[Tuple[str, str, int]], prefix: str, staging_dir: str) -> List[Dict[str, Any]]:
    stage = os.path.join(staging_dir, run["dir"], kind)
    shutil.rmtree(stage, ignore_errors=True)
    objects = []
    for rel, path, size in files:
        dest_rel = _destinations(kind, rel)
        key = s3_keys.object_key(prefix, f"files/{dest_rel}")
        group = "json" if (kind == "abi" and rel == rules.ABI_METADATA) else "data"
        target = os.path.join(stage, group, *dest_rel.split("/"))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copyfile(path, target)
        objects.append({"key": key, "size": size, "sha256": sha256_file(target)})

    data_dir = os.path.join(stage, "data")
    if os.path.isdir(data_dir):
        # Same command as the old in-PR upload of the API report folder.
        uploader.copy(data_dir, f"{prefix}/files", "application/octet-stream", recursive=True)
    json_file = os.path.join(stage, "json", rules.ABI_METADATA)
    if os.path.isfile(json_file):
        uploader.copy(json_file, f"{prefix}/files/{rules.ABI_METADATA}", "application/json")
    shutil.rmtree(stage, ignore_errors=True)
    return objects


def _upload_manifest(uploader: S3Uploader, run: Dict[str, Any], pr: Optional[int], prefix: str,
                     artifacts: List[Dict[str, Any]], staging_dir: str, publisher_url: str) -> None:
    manifest = {
        "version": 1,
        "published_at": format_github_time(utcnow()),
        "publisher_run": publisher_url,
        "source": {
            "repository": run["repo"],
            "run_id": run["run_id"],
            "run_attempt": run["run_attempt"],
            "event": run["event"],
            "head_sha": run["head_sha"],
            "head_repository": run["head_repository"],
            "is_fork": run["is_fork"],
            "pr_number": pr,
            "run_created_at": run["created_at"],
        },
        "artifacts": artifacts,
    }
    path = os.path.join(staging_dir, run["dir"], "publish-manifest.json")
    write_json(path, manifest)
    uploader.copy(path, s3_keys.object_key(prefix, "publish-manifest.json"), "application/json")
    os.remove(path)
