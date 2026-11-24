#!/usr/bin/env python3
"""ARMOR S3 publisher command line.

    publisher.py collect   --repos-file repos.txt --lookback-hours 48 --out DIR
    publisher.py validate  --collect-dir DIR --candidates-sha256 SHA --out DIR
    publisher.py upload    --candidates FILE --candidates-sha256 SHA --bundle DIR --bucket NAME --out FILE
    publisher.py finalize  --candidates FILE --candidates-sha256 SHA --out DIR [--validation FILE] [--upload-results FILE]

Run with ``python3 -I`` (isolated mode): the environment and the current
directory cannot influence which modules are imported.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # sibling modules (trusted checkout)

import ledger as ledger_mod  # noqa: E402
import rules  # noqa: E402
from common import (append_summary, error, load_verified_json, log, read_json,  # noqa: E402
                    safe_text, set_output, sha256_file, utcnow, warning, write_json)

_RAW_FILE_RE = re.compile(r"raw/[A-Za-z0-9_.-]+/(api|abi)\.zip")
_SANDBOX_TIMEOUT = 600


# ----------------------------------------------------------------------------
# collect
# ----------------------------------------------------------------------------
def cmd_collect(args: argparse.Namespace) -> int:
    import collect
    collect.run_collect(args.repos_file, args.out, args.lookback_hours, dict(os.environ))
    return 0


# ----------------------------------------------------------------------------
# validate (orchestrates one sandboxed subprocess per artifact)
# ----------------------------------------------------------------------------
def _sandbox_limits() -> None:  # runs in the child before exec
    import resource
    gib = 1024 * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (2 * gib, 2 * gib))
    resource.setrlimit(resource.RLIMIT_CPU, (300, 300))
    resource.setrlimit(resource.RLIMIT_FSIZE, (rules.MAX_FILE_BYTES + 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))


def _validate_in_sandbox(zip_path: str, kind: str, ctx: dict, target: str) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        ctx_path = os.path.join(tmp, "ctx.json")
        result_path = os.path.join(tmp, "result.json")
        write_json(ctx_path, ctx)
        cmd = [sys.executable, "-I", os.path.abspath(__file__), "validate-one",
               "--zip", zip_path, "--kind", kind, "--ctx", ctx_path, "--out", target, "--result", result_path]
        try:
            proc = subprocess.run(cmd, preexec_fn=_sandbox_limits, timeout=_SANDBOX_TIMEOUT,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, check=False)
        except subprocess.TimeoutExpired:
            return {"ok": False, "reason": "validator-timeout", "detail": "validation took too long"}
        if proc.returncode != 0 or not os.path.isfile(result_path):
            return {"ok": False, "reason": "validator-crashed", "detail": f"validator exited with {proc.returncode}"}
        return read_json(result_path)


def cmd_validate(args: argparse.Namespace) -> int:
    candidates = load_verified_json(os.path.join(args.collect_dir, "candidates.json"), args.candidates_sha256)
    validated_root = os.path.join(args.out, "validated")
    os.makedirs(validated_root, exist_ok=True)
    results, accepted = [], 0
    for run in candidates["runs"]:
        ctx = {key: run[key] for key in ("repo", "run_id", "run_attempt", "event", "head_sha",
                                          "head_branch", "created_at", "updated_at", "prs")}
        ctx["server_url"] = candidates["server_url"]
        for artifact in run["artifacts"]:
            if artifact["status"] != "downloaded":
                continue
            entry = {"key": run["key"], "kind": artifact["kind"]}
            rel = artifact.get("file", "")
            zip_path = os.path.join(args.collect_dir, *rel.split("/"))
            if (not _RAW_FILE_RE.fullmatch(rel) or not os.path.isfile(zip_path)
                    or sha256_file(zip_path) != artifact["sha256"]):
                entry.update(status="error", reason="raw-artifact-missing")
                results.append(entry)
                continue
            target = os.path.join(validated_root, run["dir"], artifact["kind"])
            shutil.rmtree(target, ignore_errors=True)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            outcome = _validate_in_sandbox(zip_path, artifact["kind"], ctx, target)
            if outcome.get("ok") is True:
                accepted += 1
                entry.update(status="accepted", files=outcome["files"], pr_number=outcome["pr_number"])
            else:
                shutil.rmtree(target, ignore_errors=True)
                entry.update(status="ignored", reason=safe_text(outcome.get("reason"), 64),
                             detail=safe_text(outcome.get("detail", ""), 200))
            log(f"{run['repo']} run {run['run_id']} {artifact['kind']}: {entry['status']}"
                + (f" ({entry['reason']}: {entry['detail']})" if entry["status"] != "accepted" else ""))
            results.append(entry)
    write_json(os.path.join(args.out, "validation.json"), {"version": 1, "results": results})
    set_output("accepted", accepted)
    log(f"Validated artifacts: {len(results)}, accepted: {accepted}")
    return 0


def cmd_validate_one(args: argparse.Namespace) -> int:
    import validator
    ctx = read_json(args.ctx)
    try:
        result = validator.validate_artifact(args.zip, args.kind, ctx, args.out)
        write_json(args.result, dict(result, ok=True))
    except rules.Rejected as rejected:
        write_json(args.result, {"ok": False, "reason": rejected.code, "detail": rejected.detail})
    return 0


# ----------------------------------------------------------------------------
# upload
# ----------------------------------------------------------------------------
def cmd_upload(args: argparse.Namespace) -> int:
    import upload
    candidates = load_verified_json(args.candidates, args.candidates_sha256)
    uploader = upload.S3Uploader(args.bucket, args.expected_bucket_owner or "", dry_run=args.dry_run)
    staging = tempfile.mkdtemp(prefix="armor-s3-staging-")
    try:
        failures = upload.run_upload(candidates, args.bundle, staging, uploader, args.out, _publisher_url())
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    log(f"Upload finished with {failures} failure(s)")
    return 0  # failures are reported by the finalize job


def _publisher_url() -> str:
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    return f"{server}/{os.environ.get('GITHUB_REPOSITORY', '')}/actions/runs/{os.environ.get('GITHUB_RUN_ID', '')}"


# ----------------------------------------------------------------------------
# finalize
# ----------------------------------------------------------------------------
def _index(path: str, label: str) -> dict:
    if not path or not os.path.isfile(path):
        warning(f"{label} not available; affected artifacts are counted as errors")
        return {}
    data = read_json(path)
    items = data.get("results", []) if isinstance(data, dict) else []
    return {(item.get("key"), item.get("kind")): item for item in items if isinstance(item, dict)}


def final_status(run: dict, artifact: dict, validation: dict, uploads: dict, dry_run: bool):
    if artifact["status"] in ("ignored", "error"):
        return artifact["status"], artifact.get("reason", "")
    verdict = validation.get((run["key"], artifact["kind"]))
    if verdict is None:
        return "error", "validation-missing"
    if verdict.get("status") == "ignored":
        return "ignored", verdict.get("reason", "")
    if verdict.get("status") != "accepted":
        return "error", verdict.get("reason", "validation-error")
    uploaded = uploads.get((run["key"], artifact["kind"]))
    if uploaded is None:
        return ("dry-run", "") if dry_run else ("error", "upload-missing")
    if uploaded.get("status") in ("published", "dry-run"):
        return uploaded["status"], ""
    return "error", uploaded.get("reason", "s3-upload-failed")


def cmd_finalize(args: argparse.Namespace) -> int:
    candidates = load_verified_json(args.candidates, args.candidates_sha256)
    validation = _index(args.validation, "Validation report")
    uploads = _index(args.upload_results, "Upload results")
    ledger = ledger_mod.parse(candidates["ledger"])
    now = utcnow()
    server = candidates["server_url"]

    rows, counts = [], {"published": 0, "ignored": 0, "error": 0, "dry-run": 0}
    for run in candidates["runs"]:
        statuses = {}
        for artifact in run["artifacts"]:
            status, reason = final_status(run, artifact, validation, uploads, args.dry_run)
            statuses[artifact["kind"]] = status
            counts[status] = counts.get(status, 0) + 1
            pr = ", ".join(f"#{pr['number']}" for pr in run["prs"]) or "-"
            rows.append(f"| {run['repo']} | [{run['run_id']}]({server}/{run['repo']}/actions/runs/{run['run_id']}) "
                        f"| {safe_text(run['event'], 32)} | {pr} | {artifact['kind'].upper()} | {status} "
                        f"| {safe_text(reason, 64) or '-'} |")
        if not args.dry_run and statuses and all(s in ledger_mod.FINAL_STATES for s in statuses.values()):
            ledger_mod.record(ledger, run["key"], run["run_attempt"], run["created_at"], statuses, now)
    for item in candidates["repo_errors"]:
        counts["error"] += 1
        rows.append(f"| {safe_text(item['repo'])} | - | - | - | - | error | {safe_text(item['reason'], 64)} |")

    keep_days = max(30, candidates["lookback_hours"] // 24 + 7)
    ledger_mod.prune(ledger, now, keep_days)
    os.makedirs(args.out, exist_ok=True)
    write_json(os.path.join(args.out, ledger_mod.LEDGER_FILE), ledger)

    stats = candidates["stats"]
    failed = counts["ignored"] + counts["error"]
    summary = [
        "## ARMOR S3 publisher" + (" (dry run)" if args.dry_run else ""),
        "",
        f"Repositories checked: **{stats['repos']}** · runs processed: **{len(candidates['runs'])}** · "
        f"in-progress runs left for later: **{stats['pending_runs']}** · already published earlier: "
        f"**{stats['already_processed']}**",
        "",
        f"Published: **{counts['published']}** · ignored (validation failed): **{counts['ignored']}** · "
        f"errors (retried next run): **{counts['error']}**" + (f" · dry-run: **{counts['dry-run']}**" if args.dry_run else ""),
        "",
    ]
    if rows:
        summary += ["| Repository | Run | Event | PR | Artifact | Result | Reason |",
                    "|---|---|---|---|---|---|---|"] + rows
    else:
        summary.append("No new ARMOR artifacts found.")
    append_summary("\n".join(summary) + "\n")

    set_output("failed", failed)
    set_output("published", counts["published"])
    log(f"published={counts['published']} ignored={counts['ignored']} errors={counts['error']}")
    return 0


# ----------------------------------------------------------------------------
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("collect")
    p.add_argument("--repos-file", required=True)
    p.add_argument("--lookback-hours", type=int, default=48)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_collect)

    p = sub.add_parser("validate")
    p.add_argument("--collect-dir", required=True)
    p.add_argument("--candidates-sha256", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("validate-one")
    for name in ("--zip", "--kind", "--ctx", "--out", "--result"):
        p.add_argument(name, required=True)
    p.set_defaults(func=cmd_validate_one)

    p = sub.add_parser("upload")
    p.add_argument("--candidates", required=True)
    p.add_argument("--candidates-sha256", required=True)
    p.add_argument("--bundle", required=True)
    p.add_argument("--bucket", required=True)
    p.add_argument("--expected-bucket-owner", default="")
    p.add_argument("--out", required=True)
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_upload)

    p = sub.add_parser("finalize")
    p.add_argument("--candidates", required=True)
    p.add_argument("--candidates-sha256", required=True)
    p.add_argument("--validation", default="")
    p.add_argument("--upload-results", default="")
    p.add_argument("--out", required=True)
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_finalize)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception as exc:  # report cleanly; messages are our own, filtered anyway
        error(f"{args.command} failed: {safe_text(type(exc).__name__)}: {safe_text(exc, 300)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
