"""End-to-end tests: collect -> validate -> upload -> finalize with fakes for GitHub and aws."""

import hashlib
import http.server
import json
import os
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

import _helpers as h
import collect
import ledger
import publisher
import upload
import validator
from common import parse_github_time, sha256_bytes, write_json
from github_api import GitHubClient, GitHubError

REPO_ID = 99
CUTOFF = parse_github_time("2026-11-19T00:00:00Z")
ARMOR_REF = [{"path": "qualcomm/armor-checkers/.github/workflows/armor-checker.yml@v2", "sha": "f" * 40}]


def _artifact(art_id, name, run_id, created="2026-11-20T10:20:00Z", digest_of=None, head_sha=h.HEAD_SHA):
    data = f"zip-{art_id}".encode()
    return {"id": art_id, "name": name, "size_in_bytes": len(data), "expired": False, "created_at": created,
            "digest": "sha256:" + sha256_bytes(digest_of if digest_of is not None else data),
            "workflow_run": {"id": run_id, "repository_id": REPO_ID, "head_sha": head_sha}}


def _run(run_id, event="pull_request", status="completed", refs=ARMOR_REF, prs=True, head_repo=h.REPO):
    owner = head_repo.split("/")[0]
    return {"id": run_id, "status": status, "run_attempt": 1, "event": event, "head_sha": h.HEAD_SHA,
            "head_branch": "feature/x", "created_at": "2026-11-20T10:00:00Z", "updated_at": "2026-11-20T10:30:00Z",
            "repository": {"id": REPO_ID, "full_name": h.REPO},
            "head_repository": {"full_name": head_repo, "owner": {"login": owner}},
            "referenced_workflows": refs,
            "pull_requests": [{"number": 42, "base": {"ref": "development", "repo": {"id": REPO_ID}}}] if prs else []}


class FakeGitHub(GitHubClient):
    def __init__(self, routes):
        super().__init__("test-token")
        self.routes = routes
        self.downloads = []

    def get_json(self, path, params=None):
        params = params or {}
        key = (path, params.get("name"), params.get("page", 1)) if path.endswith("/actions/artifacts") else path
        if path.endswith("/pulls"):
            key = (path, params.get("head"))
        if key not in self.routes:
            if isinstance(key, tuple) and key[0].endswith("/actions/artifacts"):
                return {"total_count": 0, "artifacts": []}
            raise GitHubError("HTTP 404", 404)
        return self.routes[key]

    def download_artifact_zip(self, repo, artifact_id, dest, max_bytes):
        data = f"zip-{artifact_id}".encode()
        with open(dest, "wb") as handle:
            handle.write(data)
        self.downloads.append(artifact_id)
        return hashlib.sha256(data).hexdigest(), len(data)


class CollectTest(unittest.TestCase):
    def test_collect_filters_runs(self):
        api, abi = "apichecker-reports", "abichecker-reports"
        path = f"/repos/{h.REPO}/actions/artifacts"
        routes = {
            f"/repos/{h.REPO}": {"full_name": h.REPO, "id": REPO_ID},
            (path, api, 1): {"artifacts": [
                _artifact(11, api, 1001), _artifact(21, api, 1002), _artifact(31, api, 1003),
                _artifact(41, api, 1004), _artifact(51, api, 1005),
                _artifact(61, api, 1006, digest_of=b"something else"),
                _artifact(71, api, 1007, created="2026-10-01T00:00:00Z"),      # older than lookback
            ]},
            (path, abi, 1): {"artifacts": [_artifact(12, abi, 1001)]},
            f"/repos/{h.REPO}/actions/runs/1001": _run(1001),
            f"/repos/{h.REPO}/actions/runs/1002": _run(1002, status="in_progress"),
            f"/repos/{h.REPO}/actions/runs/1003": _run(1003, refs=[]),
            f"/repos/{h.REPO}/actions/runs/1004": _run(1004, prs=False, head_repo="contributor/fastrpc"),
            f"/repos/{h.REPO}/actions/runs/1005": _run(1005),
            f"/repos/{h.REPO}/actions/runs/1006": _run(1006),
            (f"/repos/{h.REPO}/pulls", "contributor:feature/x"): [
                {"number": 7, "head": {"repo": {"full_name": "contributor/fastrpc"}},
                 "base": {"ref": "development", "repo": {"id": REPO_ID}}}],
        }
        book = ledger.empty()
        ledger.record(book, ledger.run_key(h.REPO, 1005), 1, "2026-11-20T10:00:00Z", {"api": "published"},
                      parse_github_time("2026-11-21T00:00:00Z"))
        with tempfile.TemporaryDirectory() as tmp:
            client = FakeGitHub(routes)
            c = collect.Collector(client, book, tmp, CUTOFF, collect.parse_allowed_workflows(""))
            c.collect_repo(h.REPO)

        by_run = {r["run_id"]: r for r in c.runs}
        self.assertEqual(sorted(by_run), [1001, 1003, 1004, 1006])
        self.assertEqual([a["status"] for a in by_run[1001]["artifacts"]], ["downloaded", "downloaded"])
        self.assertEqual(by_run[1003]["artifacts"][0]["reason"], "not-armor-checker-run")
        self.assertEqual(by_run[1004]["prs"], [{"number": 7, "base_ref": "development"}])
        self.assertTrue(by_run[1004]["is_fork"])
        self.assertEqual(by_run[1006]["artifacts"][0]["reason"], "artifact-digest-mismatch")
        self.assertEqual(c.stats["pending_runs"], 1)
        self.assertEqual(c.stats["already_processed"], 1)
        self.assertNotIn(31, client.downloads)            # ignored runs are never downloaded

    def test_repos_file_parsing(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
            handle.write("# comment\nqualcomm/fastrpc\n\n  qualcomm/other  # trailing comment\n")
        self.addCleanup(os.remove, handle.name)
        self.assertEqual(collect.read_repos_file(handle.name), ["qualcomm/fastrpc", "qualcomm/other"])
        for bad in ("qualcomm\n", "qualcomm/a\nQualcomm/A\n", "a/b/c\n", "# only comments\n"):
            with open(handle.name, "w") as f:
                f.write(bad)
            with self.assertRaises(ValueError, msg=bad):
                collect.read_repos_file(handle.name)


class PipelineTest(unittest.TestCase):
    """validate + upload + finalize on real zips, with a fake aws CLI."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = self.tmp.name
        self.collect_dir = os.path.join(root, "collect")
        os.makedirs(os.path.join(self.collect_dir, "raw", "run"))
        api_zip = h.make_zip(os.path.join(self.collect_dir, "raw", "run", "api.zip"), h.api_files())
        bad_files = dict(h.abi_files(), **{"src__.libs__libadsprpc.so.txt": b"#!/bin/sh\necho owned\n"})
        abi_zip = h.make_zip(os.path.join(self.collect_dir, "raw", "run", "abi.zip"), bad_files)
        run = dict(h.ctx(), key=ledger.run_key(h.REPO, h.RUN_ID), dir="run", repo_id=REPO_ID,
                   head_repository=h.REPO, is_fork=False)
        del run["server_url"]
        run["artifacts"] = [
            {"kind": "abi", "name": "abichecker-reports", "artifact_id": 2, "status": "downloaded",
             "file": "raw/run/abi.zip", "sha256": publisher.sha256_file(abi_zip), "digest": None},
            {"kind": "api", "name": "apichecker-reports", "artifact_id": 1, "status": "downloaded",
             "file": "raw/run/api.zip", "sha256": publisher.sha256_file(api_zip), "digest": None},
        ]
        candidates = {"version": 1, "server_url": h.SERVER, "lookback_hours": 48, "ledger": ledger.empty(),
                      "stats": {"repos": 1, "pending_runs": 0, "already_processed": 0, "downloaded": 2},
                      "runs": [run], "repo_errors": []}
        self.candidates_path = os.path.join(self.collect_dir, "candidates.json")
        self.sha = sha256_bytes(write_json(self.candidates_path, candidates))
        self.outputs = os.path.join(root, "github_output")
        open(self.outputs, "w").close()
        self.env = mock.patch.dict(os.environ, {"GITHUB_OUTPUT": self.outputs,
                                                "GITHUB_STEP_SUMMARY": os.path.join(root, "summary.md")})
        self.env.start()
        self.addCleanup(self.env.stop)

    def _outputs(self):
        with open(self.outputs) as handle:
            return dict(line.strip().split("=", 1) for line in handle if "=" in line)

    def test_bad_artifact_ignored_good_one_uploaded_run_fails(self):
        bundle = os.path.join(self.tmp.name, "bundle")
        self.assertEqual(publisher.main(["validate", "--collect-dir", self.collect_dir,
                                         "--candidates-sha256", self.sha, "--out", bundle]), 0)
        report = json.load(open(os.path.join(bundle, "validation.json")))["results"]
        status = {r["kind"]: (r["status"], r.get("reason")) for r in report}
        self.assertEqual(status["abi"], ("ignored", "executable-or-archive"))
        self.assertEqual(status["api"], ("accepted", None))
        self.assertFalse(os.path.exists(os.path.join(bundle, "validated", "run", "abi")))

        calls = []

        def fake_aws(cmd, **kwargs):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with mock.patch.object(upload.shutil, "which", return_value="/usr/bin/aws"):
            uploader = upload.S3Uploader("qli-prd-armor-gh-artifacts", runner=fake_aws)
        results_path = os.path.join(self.tmp.name, "upload-results.json")
        staging = os.path.join(self.tmp.name, "staging")
        failures = upload.run_upload(json.load(open(self.candidates_path)), bundle, staging, uploader,
                                     results_path, "https://github.com/qualcomm/armor-s3-publisher/actions/runs/1")
        self.assertEqual(failures, 0)
        prefix = "s3://qli-prd-armor-gh-artifacts/2026/11/20/10/github.com/qualcomm/fastrpc/42/merge/1234567890"
        self.assertEqual(calls[0][4:], [f"{prefix}/files", "--content-type", "application/octet-stream",
                                        "--only-show-errors", "--recursive"])
        self.assertEqual(calls[1][4], f"{prefix}/publish-manifest.json")
        self.assertEqual(len(calls), 2)

        final = os.path.join(self.tmp.name, "final")
        publisher.main(["finalize", "--candidates", self.candidates_path, "--candidates-sha256", self.sha,
                        "--validation", os.path.join(bundle, "validation.json"),
                        "--upload-results", results_path, "--out", final])
        out = self._outputs()
        self.assertEqual(out["failed"], "1")            # the ignored ABI artifact fails the run
        self.assertEqual(out["published"], "1")
        book = json.load(open(os.path.join(final, "ledger.json")))
        self.assertEqual(book["runs"][ledger.run_key(h.REPO, h.RUN_ID)]["artifacts"],
                         {"abi": "ignored", "api": "published"})

    def test_tampered_bundle_is_not_uploaded(self):
        bundle = os.path.join(self.tmp.name, "bundle")
        publisher.main(["validate", "--collect-dir", self.collect_dir, "--candidates-sha256", self.sha, "--out", bundle])
        with open(os.path.join(bundle, "validated", "run", "api", "others.txt"), "a") as handle:
            handle.write("[BACKWARD_COMPATIBLE]inc/remote.h\n")
        with mock.patch.object(upload.shutil, "which", return_value="/usr/bin/aws"):
            uploader = upload.S3Uploader("qli-prd-armor-gh-artifacts",
                                         runner=lambda cmd, **kw: self.fail("aws must not be called"))
        results_path = os.path.join(self.tmp.name, "r.json")
        failures = upload.run_upload(json.load(open(self.candidates_path)), bundle, os.path.join(self.tmp.name, "s"),
                                     uploader, results_path, "url")
        self.assertEqual(failures, 1)
        self.assertEqual(json.load(open(results_path))["results"][0]["reason"], "bundle-mismatch")

    def test_tampered_candidates_rejected(self):
        with open(self.candidates_path, "a") as handle:
            handle.write(" ")
        self.assertEqual(publisher.main(["validate", "--collect-dir", self.collect_dir,
                                         "--candidates-sha256", self.sha, "--out", self.tmp.name + "/b"]), 1)


class RedirectTest(unittest.TestCase):
    """Artifact downloads must not send the GitHub token to the storage host."""

    def test_token_not_forwarded(self):
        seen = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.endswith("/zip"):
                    seen["api_auth"] = self.headers.get("Authorization")
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/blob")
                    self.end_headers()
                else:
                    seen["blob_auth"] = self.headers.get("Authorization")
                    body = b"zip-bytes"
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        client = GitHubClient("secret-token", api_url=f"http://127.0.0.1:{server.server_port}",
                              require_https_redirect=False, max_retries=0)
        with tempfile.TemporaryDirectory() as tmp:
            sha, size = client.download_artifact_zip("o/r", 5, os.path.join(tmp, "a.zip"), 1000)
        self.assertEqual(seen["api_auth"], "Bearer secret-token")
        self.assertIsNone(seen["blob_auth"])
        self.assertEqual((sha, size), (hashlib.sha256(b"zip-bytes").hexdigest(), 9))

    def test_https_required_for_redirect(self):
        client = GitHubClient("t", require_https_redirect=True)
        with mock.patch.object(client, "_open", return_value=(302, {"Location": "http://evil.example/blob"}, None)):
            with self.assertRaises(GitHubError):
                client.download_artifact_zip("o/r", 5, "/dev/null", 10)


if __name__ == "__main__":
    unittest.main()
