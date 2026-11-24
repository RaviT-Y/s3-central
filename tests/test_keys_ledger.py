import datetime as dt
import unittest

import _helpers as h
import ledger
import s3_keys
from common import parse_github_time


def run(event="pull_request", **overrides):
    data = {"repo": h.REPO, "run_id": h.RUN_ID, "event": event, "head_branch": "development",
            "created_at": "2026-11-20T10:05:00Z"}
    data.update(overrides)
    return data


class S3KeyTest(unittest.TestCase):
    def test_pull_request_prefix_matches_old_layout(self):
        prefix = s3_keys.run_prefix(run(), h.SERVER, 42)
        self.assertEqual(prefix, "2026/11/20/10/github.com/qualcomm/fastrpc/42/merge/1234567890")

    def test_push_prefix_uses_branch(self):
        prefix = s3_keys.run_prefix(run("push", head_branch="release/1.2"), h.SERVER, None)
        self.assertEqual(prefix, "2026/11/20/10/github.com/qualcomm/fastrpc/release/1.2/1234567890")

    def test_unsafe_branches_rejected(self):
        for branch in ("../x", "a//b", "/a", "a/", "a b", "a/./b", ""):
            with self.assertRaises(s3_keys.KeyError_, msg=branch):
                s3_keys.run_prefix(run("push", head_branch=branch), h.SERVER, None)

    def test_pull_request_needs_pr_number(self):
        with self.assertRaises(s3_keys.KeyError_):
            s3_keys.run_prefix(run(), h.SERVER, None)

    def test_object_key_cannot_escape_prefix(self):
        prefix = s3_keys.run_prefix(run(), h.SERVER, 42)
        self.assertEqual(s3_keys.object_key(prefix, "files/metadata.json"), prefix + "/files/metadata.json")
        for rel in ("files/../../x", "../x", "files//x"):
            with self.assertRaises(s3_keys.KeyError_):
                s3_keys.object_key(prefix, rel)


class LedgerTest(unittest.TestCase):
    def test_record_and_reprocess_on_rerun(self):
        book = ledger.empty()
        now = parse_github_time("2026-11-21T03:17:00Z")
        key = ledger.run_key("Qualcomm/FastRPC", 5)
        ledger.record(book, key, 1, "2026-11-20T10:00:00Z", {"api": "published"}, now)
        self.assertTrue(ledger.is_done(book, key, 1))
        self.assertFalse(ledger.is_done(book, key, 2))       # re-run attempt is processed again
        self.assertTrue(ledger.is_done(book, "qualcomm/fastrpc#5", 1))

    def test_prune_and_parse(self):
        book = ledger.empty()
        now = parse_github_time("2026-11-21T03:17:00Z")
        ledger.record(book, "o/r#1", 1, "2026-09-01T00:00:00Z", {"api": "ignored"}, now)
        ledger.record(book, "o/r#2", 1, "2026-11-20T00:00:00Z", {"abi": "published"}, now)
        ledger.prune(book, now, keep_days=30)
        self.assertEqual(list(book["runs"]), ["o/r#2"])
        self.assertIs(ledger.parse(book), book)
        for bad in ({}, {"version": 2, "runs": {}}, {"version": 1, "runs": {"bad key": {}}},
                    {"version": 1, "runs": {"o/r#1": {"attempt": 1, "created_at": "x", "artifacts": {}}}}):
            with self.assertRaises(ValueError):
                ledger.parse(bad)


if __name__ == "__main__":
    unittest.main()
