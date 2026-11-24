import json
import os
import tempfile
import unittest
import warnings
from unittest import mock

import _helpers as h
import rules
import validator
from rules import Rejected


class ValidatorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.count = 0

    def _run(self, files, kind="api", ctx=None, modes=None, flags=None):
        self.count += 1
        zip_path = h.make_zip(os.path.join(self.tmp.name, f"a{self.count}.zip"), files, modes, flags)
        out = os.path.join(self.tmp.name, f"out{self.count}")
        return validator.validate_artifact(zip_path, kind, ctx or h.ctx(), out)

    def assertRejected(self, code, files, **kwargs):
        with self.assertRaises(Rejected) as caught:
            self._run(files, **kwargs)
        self.assertEqual(caught.exception.code, code, caught.exception.detail)

    # ------------------------------------------------------------ accepted
    def test_valid_api_artifact(self):
        result = self._run(h.api_files())
        self.assertEqual(result["pr_number"], 42)
        self.assertEqual(len(result["files"]), 7)

    def test_valid_abi_artifact(self):
        result = self._run(h.abi_files(), kind="abi")
        self.assertEqual([f["path"] for f in result["files"]], ["abi_metadata.json", "src__.libs__libadsprpc.so.txt"])

    def test_valid_push_artifacts(self):
        push = h.ctx("push")
        self._run(h.api_files(h.api_metadata("push")), ctx=push)
        self._run(h.abi_files(h.abi_metadata("push")), kind="abi", ctx=push)

    def test_new_provenance_fields_accepted(self):
        meta = h.api_metadata(schema_version=1, checker="api", repository=h.REPO, run_id=h.RUN_ID,
                              run_attempt=1, run_head_sha=h.HEAD_SHA)
        self._run(h.api_files(meta))

    # ----------------------------------------------- file types / executables
    def test_script_file_rejected(self):
        self.assertRejected("unexpected-file-type", dict(h.api_files(), **{f"{h.HDR_DIR}/armor_reports/run.sh": b"echo hi\n"}))

    def test_executable_bit_rejected(self):
        files = h.api_files()
        self.assertRejected("executable-file", files, modes={"others.txt": 0o100755})

    def test_elf_disguised_as_text_rejected(self):
        files = dict(h.api_files(), **{"others.txt": b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32})
        self.assertRejected("executable-or-archive", files)

    def test_shebang_script_disguised_as_text_rejected(self):
        files = dict(h.abi_files(), **{"src__.libs__libadsprpc.so.txt": b"#!/bin/sh\nrm -rf /\n"})
        self.assertRejected("executable-or-archive", files, kind="abi")

    def test_nested_archive_rejected(self):
        files = dict(h.api_files(), **{f"{h.HDR_DIR}/debug_output/ast_diffs/a.json": b"PK\x03\x04rest-of-zip"})
        self.assertRejected("executable-or-archive", files)

    def test_binary_content_rejected(self):
        files = dict(h.api_files(), **{f"{h.HDR_DIR}/armor_reports/html_reports/api_diff_report_remote.h.html": b"<html>\x00</html>"})
        self.assertRejected("binary-content", files)

    def test_log_outside_debug_output_rejected(self):
        files = dict(h.api_files(), **{f"{h.HDR_DIR}/armor_reports/run.log": b"text\n"})
        self.assertRejected("unexpected-file", files)

    # --------------------------------------------------------- unsafe paths
    def test_symlink_rejected(self):
        files = dict(h.api_files(), **{f"{h.HDR_DIR}/armor_reports/link.txt": b"/etc/passwd"})
        self.assertRejected("not-a-regular-file", files, modes={f"{h.HDR_DIR}/armor_reports/link.txt": 0o120777})

    def test_path_traversal_rejected(self):
        self.assertRejected("bad-path", dict(h.api_files(), **{"../evil.txt": b"x"}))

    def test_absolute_path_rejected(self):
        self.assertRejected("bad-path", dict(h.api_files(), **{"/tmp/evil.txt": b"x"}))

    def test_backslash_path_rejected(self):
        self.assertRejected("bad-path", dict(h.api_files(), **{"..\\evil.txt": b"x"}))

    def test_hidden_file_rejected(self):
        self.assertRejected("unexpected-file", dict(h.api_files(), **{".headers.ndjson": b"{}"}))

    def test_unexpected_top_level_file_rejected(self):
        self.assertRejected("unexpected-file", dict(h.api_files(), **{"notes.txt": b"hello\n"}))

    def test_duplicate_entries_rejected(self):
        files = dict(h.api_files())
        name = f"{h.HDR_DIR}/armor_reports/Report.json"
        files[name] = b"{}"
        files[name.lower()] = b"{}"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self.assertRejected("duplicate-entry", files)

    def test_not_a_zip_rejected(self):
        path = os.path.join(self.tmp.name, "junk.zip")
        with open(path, "wb") as handle:
            handle.write(b"not a zip at all")
        with self.assertRaises(Rejected) as caught:
            validator.validate_artifact(path, "api", h.ctx(), os.path.join(self.tmp.name, "junk-out"))
        self.assertEqual(caught.exception.code, "not-a-zip")

    def test_encrypted_entry_rejected(self):
        self.assertRejected("encrypted-entry", h.api_files(), flags={"others.txt": 0x1})

    # --------------------------------------------------------------- limits
    def test_too_many_files_rejected(self):
        with mock.patch.object(rules, "MAX_ENTRIES", 3):
            self.assertRejected("too-many-files", h.api_files())

    def test_file_too_large_rejected(self):
        with mock.patch.object(rules, "MAX_FILE_BYTES", 10):
            self.assertRejected("file-too-large", h.api_files())

    def test_zip_bomb_rejected(self):
        files = dict(h.api_files(), **{f"{h.HDR_DIR}/debug_output/logs/big.log": b"A" * 200_000})
        with mock.patch.object(rules, "RATIO_MIN_BYTES", 1000), mock.patch.object(rules, "MAX_RATIO", 10):
            self.assertRejected("zip-bomb", files)

    # ------------------------------------------------------ JSON and schema
    def test_invalid_json_rejected(self):
        files = dict(h.api_files(), **{f"{h.HDR_DIR}/armor_reports/json_reports/api_diff_report_remote.h.json": b"{oops"})
        self.assertRejected("invalid-json", files)

    def test_duplicate_json_keys_rejected(self):
        files = dict(h.api_files(), **{"metadata.json": b'{"branch": "a", "branch": "b"}'})
        self.assertRejected("invalid-json", files)

    def test_nan_rejected(self):
        files = dict(h.api_files(), **{f"{h.HDR_DIR}/armor_reports/json_reports/api_diff_report_remote.h.json": b'{"x": NaN}'})
        self.assertRejected("invalid-json", files)

    def test_missing_metadata_rejected(self):
        files = h.api_files()
        del files["metadata.json"]
        self.assertRejected("missing-metadata", files)

    def test_unknown_metadata_key_rejected(self):
        self.assertRejected("schema-mismatch", h.api_files(h.api_metadata(s3_bucket="attacker-bucket")))

    def test_bad_status_rejected(self):
        meta = h.api_metadata(headers=[{"header": "inc/remote.h", "api_names": [], "compatibility": "PWNED"}])
        self.assertRejected("schema-mismatch", h.api_files(meta))

    def test_unlisted_report_directory_rejected(self):
        files = dict(h.api_files(), **{"other_header.h/armor_reports/json_reports/x.json": b"{}"})
        self.assertRejected("unexpected-file", files)

    def test_unlisted_abi_report_rejected(self):
        files = dict(h.abi_files(), **{"extra.txt": b"hello\n"})
        self.assertRejected("unexpected-file", files, kind="abi")

    # ----------------------------------------------------------- provenance
    def test_other_repository_rejected(self):
        meta = h.api_metadata(project_url="https://github.com/someone/else")
        self.assertRejected("provenance-repository", h.api_files(meta))

    def test_other_run_rejected(self):
        meta = h.api_metadata(artifacts=f"{h.SERVER}/{h.REPO}/actions/runs/999#artifacts")
        self.assertRejected("provenance-run-id", h.api_files(meta))

    def test_event_mismatch_rejected(self):
        self.assertRejected("provenance-event", h.api_files(h.api_metadata(github_event="push")))

    def test_pr_not_in_run_rejected(self):
        self.assertRejected("provenance-pr", h.api_files(h.api_metadata(pr_number=7)))

    def test_branch_mismatch_rejected(self):
        self.assertRejected("provenance-branch", h.api_files(h.api_metadata(branch="main")))

    def test_push_commit_mismatch_rejected(self):
        meta = h.abi_metadata("push", head_sha="d" * 40)
        self.assertRejected("provenance-commit", h.abi_files(meta), kind="abi", ctx=h.ctx("push"))

    def test_timestamp_outside_run_rejected(self):
        self.assertRejected("provenance-timestamp", h.api_files(h.api_metadata(timestamp="2026-01-01T00:00:00Z")))

    def test_new_run_id_field_must_match(self):
        self.assertRejected("provenance-run-id", h.api_files(h.api_metadata(run_id=1)))


class RulesTest(unittest.TestCase):
    def test_escape_codes_only_allowed_in_tool_output(self):
        rules.check_content(b"\x1b[31mred\x1b[0m\n", "report.txt")
        with self.assertRaises(Rejected):
            rules.check_content(b'{"a": "\x1b"}', "report.json")

    def test_allowed_extensions(self):
        for name in ("a.json", "a.html", "a.txt", "d/a.log"):
            rules.check_relpath(name)
        for name in ("a.exe", "a.sh", "a.py", "a.zip", "a", "a.so"):
            with self.assertRaises(Rejected):
                rules.check_relpath(name)


if __name__ == "__main__":
    unittest.main()
