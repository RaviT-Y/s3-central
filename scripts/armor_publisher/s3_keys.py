"""S3 key layout, built only from trusted run information.

Same layout as the old in-PR upload:

    <YYYY>/<MM>/<DD>/<HH>/<host>/<owner>/<repo>/<ref>/<run_id>/files/<relpath>

* date/hour: the workflow run's ``created_at`` (UTC), so a run always maps to
  the same prefix and re-uploads overwrite the same objects;
* ``<ref>``: ``<pr_number>/merge`` for pull_request runs (what GITHUB_REF_NAME
  was in the PR job), otherwise the run's branch name;
* nothing comes from the artifact except the allowlisted relative file path.
"""

from __future__ import annotations

import posixpath
import re
import urllib.parse
from typing import Any, Dict, Optional

from common import parse_github_time

_REPO_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
_REF_RE = re.compile(r"[A-Za-z0-9._/-]{1,200}")
_HOST_RE = re.compile(r"[A-Za-z0-9.-]{1,253}")


class KeyError_(ValueError):
    """Raised when a trusted value cannot be turned into a safe S3 key."""


def ref_segment(run: Dict[str, Any], pr_number: Optional[int]) -> str:
    if run["event"] == "pull_request":
        if not isinstance(pr_number, int) or isinstance(pr_number, bool) or pr_number <= 0:
            raise KeyError_("pull_request run without a verified PR number")
        return f"{pr_number}/merge"
    branch = run.get("head_branch") or ""
    if not _REF_RE.fullmatch(branch) or branch.startswith("/") or branch.endswith("/"):
        raise KeyError_("branch name cannot be used in an S3 key")
    if any(part in ("", ".", "..") for part in branch.split("/")):
        raise KeyError_("branch name cannot be used in an S3 key")
    return branch


def run_prefix(run: Dict[str, Any], server_url: str, pr_number: Optional[int]) -> str:
    repo = run["repo"]
    if not _REPO_RE.fullmatch(repo) or any(part in (".", "..") for part in repo.split("/")):
        raise KeyError_("repository name cannot be used in an S3 key")
    host = urllib.parse.urlparse(server_url).hostname or ""
    if not _HOST_RE.fullmatch(host):
        raise KeyError_("server host cannot be used in an S3 key")
    run_id = run["run_id"]
    if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id <= 0:
        raise KeyError_("invalid run id")
    created = parse_github_time(run["created_at"])
    prefix = "/".join(
        [created.strftime("%Y"), created.strftime("%m"), created.strftime("%d"), created.strftime("%H"),
         host, repo, ref_segment(run, pr_number), str(run_id)]
    )
    if posixpath.normpath(prefix) != prefix:
        raise KeyError_("S3 prefix is not normalised")
    return prefix


def object_key(prefix: str, relpath: str) -> str:
    key = f"{prefix}/{relpath}"
    if posixpath.normpath(key) != key or not key.startswith(prefix + "/"):
        raise KeyError_("object key escapes the run prefix")
    return key
