"""Minimal GitHub REST client (standard library only).

Artifact downloads answer with a 302 redirect to a short-lived blob-storage URL.
Redirects are never followed automatically: the client reads ``Location`` and
fetches it *without* the Authorization header, so the GitHub token is never
sent to the storage host.
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Iterator, Optional, Tuple

API_VERSION = "2022-11-28"
USER_AGENT = "armor-s3-publisher"
_RETRY_STATUSES = {429, 500, 502, 503, 504}
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class GitHubError(Exception):
    def __init__(self, message: str, status: Optional[int] = None) -> None:
        super().__init__(message)
        self.status = status


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


class GitHubClient:
    def __init__(
        self,
        token: str,
        api_url: str = "https://api.github.com",
        timeout: int = 60,
        max_retries: int = 4,
        sleep: Callable[[float], None] = time.sleep,
        require_https_redirect: bool = True,
    ) -> None:
        if not token:
            raise GitHubError("no GitHub token provided")
        self._token = token
        self._api = api_url.rstrip("/")
        self._timeout = timeout
        self._max_retries = max_retries
        self._sleep = sleep
        self._require_https_redirect = require_https_redirect
        self._opener = urllib.request.build_opener(_NoRedirect)

    # ------------------------------------------------------------------ basics
    def _headers(self, auth: bool) -> Dict[str, str]:
        headers = {"User-Agent": USER_AGENT}
        if auth:
            headers.update(
                {
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {self._token}",
                    "X-GitHub-Api-Version": API_VERSION,
                }
            )
        return headers

    def _backoff(self, attempt: int, headers: Any = None) -> None:
        delay = min(60.0, 2.0 ** attempt)
        if headers is not None:
            retry_after = headers.get("Retry-After")
            if retry_after and retry_after.isdigit():
                delay = min(120.0, float(retry_after))
        self._sleep(delay)

    def _open(self, url: str, auth: bool):
        """Open ``url`` with retries. Returns (status, headers, response-or-None)."""
        last_error = "unknown error"
        for attempt in range(self._max_retries + 1):
            request = urllib.request.Request(url, headers=self._headers(auth), method="GET")
            try:
                response = self._opener.open(request, timeout=self._timeout)
                return response.status, response.headers, response
            except urllib.error.HTTPError as exc:
                if exc.code in _REDIRECT_STATUSES:
                    return exc.code, exc.headers, None
                rate_limited = exc.code == 403 and (
                    exc.headers.get("X-RateLimit-Remaining") == "0" or exc.headers.get("Retry-After")
                )
                if (exc.code in _RETRY_STATUSES or rate_limited) and attempt < self._max_retries:
                    last_error = f"HTTP {exc.code}"
                    self._backoff(attempt, exc.headers)
                    continue
                raise GitHubError(f"HTTP {exc.code}", exc.code) from None
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
                last_error = type(exc).__name__
                if attempt < self._max_retries:
                    self._backoff(attempt)
                    continue
                raise GitHubError(f"network error: {last_error}") from None
        raise GitHubError(f"giving up after retries: {last_error}")

    # -------------------------------------------------------------------- JSON
    def get_json(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        if not path.startswith("/"):
            raise GitHubError("API path must start with '/'")
        url = self._api + urllib.parse.quote(path, safe="/:@-._~")
        if params:
            url += "?" + urllib.parse.urlencode(params)
        status, _headers, response = self._open(url, auth=True)
        if response is None or status != 200:
            raise GitHubError(f"unexpected HTTP {status}", status)
        with response:
            body = response.read(64 * 1024 * 1024 + 1)
        if len(body) > 64 * 1024 * 1024:
            raise GitHubError("API response too large")
        try:
            return json.loads(body.decode("utf-8"))
        except ValueError:
            raise GitHubError("API returned invalid JSON") from None

    def paginate(
        self,
        path: str,
        params: Dict[str, Any],
        key: Optional[str],
        max_pages: int = 20,
        stop: Optional[Callable[[list], bool]] = None,
    ) -> Iterator[dict]:
        """Yield items of a list endpoint page by page.

        ``key`` names the list inside the response object (``None`` when the
        endpoint returns a bare JSON array). ``stop(page_items)`` returning
        True ends pagination after that page.
        """
        for page in range(1, max_pages + 1):
            data = self.get_json(path, dict(params, page=page))
            if key is None:
                items = data if isinstance(data, list) else None
            else:
                items = data.get(key) if isinstance(data, dict) else None
            if not isinstance(items, list):
                raise GitHubError(f"list endpoint did not return '{key or 'a list'}'")
            for item in items:
                yield item
            if len(items) < int(params.get("per_page", 30)):
                return
            if stop is not None and stop(items):
                return

    # --------------------------------------------------------------- downloads
    def download_artifact_zip(self, repo: str, artifact_id: int, dest: str, max_bytes: int) -> Tuple[str, int]:
        """Download an artifact zip to ``dest``. Returns (sha256 hex, size).

        The bytes are treated as opaque: nothing here opens or parses the zip.
        """
        url = f"{self._api}/repos/{urllib.parse.quote(repo, safe='/')}/actions/artifacts/{int(artifact_id)}/zip"
        status, headers, response = self._open(url, auth=True)
        if response is not None:
            response.close()
        if status not in _REDIRECT_STATUSES:
            raise GitHubError(f"artifact download did not redirect (HTTP {status})", status)
        location = headers.get("Location", "")
        parsed = urllib.parse.urlparse(location)
        if not parsed.netloc or (self._require_https_redirect and parsed.scheme != "https"):
            raise GitHubError("artifact download redirected to an unexpected URL")
        return self._stream_to_file(location, dest, max_bytes)

    def _stream_to_file(self, url: str, dest: str, max_bytes: int) -> Tuple[str, int]:
        # _open() already retries connection-level failures; this loop only
        # restarts a download that broke off half way through.
        last_error = "blob download failed"
        for attempt in range(2):
            status, _headers, response = self._open(url, auth=False)
            if response is None or status != 200:
                raise GitHubError(f"blob download returned HTTP {status}", status)
            digest = hashlib.sha256()
            size = 0
            try:
                with response, open(dest, "wb") as handle:
                    while True:
                        chunk = response.read(1024 * 1024)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > max_bytes:
                            raise GitHubError("artifact larger than the allowed download size")
                        digest.update(chunk)
                        handle.write(chunk)
                return digest.hexdigest(), size
            except (OSError, urllib.error.URLError) as exc:
                last_error = f"download interrupted: {type(exc).__name__}"
                if attempt == 0:
                    self._backoff(attempt)
        raise GitHubError(last_error)
