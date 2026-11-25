"""Bounded HTTP requests for remote providers; credentials never enter errors."""

from __future__ import annotations

import http.client
import json
import queue
import threading
import time
from decimal import Decimal
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from ..errors import CardanoError

MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class ProviderHttpError(CardanoError):
    """HTTP failure retaining only the status, never the response or credentials."""

    def __init__(self, status: int):
        self.status = status
        super().__init__(f"Provider HTTP status {status}")


class ProviderTimeoutError(CardanoError):
    """The whole-request deadline expired, including DNS and response reading."""


def milliseconds(value: int) -> int:
    """Validate a configured request timeout or polling interval."""
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 60000:
        raise ValueError("Timeout and polling interval must be 1 through 60000 milliseconds")
    return value


def bearer(token: str | None) -> dict[str, str]:
    """Validate an optional opaque bearer credential."""
    if token is None:
        return {}
    if not isinstance(token, str) or not 1 <= len(token) <= 4096 or any(not 33 <= ord(char) <= 126 for char in token):
        raise ValueError("Invalid provider credential")
    return {"Authorization": f"Bearer {token}"}


def _constant(_value):
    raise ValueError("Non-finite JSON number")


def decode_json(data: bytes):
    """Retain integer quantities and exact decimal fractions."""
    try:
        return json.loads(data, parse_float=Decimal, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise CardanoError("Invalid provider JSON response") from None


class Http:
    """One-shot HTTP transport with a bounded number of in-flight workers.

    DNS cannot be interrupted by the standard library. A timed-out worker retains
    its own connection until cleanup, with at most four workers per client. The
    caller still observes a whole-request deadline. Submissions are never retried.
    """

    def __init__(self, base_url: str, token: str | None = None, timeout_ms: int = 30000):
        try:
            parts = urlsplit(base_url)
            if (parts.scheme not in ("http", "https") or not parts.hostname or parts.username is not None
                    or parts.password is not None or parts.fragment):
                raise ValueError
            if any(ord(char) < 33 for char in base_url):
                raise ValueError
            _ = parts.port
        except (ValueError, TypeError):
            raise ValueError("Provider endpoint must be an absolute HTTP(S) URL without user information or a fragment") from None
        self._base = parts
        self._headers = {"Accept": "application/json", **bearer(token)}
        self._timeout = milliseconds(timeout_ms) / 1000
        self._workers = threading.BoundedSemaphore(4)

    def request(self, path=(), query=None, body=None, timeout_ms=None):
        """Return status and decoded JSON; None query values are bare flags."""
        query = query or {}
        existing = [(key, value) for key, value in parse_qsl(self._base.query, keep_blank_values=True) if key not in query]
        encoded = [urlencode(existing)] if existing else []
        encoded.extend(quote(key, safe="") if value is None else urlencode({key: value}) for key, value in query.items())
        target = self._base.path
        if path:
            target = target.rstrip("/") + "/" + "/".join(quote(item, safe="") for item in path)
        target = urlunsplit(("", "", target or "/", "&".join(encoded), ""))
        payload = None if body is None else json.dumps(body, allow_nan=False, separators=(",", ":")).encode()
        budget = self._timeout if timeout_ms is None else min(self._timeout, max(0, timeout_ms) / 1000)
        deadline = time.monotonic() + budget
        # Ownership transfers to the worker, which releases this slot after cleanup.
        if budget <= 0 or not self._workers.acquire(timeout=budget):  # pylint: disable=consider-using-with
            raise ProviderTimeoutError("Provider request timed out")
        result = queue.Queue(maxsize=1)
        threading.Thread(target=self._run, args=(target, payload, deadline, result), daemon=True).start()
        try:
            status, value = result.get(timeout=max(0, deadline - time.monotonic()))
        except queue.Empty:
            raise ProviderTimeoutError("Provider request timed out") from None
        if status == "error":
            raise value
        return status, decode_json(value)

    def json(self, path=(), query=None, body=None, timeout_ms=None):
        """Return the JSON body of a successful request."""
        return self.request(path, query, body, timeout_ms)[1]

    def _run(self, target, payload, deadline, result):
        connection_type = http.client.HTTPSConnection if self._base.scheme == "https" else http.client.HTTPConnection
        connection = connection_type(self._base.hostname, self._base.port, timeout=max(0.001, deadline - time.monotonic()))
        try:
            connection.connect()
            self._remaining(connection, deadline)
            headers = dict(self._headers)
            if payload is not None:
                headers["Content-Type"] = "application/json"
            connection.request("GET" if payload is None else "POST", target, body=payload, headers=headers)
            self._remaining(connection, deadline)
            response = connection.getresponse()
            if not 200 <= response.status < 300:
                raise ProviderHttpError(response.status)
            chunks = []
            length = 0
            while True:
                self._remaining(connection, deadline)
                chunk = response.read1(min(65536, MAX_RESPONSE_BYTES + 1 - length))
                if not chunk:
                    break
                length += len(chunk)
                if length > MAX_RESPONSE_BYTES:
                    raise CardanoError("Provider response exceeds size limit")
                chunks.append(chunk)
            result.put((response.status, b"".join(chunks)))
        except (TimeoutError, ProviderTimeoutError):
            result.put(("error", ProviderTimeoutError("Provider request timed out")))
        except CardanoError as error:
            result.put(("error", error))
        except (OSError, http.client.HTTPException, ValueError):
            result.put(("error", CardanoError("Provider transport failed")))
        finally:
            connection.close()
            self._workers.release()

    @staticmethod
    def _remaining(connection, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProviderTimeoutError("Provider request timed out")
        if connection.sock is not None:
            connection.sock.settimeout(remaining)


def confirm(tx_id, timeout_ms, poll_interval_ms, check):
    """Poll within one monotonic deadline; transport errors remain visible."""
    timeout_ms = 20000 if timeout_ms is None else timeout_ms
    if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or timeout_ms < 0:
        raise ValueError("Confirmation timeout must be a nonnegative integer")
    deadline = time.monotonic() + timeout_ms / 1000
    while (remaining := deadline - time.monotonic()) > 0:
        try:
            if check(tx_id, remaining * 1000):
                return True
        except ProviderTimeoutError:
            if time.monotonic() < deadline:
                raise
            return False
        time.sleep(max(0, min(poll_interval_ms / 1000, deadline - time.monotonic())))
    return False
