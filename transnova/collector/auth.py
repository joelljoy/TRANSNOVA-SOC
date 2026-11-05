"""Bearer tokens read from files. Nothing here logs or returns a token, a path or an exception text."""

from __future__ import annotations

import hmac
import re

MAX_TOKEN_BYTES = 4096
_TOKEN = re.compile(rb"[\x21-\x2b\x2d-\x7e]+")  # printable ASCII with no space or comma


def load_token(path: str | None) -> bytes | None:
    """The token in that file, or None if it cannot be used for any reason. Read on every call, so
    a changed token takes effect without a restart, and a broken file can never stop the collector."""
    if not path:
        return None
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_TOKEN_BYTES + 3)
    except (OSError, ValueError):
        return None
    token = raw.strip()
    return token if len(token) <= MAX_TOKEN_BYTES and _TOKEN.fullmatch(token) else None


def bearer(headers: list[tuple[bytes, bytes]]) -> bytes | None:
    """The token from exactly one well-formed `Authorization: Bearer <token>` header, else None.

    Raw headers are counted, so which of two values a library would return cannot matter.
    """
    values = [value for name, value in headers if name == b"authorization"]
    if len(values) != 1 or not values[0].startswith(b"Bearer "):
        return None
    token = values[0][len(b"Bearer "):]
    return token if len(token) <= MAX_TOKEN_BYTES and _TOKEN.fullmatch(token) else None


def same(given: bytes | None, expected: bytes | None) -> bool:
    return given is not None and expected is not None and hmac.compare_digest(given, expected)
