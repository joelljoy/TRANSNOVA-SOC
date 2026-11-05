"""Canonicalize attacker input before matching (PLAN.md §5.1)."""

from __future__ import annotations

import unicodedata
from urllib.parse import unquote_plus

MAX_RAW = 8192      # never decode more than this
MAX_MATCH = 2048    # regexes only ever see this much


def normalize(value: str) -> tuple[str, bool]:
    """Return (canonical text, had_nul_byte).

    URL-decode up to twice (catches %252e%252e double encoding), NFKC (folds
    full-width tricks like ．．／), lowercase, strip NUL, then cap length so
    every regex runs on bounded input.
    """
    s = str(value)[:MAX_RAW]
    for _ in range(2):
        decoded = unquote_plus(s)
        if decoded == s:
            break
        s = decoded
    s = unicodedata.normalize("NFKC", s).lower()
    had_nul = "\x00" in s
    return s.replace("\x00", "")[:MAX_MATCH], had_nul
