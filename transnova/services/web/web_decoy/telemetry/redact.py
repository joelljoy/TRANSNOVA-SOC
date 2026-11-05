"""Redaction and bounding for everything that leaves the request (PLAN.md §4.1).

Order for every value: strip control chars -> cap input at 2 KiB (bounds regex
work, ReDoS) -> redact secret patterns -> truncate to the output limit. Redaction
happens BEFORE truncation so a secret cannot survive by straddling the cut.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterable

REDACTED = "[REDACTED]"
MAX_INPUT = 2048
MAX_VALUE = 512
MAX_KEY = 64
MAX_KEYS = 50
MAX_EVIDENCE_BYTES = 4096

HEADER_ALLOWLIST = ("host", "user-agent", "accept", "content-type", "content-length", "referer")

_CONTROL = re.compile(r"[\x00-\x1f\x7f  ]")

SENSITIVE_KEY = re.compile(
    r"pass|pwd|secret|token|api[_-]?key|auth|session|cookie|jwt|bearer|otp|credential|private[_-]?key",
    re.IGNORECASE,
)

# All patterns are linear: no nested quantifiers. Input is capped at MAX_INPUT first.
# No leading \b: a secret glued to other text ("aaaeyJ...", "mypassword=") has no word
# boundary and would slip through. Over-redaction is the safe failure mode.
_VALUE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----|$)",
                re.DOTALL), REDACTED),
    (re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"), REDACTED),
    (re.compile(r"(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE), REDACTED),
    (re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"), REDACTED),
    (re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,})"), REDACTED),
    (re.compile(
        r"(pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|auth|session(?:id)?|jwt)"
        r"(\s{0,3}[=:]\s{0,3})([^\s&;,\"']+)",
        re.IGNORECASE), r"\1\2" + REDACTED),
)

_MARKUP = re.compile(r"<\s{0,3}[a-z/!?]|javascript\s{0,3}:|\bon[a-z]{2,20}\s{0,3}=", re.IGNORECASE)


def clean(s: str) -> str:
    return _CONTROL.sub("", s)


def truncate(s: str, limit: int) -> str:
    if len(s) <= limit:
        return s
    return s[:limit] + f"…[truncated {len(s) - limit}]"


def redact_text(s: str) -> str:
    """Apply secret patterns. Caller must have capped the input length."""
    for pattern, repl in _VALUE_PATTERNS:
        s = pattern.sub(repl, s)
    return s


def safe_value(value: Any, limit: int = MAX_VALUE) -> str:
    s = clean(str(value))[:MAX_INPUT]
    return truncate(redact_text(s), limit)


def safe_optional(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    out = safe_value(value, limit)
    return out or None


def is_sensitive_key(key: str) -> bool:
    return bool(SENSITIVE_KEY.search(key))


def contains_markup(value: str) -> bool:
    return bool(_MARKUP.search(value[:MAX_INPUT]))


def redact_pairs(pairs: Iterable[tuple[str, Any]]) -> tuple[dict[str, Any], bool]:
    """Key/value pairs -> bounded, redacted dict. Returns (dict, markup_seen)."""
    out: dict[str, Any] = {}
    markup = False
    dropped = 0
    for raw_key, raw_val in pairs:
        key = safe_value(raw_key, MAX_KEY) or "_empty"
        if key not in out and len(out) >= MAX_KEYS:
            dropped += 1
            continue
        if is_sensitive_key(str(raw_key)):
            val: Any = REDACTED
        else:
            val = safe_value(raw_val)
            markup = markup or contains_markup(val)
        if key in out:  # repeated parameter -> list
            prev = out[key]
            out[key] = (prev if isinstance(prev, list) else [prev])[:9] + [val]
        else:
            out[key] = val
    if dropped:
        out["_dropped_keys"] = dropped
    return out, markup


def flatten_json(obj: Any, prefix: str = "", depth: int = 0) -> list[tuple[str, Any]]:
    """Flatten parsed JSON into (dotted_key, scalar) pairs, bounded in depth and count."""
    pairs: list[tuple[str, Any]] = []
    if depth > 3:
        return [(prefix or "_root", "[nested]")]
    if isinstance(obj, dict):
        for k, v in list(obj.items())[:MAX_KEYS]:
            key = f"{prefix}.{k}" if prefix else str(k)
            pairs.extend(flatten_json(v, key, depth + 1))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:10]):
            pairs.extend(flatten_json(v, f"{prefix}[{i}]", depth + 1))
    else:
        pairs.append((prefix or "_root", obj))
    return pairs[: MAX_KEYS * 2]


def filter_headers(raw_headers: Iterable[tuple[bytes, bytes]]) -> dict[str, str]:
    """Allowlist only. Authorization, Cookie, X-Api-Key etc. are never copied."""
    out: dict[str, str] = {}
    for k, v in raw_headers:
        name = k.decode("latin-1").lower()
        if name in HEADER_ALLOWLIST and name not in out:
            out[name] = safe_value(v.decode("latin-1"))
    return out


def _size(obj: Any) -> int:
    return len(json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode())


def bound_evidence(evidence: dict[str, Any], limit: int = MAX_EVIDENCE_BYTES) -> dict[str, Any]:
    """Enforce the total evidence budget: shrink values, then drop bulky sections."""
    if _size(evidence) <= limit:
        return evidence
    shrunk: dict[str, Any] = {}
    for section, content in evidence.items():
        if isinstance(content, dict) and section in ("query", "form", "json", "headers"):
            shrunk[section] = {
                k: (truncate(v, 96) if isinstance(v, str) else v) for k, v in content.items()
            }
        else:
            shrunk[section] = content
    shrunk["_truncated"] = True
    for section in ("json", "form", "query", "headers"):
        if _size(shrunk) <= limit:
            break
        if section in shrunk:
            shrunk[section] = {"_dropped": "evidence budget exceeded"}
    return shrunk
