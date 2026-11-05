"""Safe, signature- and behaviour-based classification (PLAN.md §5).

Nothing here evaluates, executes, opens or fetches request input. Every
detection describes an ATTEMPT that was observed; none claims success.
"""

from __future__ import annotations

from ..anon import load_anon_intel  # noqa: F401  (re-exported for app.py)
from ..config import Settings
from .behavior import BehaviorEngine
from .mappings import make
from .signatures import detect_signatures


def anonymizer_detector(intel):
    """W-ANON-01 (Tor exit) / W-ANON-02 (VPN or hosting range). Pure in-memory lookup."""
    def detect(ctx) -> list:
        verdict = intel.classify(ctx.source_ip) if intel is not None else None
        if verdict is None:
            return []
        where = "list fetched " + (verdict.list_date or "unknown date")
        if verdict.source == "demo":
            where = "demo list (rehearsal entry, not a real Tor/VPN lookup)"
        if verdict.category == "tor":
            return [make("W-ANON-01", "source_ip", f"source address is a Tor exit node ({where})")]
        return [make("W-ANON-02", "source_ip",
                     f"source address is in a known {verdict.category} range ({where})")]
    return detect


def adaptive_detector(ctx) -> list:
    """W-ADAPT-01: the route marks a taken bait; the detector only labels it."""
    if (ctx.route or {}).get("adaptive", {}).get("stage") == "taken":
        return [make("W-ADAPT-01", "path", "adaptive bait opened: the link was shown only to this source, after it "
                                           "showed attack intent; ordinary visitors never see it")]
    return []


def default_detectors(settings: Settings, intel=None) -> list:
    engine = BehaviorEngine()
    return [detect_signatures, engine.detect, anonymizer_detector(intel), adaptive_detector]
