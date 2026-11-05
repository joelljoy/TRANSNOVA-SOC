"""Loads the shared anonymizer lists (services/anonintel). Kept outside detection/ because it reads files.

The decoy never downloads anything: lists are refreshed on the host with
scripts/refresh_anon_lists.py and re-read here when they change.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SHARED = Path(__file__).resolve().parents[2] / "anonintel"   # services/anonintel in the repo
_BUNDLED = Path(__file__).resolve().parents[1] / "anonintel"  # /app/anonintel in the image


_CACHE: dict[str, object] = {}


def load_anon_intel(settings):
    """Return an AnonIntel, or None if the module is missing (labelling is then off, nothing breaks).

    One instance per data folder per process: the lists hold ~57k ranges, and it re-reads
    changed files by itself, so building it again per app would only waste time."""
    for candidate in (_BUNDLED, _SHARED):
        if (candidate / "anonintel.py").is_file() and str(candidate) not in sys.path:
            sys.path.append(str(candidate))
    try:
        from anonintel import AnonIntel
    except ImportError:
        return None
    key = settings.anon_data_dir or ""
    if key in _CACHE:
        return _CACHE[key]
    try:
        _CACHE[key] = AnonIntel(settings.anon_data_dir or None)
        return _CACHE[key]
    except Exception:  # a broken list folder must never stop the decoy
        return None
