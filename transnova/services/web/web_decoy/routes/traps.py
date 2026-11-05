"""Bait routes: backup/config, fake downloads, upload. Nothing here touches the filesystem."""

from __future__ import annotations

import hashlib
import re

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from starlette.datastructures import UploadFile as StarletteUploadFile

from .. import fixtures
from ..adaptive import BAIT_BODY, BAIT_PATH
from ..deps import current_session, source_ip, templates
from ..errors import nginx_error
from ..telemetry import redact

router = APIRouter()


@router.get("/backup")
@router.get("/backup/")
@router.get("/config")
def forbidden():
    return nginx_error(403)


@router.get("/backup/{name}")
def backup_file(request: Request, name: str):
    """The adaptive bait. It exists only for a source it was revealed to; everyone else gets the same
    404 as any other /backup/ guess, so the file can't be found by brute force and doesn't tip anyone off."""
    adaptive = getattr(request.app.state, "adaptive", None)
    if f"/backup/{name}" != BAIT_PATH or adaptive is None or not adaptive.was_revealed(source_ip(request)):
        return nginx_error(404)
    request.state.telemetry = {**(getattr(request.state, "telemetry", None) or {}),
                               "adaptive": {"stage": "taken", "bait": BAIT_PATH}}
    return Response(BAIT_BODY, media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/download")
def download(file: str = ""):
    # Exact dict lookup only. Traversal strings simply miss and return 404.
    entry = fixtures.FAKE_FILES.get(file)
    if entry is None:
        return nginx_error(404)
    media_type, body = entry  # `file` is now known to be one of our own fixed keys
    return Response(
        body,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{file}"'},
    )


@router.get("/upload")
def upload_page(request: Request):
    return templates.TemplateResponse(request, "upload.html", {"session": current_session(request)})


# Magic-byte signatures -> label. Content is classified, never executed or stored.
_MAGIC = (
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF8", "image/gif"),
    (b"PK\x03\x04", "application/zip"),
    (b"\x7fELF", "application/x-elf"),
    (b"MZ", "application/x-msdownload"),
    (b"#!", "text/x-script"),
    (b"<?php", "application/x-php"),
    (b"<%", "text/x-server-page"),
)


# Server-side script markers searched across the WHOLE upload (security fix F3), so a
# real image header followed by a webshell (GIF/JPEG polyglot) is still flagged.
# Markers are long enough that random binary data practically never matches.
_SCRIPT_MARKERS = (
    ("php", re.compile(rb"<\?php[\s(]|<\?=\s{0,5}\$|<script\s{1,5}language\s{0,5}=\s{0,5}[\"']?php", re.I)),
    ("jsp", re.compile(rb"<%@\s{0,5}page\b|<%\s{0,5}(?:out|request|response|runtime)\.", re.I)),
    ("asp", re.compile(rb"<%@\s{0,5}language\s{0,5}=|<%\s{0,5}eval\s{0,5}\(", re.I)),
)
_MARKER_OVERLAP = 64  # bytes carried between chunks so a marker split across chunks is seen


def _sniff(head: bytes) -> str:
    stripped = head.lstrip()
    for sig, label in _MAGIC:
        if head.startswith(sig) or stripped.startswith(sig):
            return label
    return "application/octet-stream"


def _safe_filename(raw: str | None) -> str | None:
    if not raw:
        return None
    base = raw.replace("\\", "/").rsplit("/", 1)[-1]  # basename for "/" and "\\" style paths
    return redact.safe_value(base, 255) or None


@router.post("/upload")
async def upload(request: Request):
    """Parse one file, record metadata (name, size, sha256, sniffed type), discard content.

    The telemetry middleware has already capped the whole body at
    max_upload_bytes + multipart overhead, so the part stays in memory (Starlette
    spools to disk only above 1 MiB). Nothing is stored, served or executed."""
    cap = request.app.state.settings.max_upload_bytes
    form = await request.form(max_files=1, max_fields=5, max_part_size=cap)
    part = next((v for v in form.values() if isinstance(v, StarletteUploadFile)), None)
    if part is None:
        request.state.telemetry = {"action": "upload_attempt"}
        return JSONResponse({"error": "no file"}, status_code=400)

    digest = hashlib.sha256()
    size = 0
    head = b""
    tail = b""
    markers: set[str] = set()
    too_big = False
    while chunk := await part.read(65536):
        if not head:
            head = chunk[:16]
        size += len(chunk)
        if size > cap:
            too_big = True
            break
        digest.update(chunk)
        window = tail + chunk
        for label, pattern in _SCRIPT_MARKERS:
            if label not in markers and pattern.search(window):
                markers.add(label)
        tail = chunk[-_MARKER_OVERLAP:]
    await part.close()  # content discarded here

    file_name = _safe_filename(part.filename)
    meta = {
        "file_name": file_name,
        "declared_type": redact.safe_value(part.content_type or "", 100) or None,
        "sniffed_type": _sniff(head),
        "size_bytes": size,
        "sha256": None if too_big else digest.hexdigest(),
        "script_markers": sorted(markers),
        "stored": False,
    }
    request.state.telemetry = {"upload": meta, "file_name": file_name,
                               "outcome": "blocked" if too_big else "observed"}
    if too_big:
        return nginx_error(413)
    return JSONResponse({"status": "received", "message": "File queued for review."})
