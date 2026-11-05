"""Detailed health for the lab/integrator only. Everyone else gets the normal site 404."""

from __future__ import annotations

import time

from fastapi import APIRouter, Request

from .. import __version__
from ..config import ip_in
from ..errors import nginx_error

router = APIRouter()


@router.get("/health")
def health(request: Request):
    settings = request.app.state.settings
    host = request.client.host if request.client else None
    if not ip_in(host, settings.health_allowed):
        return nginx_error(404)  # byte-identical to an unknown path; still emitted as a probe
    request.state.telemetry = {"skip": True}  # lab/integrator polling is not attacker activity
    stats = request.app.state.emitter.stats()
    return {
        "status": stats["status"],
        "sensor_id": settings.sensor_id,
        "service": "web",
        "version": __version__,
        "uptime_s": int(time.monotonic() - request.app.state.started_at),
        **{k: v for k, v in stats.items() if k != "status"},
        "telemetry_errors": request.app.state.telemetry_errors,
        "active_sessions": len(request.app.state.sessions),
    }
