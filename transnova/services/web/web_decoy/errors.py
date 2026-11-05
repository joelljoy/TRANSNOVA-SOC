"""nginx-style error pages, so the decoy never leaks FastAPI's JSON error format."""

from __future__ import annotations

from fastapi.responses import HTMLResponse

SECURITY_HEADERS = {
    "Server": "nginx",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'none'; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
}

HSTS_VALUE = "max-age=31536000"  # sent only when serving HTTPS

_REASONS = {
    400: "Bad Request",
    401: "Authorization Required",
    403: "Forbidden",
    404: "Not Found",
    405: "Not Allowed",
    408: "Request Time-out",
    413: "Request Entity Too Large",
    429: "Too Many Requests",
    500: "Internal Server Error",
}


def nginx_error_body(status: int) -> str:
    reason = _REASONS.get(status, "Error")
    return (
        "<html>\r\n"
        f"<head><title>{status} {reason}</title></head>\r\n"
        "<body>\r\n"
        f"<center><h1>{status} {reason}</h1></center>\r\n"
        "<hr><center>nginx</center>\r\n"
        "</body>\r\n"
        "</html>\r\n"
    )


def nginx_error(status: int, headers: dict[str, str] | None = None) -> HTMLResponse:
    return HTMLResponse(nginx_error_body(status), status_code=status, headers=headers)
