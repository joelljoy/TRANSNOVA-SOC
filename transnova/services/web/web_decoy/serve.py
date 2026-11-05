"""Production entrypoint: uvicorn with a header-completion deadline (security fix F1).

    python -m web_decoy.serve                      (container: 0.0.0.0:8080)
    WEB_DECOY_HOST=127.0.0.1 WEB_DECOY_PORT=8081 python -m web_decoy.serve   (local)

ALWAYS start the decoy this way, locally too. Plain `uvicorn web_decoy.app:app`
trusts X-Forwarded-For from 127.0.0.1 by default and rewrites the client IP
before the app sees it, so a faked header would be logged as the source IP
(PLAN P13).

Why not plain `uvicorn ...`: uvicorn has no deadline for receiving request headers.
Its keep-alive timer is cancelled on every received byte, so a client trickling
header bytes holds a connection (and a --limit-concurrency slot) forever. Enough
such clients make the decoy answer 503 to everyone, and because the app never
runs, nothing is recorded. `HeaderDeadlineH11Protocol` closes any connection whose
request headers are not complete within HEADER_TIMEOUT_S of the first wait,
however slowly the bytes arrive. The request BODY deadline lives in the telemetry
middleware (Settings.body_timeout_s).
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import tempfile

import h11
import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol

HEADER_TIMEOUT_S = float(os.environ.get("HEADER_TIMEOUT_S", "10"))
# Max simultaneous connections from ONE source address (F6). With 200 total slots, one
# source can hold at most this many; extra connections are closed immediately.
MAX_CONN_PER_IP = int(os.environ.get("MAX_CONN_PER_IP", "20"))


def tls_enabled() -> bool:
    return os.environ.get("WEB_DECOY_TLS", "0").strip().lower() in ("1", "true", "yes", "on")


def make_ephemeral_certificate(directory: str | None = None) -> tuple[str, str]:
    """Generate a fresh self-signed TLS certificate at every start (OWASP 2021 A02 / 2025 A04).

    The private key exists only in a new 0700 temp directory (tmpfs in the container), is
    created 0600 with O_EXCL, and is never stored in the repository or the image."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TransNova Logistics"),
                      x509.NameAttribute(NameOID.COMMON_NAME, "partners.transnova-logistics.example")])
    now = datetime.datetime.now(datetime.timezone.utc)
    san = x509.SubjectAlternativeName([
        x509.DNSName("partners.transnova-logistics.example"), x509.DNSName("localhost"),
        x509.DNSName("web-decoy"), x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.IPAddress(ipaddress.ip_address("172.28.0.10")),
    ])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(san, critical=False).sign(key, hashes.SHA256()))

    directory = directory or tempfile.mkdtemp(prefix="tls-")   # mkdtemp creates it 0700
    key_path = os.path.join(directory, "key.pem")
    cert_path = os.path.join(directory, "cert.pem")
    key_bytes = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption())
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key_bytes)
    fd = os.open(cert_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


class HeaderDeadlineH11Protocol(H11Protocol):
    _header_deadline = None
    _counted_ip: str | None = None
    _conns_per_ip: dict = {}          # shared across connections (single event loop)
    rejected_connections = 0           # visible to tests/diagnostics

    def connection_made(self, transport) -> None:  # type: ignore[override]
        super().connection_made(transport)
        peer = transport.get_extra_info("peername")
        ip = peer[0] if peer else None
        counts = HeaderDeadlineH11Protocol._conns_per_ip
        if ip is not None and counts.get(ip, 0) >= MAX_CONN_PER_IP:
            HeaderDeadlineH11Protocol.rejected_connections += 1
            transport.close()          # this source already holds its share of the slots
            return
        if ip is not None:
            counts[ip] = counts.get(ip, 0) + 1
            self._counted_ip = ip
        self._arm_header_deadline()

    def data_received(self, data: bytes) -> None:
        super().data_received(data)
        if self.conn.their_state is h11.IDLE:
            self._arm_header_deadline()      # still waiting for (the next request's) headers
        else:
            self._cancel_header_deadline()   # headers complete; body deadline is the app's job

    def connection_lost(self, exc) -> None:
        self._cancel_header_deadline()
        if self._counted_ip is not None:
            counts = HeaderDeadlineH11Protocol._conns_per_ip
            left = counts.get(self._counted_ip, 1) - 1
            if left > 0:
                counts[self._counted_ip] = left
            else:
                counts.pop(self._counted_ip, None)
            self._counted_ip = None
        super().connection_lost(exc)

    def _arm_header_deadline(self) -> None:
        if self._header_deadline is None:     # absolute: NOT reset by further bytes
            self._header_deadline = self.loop.call_later(HEADER_TIMEOUT_S, self._header_timeout)

    def _cancel_header_deadline(self) -> None:
        if self._header_deadline is not None:
            self._header_deadline.cancel()
            self._header_deadline = None

    def _header_timeout(self) -> None:
        self._header_deadline = None
        if self.conn.their_state is h11.IDLE and not self.transport.is_closing():
            self.transport.close()


def build_config(host: str | None = None, port: int | None = None, tls: bool | None = None,
                 **overrides) -> uvicorn.Config:
    """The one hardened server configuration (also used by the tests).

    TLS is on when WEB_DECOY_TLS=1 (set in the Dockerfile, so the deployed container always
    serves HTTPS). Local development runs default to plain HTTP on 127.0.0.1."""
    options = dict(
        app="web_decoy.app:create_app",
        factory=True,               # settings read from env at start, not at import
        host=host or os.environ.get("WEB_DECOY_HOST", "0.0.0.0"),
        port=int(os.environ.get("WEB_DECOY_PORT", "8080")) if port is None else port,
        http=HeaderDeadlineH11Protocol,
        proxy_headers=False,        # never trust X-Forwarded-For (PLAN P2, P13)
        server_header=False,        # app sets "Server: nginx"
        access_log=False,           # uvicorn's log would hold unredacted query strings
        limit_concurrency=200,
        timeout_keep_alive=5,
    )
    if tls_enabled() if tls is None else tls:
        cert_path, key_path = make_ephemeral_certificate()
        options.update(ssl_certfile=cert_path, ssl_keyfile=key_path)
    options.update(overrides)
    return uvicorn.Config(**options)


def main() -> None:
    uvicorn.Server(build_config()).run()


if __name__ == "__main__":
    main()
