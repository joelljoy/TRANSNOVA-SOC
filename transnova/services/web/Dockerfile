# syntax=docker/dockerfile:1
# Web honeypot decoy. Python 3.12, pinned by digest (verified 2026-10-31).
FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    EVENT_LOG_PATH=/data/web-events.jsonl \
    SPOOL_PATH=/data/web-spool.jsonl \
    WEB_DECOY_TLS=1

WORKDIR /app
COPY requirements.txt .
# Optional `pip_ca` secret: only for build environments behind a TLS-intercepting proxy.
# It is mounted for this step only and never stored in the image. Normal builds skip it.
RUN --mount=type=secret,id=pip_ca,required=false \
    if [ -f /run/secrets/pip_ca ]; then export PIP_CERT=/run/secrets/pip_ca; fi \
 && pip install --require-hashes --no-deps -r requirements.txt \
 && groupadd --system --gid 10001 decoy \
 && useradd --system --uid 10001 --gid decoy --no-create-home --shell /usr/sbin/nologin decoy \
 && mkdir -p /data && chown decoy:decoy /data

COPY web_decoy ./web_decoy
# Shared Tor/VPN/hosting lookup + list snapshot (compose passes services/anonintel as the
# `anonintel` build context). Read-only data; the decoy never downloads lists itself.
COPY --from=anonintel anonintel.py ./anonintel/anonintel.py
COPY --from=anonintel data ./anonintel/data

USER 10001:10001
EXPOSE 8080

# Supply chain (OWASP 2021 A06/A08, 2025 A03/A08): every package, including transitive ones, is
# pinned by version AND sha256 hash in requirements.txt (generated from requirements.in);
# --require-hashes makes pip refuse anything unpinned or altered. Base image pinned by digest.
#
# TLS (OWASP 2021 A02 / 2025 A04): WEB_DECOY_TLS=1 -> a fresh self-signed certificate is generated
# in tmpfs at every start; the Secure cookie flag and HSTS are enabled.
#
# web_decoy.serve runs uvicorn with: a header-completion deadline (security fix F1),
# no proxy-header trust (PLAN P2), no server header (app sets "Server: nginx"), no access
# log (it would hold unredacted query strings), limit-concurrency 200, keep-alive 5 s.
CMD ["python", "-m", "web_decoy.serve"]
