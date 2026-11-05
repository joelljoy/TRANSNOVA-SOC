# OWASP Top 10 — Web Decoy (2021 and 2025 editions)

**Goal agreed with the owner:** *the decoy itself cannot be exploited.* Attackers are expected to
**try** every OWASP category, because that's the point of a honeypot. Every attempt must be recorded, and none
may succeed in reading, changing or reaching anything real.

**No application is "immune".** The defensible claim is narrower: each category has a specific
protection, and for each one there's a test that fails if that protection is removed. All tests listed are in
`services/web/tests/`. Status as of version 0.7.0 (2026-10-31): `371 passed` on Python 3.12, both locally and inside the image.

Two items are **deliberate honeypot bait**, not weaknesses. They're marked **By design** below, so a reviewer
doesn't mistake them for oversights.

---

## 2021 edition

| # | Category | How the decoy is protected | Proven by | Residual risk |
|---|---|---|---|---|
| **A01** | Broken Access Control | Portal pages and API need a server-side session (256-bit random token, deleted on logout). `/download` is a dictionary lookup of 2 fake files, so no path from the request ever reaches the filesystem. `/health` details are only served to `127.0.0.1`. **By design:** `/api/v1/users/{id}` and `/portal/shipments/{id}` let a logged-in user read *other* fake records. That's IDOR bait with synthetic data, detected as `W-IDOR-01` | `test_auth.py` (forged/replayed cookies), `test_routes.py::test_download_traversal_never_reads_files`, `test_routes.py::test_health_*`, `test_detection_p1.py::test_idor_*` | None for real data (none exists) |
| **A02** | Cryptographic Failures | **Container serves HTTPS only** (TLS 1.2+, TLS 1.3 negotiated). An EC P-256 self-signed certificate is generated **at every start**, with the key written `0600` into a `0700` tmpfs folder and never stored in the repo or image. `Secure` cookie flag and HSTS (`max-age=31536000`) whenever TLS is on. No real passwords exist; typed passwords are never stored (redacted) | `test_owasp.py::test_real_server_serves_tls_and_refuses_plain_http`, `::test_old_tls_versions_refused`, `::test_certificate_is_fresh_and_key_is_private`, `::test_no_private_key_or_certificate_committed`, `::test_cookie_secure_and_hsts_when_tls`; `test_redaction.py` | Self-signed (no CA in an isolated lab): clients skip verification for this one target. Local dev runs are plain HTTP, but bound to 127.0.0.1 only |
| **A03** | Injection | No database, no shell, no `eval`/`exec`/`subprocess`/`pickle` anywhere (enforced by AST scan). Login is a constant-time comparison with one fixed fake credential, so SQL syntax is just a wrong password. Jinja2 auto-escaping plus a CSP with `script-src 'none'` make XSS render as text. Log lines are JSON-encoded with control characters stripped (no log injection) | `test_safety.py::test_no_code_execution_primitives`, `::test_templates_never_disable_escaping`, `test_routes.py::test_search_reflection_is_escaped`, `test_auth.py` (SQLi login fails), `test_redaction.py::test_control_chars_cannot_forge_log_lines` | — |
| **A04** | Insecure Design | Written threat model and plan (`PLAN.md`), with 13 design problems (P1–P13) found and fixed. Every request has hard limits: 64 KiB body, 960 KiB upload, 15 s body and 10 s header deadlines, 200 connections. Isolated container. Detectors see raw input but can only emit sanitized fields | `test_security_fixes.py`, `test_telemetry.py`, `test_redos.py` | — |
| **A05** | Security Misconfiguration | Framework pages (`/docs`, `/redoc`, `/openapi.json`) disabled. Every error is a plain nginx page with no stack trace. Security headers (CSP, `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`). Proxy headers not trusted. Access log off (it would hold unredacted query strings). Container: non-root uid 10001, read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, memory and process limits, internal network with host access inhibited | `test_routes.py::test_framework_docs_disabled`, `::test_security_headers_present`, `test_telemetry.py::test_unhandled_exception_is_nginx_500_and_recorded`, `test_safety.py::test_default_compose_is_isolated`, `scripts/isolation_check.py` (ALL PASS, including on the owner's Windows machine) | — |
| **A06** | Vulnerable and Outdated Components | All 23 runtime packages (29 with test tools), **including indirect ones**, pinned by version. Scanned with `pip-audit`: **No known vulnerabilities found** (2026-10-31). Base image pinned by digest | `pip-audit -r requirements.txt --require-hashes` (README), `test_owasp.py::test_every_dependency_is_version_and_hash_pinned` | New CVEs appear over time: re-run `pip-audit` before every demo or release. The scan used PyPI advisory data; OSV was unreachable from the build sandbox |
| **A07** | Identification and Authentication Failures | Constant-time credential check. The same generic error for a wrong user or a wrong password (no username enumeration). A new random session on every login (no fixation). Logout deletes the session server-side. HttpOnly + SameSite=Lax (+ Secure under TLS). **By design: no lockout or rate limit.** The decoy *wants* to record guessing, and the only account is fake, so there's nothing to protect by locking it | `test_auth.py`, `test_detection_p0.py::test_bruteforce_*` | — |
| **A08** | Software and Data Integrity Failures | Every package is **hash-locked** (SHA-256), and the Docker build uses `pip install --require-hashes`, so a substituted or modified package **aborts the build**. Verified by tampering one fastapi hash: pip refused with "THESE PACKAGES DO NOT MATCH THE HASHES" and no image was produced. Uploads are hashed and discarded, never executed or deserialized | `test_owasp.py::test_every_dependency_is_version_and_hash_pinned`, `::test_dockerfile_requires_hashes_and_pins_base_image`, `test_routes.py::test_upload_writes_nothing_to_disk` | — |
| **A09** | Security Logging and Monitoring Failures | **The decoy's purpose:** one redacted canonical event per request, 13 detection rules, batches sent to the collector with a spool if it's down. Slow-connection blind spots closed (F1) | `test_telemetry.py`, `test_detection_*.py`, `test_emitter.py`, `test_security_fixes.py` | An attacker who gained code execution inside the container could edit the local log in `/data`; events already sent to the collector (about 1 s later) are out of reach. Header-phase timeouts are closed before a request exists, so they leave no event |
| **A10** | Server-Side Request Forgery | `/api/v1/preview` never fetches anything. Route and detection modules import no network client (AST-enforced); only the event sender talks to the configured collector. SSRF attempts are detected (`W-SSRF-01`) | `test_routes.py::test_preview_never_connects` (sockets and file opens blocked), `test_safety.py::test_routes_and_detection_have_no_network_or_file_access` | — |

---

## 2025 edition

The 2025 edition reorders the list, merges SSRF into Broken Access Control, and adds two categories.
The protections are the same as above; the new categories are covered in detail below.
*Category names follow the 2025 list as published by OWASP. Check them against owasp.org/Top10 if a reviewer quotes slightly different wording.*

| 2025 | Category | Covered by (2021 row above, plus new work) |
|---|---|---|
| **A01** | Broken Access Control (now includes SSRF) | 2021 A01 + A10 |
| **A02** | Security Misconfiguration | 2021 A05 |
| **A03** | **Software Supply Chain Failures** *(new)* | Hash-locked dependencies, including indirect ones; `--require-hashes` build that refuses tampered packages (tamper test performed); `pip-audit` scan clean; base image pinned by digest; `.in` → lock regeneration documented in the README. Tests: `test_owasp.py::test_every_dependency_*`, `::test_dockerfile_requires_hashes_*` |
| **A04** | Cryptographic Failures | 2021 A02 |
| **A05** | Injection | 2021 A03 |
| **A06** | Insecure Design | 2021 A04 |
| **A07** | Authentication Failures | 2021 A07 |
| **A08** | Software or Data Integrity Failures | 2021 A08 |
| **A09** | Security Logging & Alerting Failures | 2021 A09. Alerting itself is the integrator's collector/dashboard; the decoy supplies labelled, prioritized detections |
| **A10** | **Mishandling of Exceptional Conditions** *(new)* | **Fails closed:** an error during the login check returns a plain 500 and **grants no session**; a broken session store never shows portal data; unhandled errors return an nginx 500 with no traceback; detector, log-write and collector failures never break a request and are counted in `/health`; malformed bodies, undecodable bytes, 5,000-deep JSON and oversized IDs all produce clean errors. Tests: `test_owasp.py::test_error_during_login_check_fails_closed`, `::test_error_in_session_store_fails_closed`, `::test_malformed_inputs_never_crash_into_tracebacks`; `test_telemetry.py::test_broken_detector_never_breaks_requests`, `::test_log_write_failure_never_breaks_requests`, `::test_unhandled_exception_is_nginx_500_and_recorded` |

---

## How each protection was verified (not just written)

- **Planted-bug checks.** For every control added here, I temporarily broke it and confirmed a test fails. That covered: TLS removed, Secure flag removed, HSTS removed, key file world-readable, one package hash removed, `--require-hashes` removed, and login failing *open* on error. All 7 were caught. One test was weak at first: it passed when `--require-hashes` existed only in a comment. It was fixed to check only real commands.
- **Real container:**
  - TLS 1.3 negotiated, and plain HTTP refused.
  - Login cookie is `HttpOnly; SameSite=lax; Secure`, with HSTS present.
  - Key file `-rw-------` in a `drwx------` tmpfs folder.
  - Isolation check ALL PASS.
- **Supply chain:** the real image built with `--require-hashes`. A copy with one tampered fastapi hash was refused by pip, and no image was produced.

## How to re-verify

From `services/web` with the venv active:
```bash
python -m pytest -q
```
```bash
python -m pip install pip-audit && pip-audit -r requirements.txt --require-hashes
```
From the repo root, with Docker running:
```bash
docker compose -f docker-compose.web.yml up -d --build
```
```bash
Get-Content services/web/scripts/isolation_check.py | docker compose -f docker-compose.web.yml exec -T web-decoy python -
```

## What this does not claim
- It doesn't claim to be immune to *unknown* bugs in Python, FastAPI, uvicorn, OpenSSL, Docker or the OS kernel. Hash-locking and scanning cover *known* issues only, so re-scan regularly.
- It doesn't claim the integrator's collector and dashboard meet these controls. They're outside this module. See `docs/INTEGRATOR_NOTES.md` §3 (dashboard XSS) and §8 (forged events).
