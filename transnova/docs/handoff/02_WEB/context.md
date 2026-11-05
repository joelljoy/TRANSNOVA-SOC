# Web Teammate --- Context

## Your ownership

Build an isolated fake web login/application honeypot using **FastAPI**,
capture HTTP requests and authentication behavior, and provide an
adapter that emits the shared normalized event schema. You own the web
service, safe request handling, web detection tests and handoff to the
integrator.

## Why this module exists

Web applications are frequently probed for exposed admin routes, weak
authentication, injection flaws, path traversal, unsafe uploads and
authorization weaknesses. The decoy should look realistic enough to
attract controlled demo traffic, but it must never execute attacker
input or access production resources.

## Technology

-   Primary: Python FastAPI decoy application.
-   Optional tripwire: OpenCanary HTTP/HTTPS sensor; not a substitute
    for application-level request telemetry.
-   Telemetry: structured application middleware logs (JSON).
-   Adapter: send normalized events to central collector.

## Common real-world behavior to cover

P0: 1. Route/directory enumeration (`/admin`, `/backup`, `/config`,
`/api`). 2. Repeated login failures and a synthetic successful login. 3.
SQL-injection-like input detection (signature/behavior only). 4.
XSS-like input detection (record, never render/execute). 5. Path
traversal-like request detection (record only; never open files).

P1: - SSRF-like parameter detection (never make outbound request). -
File upload metadata capture (store inert/safe fixture only; never
execute). - IDOR/authorization-bypass behavior using synthetic
users/objects. - Webshell path probing (path request only; do not deploy
a webshell).

## Detection and mapping guidance

-   Treat suspicious strings as probes, not proof of successful
    exploitation.
-   T1110.001 / T1110.003 for supported brute-force/spraying patterns.
-   T1190 only if evidence supports an exploitation attempt against a
    public-facing application.
-   T1505.003 only if actual web-shell deployment/use is evidenced; a
    path probe alone is insufficient.
-   Use OWASP category labels for injection, broken access control and
    SSRF where ATT&CK mapping is uncertain.
-   Record confidence and rationale.

## Required normalized events

Use master schema: - `http_request` for route and parameter probes. -
`authentication` for login attempts. - `file_transfer` for upload
metadata where applicable. Include timestamp, source IP, method, route,
status, user-agent, synthetic session ID and redacted evidence. Never
log passwords, session cookies or authorization headers.

## Deliverables

-   FastAPI decoy app with realistic synthetic login page and routes.
-   Middleware/structured JSON event logging.
-   Detection/classification module for P0 patterns.
-   Adapter to central collector.
-   Sample redacted events and tests.
-   README with run/stop/reset, ports, environment variables and
    limitations.
-   Network isolation proof.
-   2-minute demo script.

## Safety

-   Never execute shell commands from request input.
-   Never evaluate or render untrusted HTML/JavaScript.
-   Never fetch SSRF-supplied URLs.
-   Never open arbitrary paths based on request input.
-   Do not expose a file upload to execution; use strict size limits and
    inert storage or metadata-only capture.
-   Bind only to lab network; no production credentials/data.
