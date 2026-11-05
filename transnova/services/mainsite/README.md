# TransNova Logistics main site (the real service)

The public company website. **Not a honeypot**: it stores nothing visitors type and has no login.
It is the "amazon.in" to the honeypot's "admin.amazon.in" (the partner portal in `services/web`).

- Start: from `services/mainsite`, with the web venv active: `python -m mainsite.serve` (default `127.0.0.1:8088`).
- Env: `MAIN_SITE_HOST`, `MAIN_SITE_PORT`, `PORTAL_URL` (honeypot address), `ANON_BLOCK` (default `tor,vpn,hosting`),
  `ANON_DATA_DIR`, `MAINSITE_LOG_PATH`.
- Blocks Tor / VPN / hosting visitors with 403 (see `docs/TOR_VPN.md`); never trusts `X-Forwarded-For`.
- Trail to the honeypot: footer "Partner portal", `/admin` and `/partners` redirects, `robots.txt`, an HTML comment, `/js/site.js`.
- Tests: `python -m pytest -q` → 27 passed.
