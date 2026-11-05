# Integrator Notes — from the Web module

Audience: the integrator (owner of `collector/`, the canonical schema, detections and `dashboard/`).
The web module does not change the shared schema. Everything here is a request or a contract proposal for you to accept or reject.

## 1. Transport

- Endpoint: `POST http://collector:8000/api/events`
- Body: **JSON array** of canonical events (HANDOFF_FINAL.md §6), ≤50 per request, `Content-Type: application/json`.
- Web sends at least once a second while events are queued. Timeout 2 s.
- If the collector is unavailable, events are spooled to `/data/web-spool.jsonl` and resent later. **Please deduplicate on `event_id`**, because a resend after a timeout can deliver the same event twice.
- Expected response: `2xx` = accepted. Any other response means the batch is spooled and retried.

## 2. Detection metadata (schema gap)

The canonical schema has no field for rule hits. Until you add one, web puts them here:

```json
"raw_evidence_redacted": {
  "detections": [
    {
      "rule": "W-SQLI-01",
      "category": "probe_detected",
      "label": "probe:sqli",
      "field": "q",
      "owasp": "A03:2021-Injection",
      "attack": [
        {"technique": "T1190", "status": "candidate",
         "rationale": "SQLi-like input observed; no evidence of success",
         "confidence": "medium"}
      ],
      "confidence": "medium"
    }
  ]
},
"tags": ["probe:sqli", "owasp:A03"]
```

- `category`: `probe_detected` (input signatures, path probes), `behavior_detected` (route scan, failed login, brute force, spraying) or `decoy_interaction` (decoy credential accepted). Web never claims an exploit succeeded.
- `field`: `path`, `query.<name>`, `form.<name>`, `json.<dotted.name>` or `upload`. The matched value itself is never included.
- Rules and thresholds (all in the web module's PLAN.md §5): W-ENUM-01 sensitive path (low), W-ENUM-02 ≥8 distinct 403/404/bait paths in 60 s (T1595.003), W-AUTH-01 failed login, W-AUTH-02 ≥5 / ≥15 failures for one username in 60 s (T1110.001, medium / high), W-AUTH-03 ≥4 usernames with ≤2 tries each in 5 min (T1110.003), W-AUTH-04 decoy login accepted (high), W-SQLI-01 (T1190), W-XSS-01, W-PATH-01, W-SSRF-01, W-UPL-01, W-IDOR-01, W-SHELL-01.
- Full attack-campaign sample (24 events, one campaign ID, every rule firing): `services/web/samples/web-attack-campaign.sample.jsonl`.
- `attack[].status` is `candidate`. Your alert layer decides whether to promote a candidate to an alert mapping.
- `T1505.003` is never emitted for a webshell path probe.
- If you add a first-class schema field (e.g. `detections`), tell the web owner and the adapter will move the data there.
- **Behaviour rules repeat (since web 0.8.0):** once W-ENUM-02, W-AUTH-02 or W-AUTH-03 crosses its threshold, every further qualifying event from that source carries the rule with the running count in `rationale` (e.g. 50 failed logins → W-AUTH-02 on events 5–50: medium 5–14, high 15+). To show one incident per attack, group alerts by `(source_ip, rule)` within the rule's window and use the highest confidence seen.

## 3. Dashboard XSS: action needed on your side

Event evidence contains **raw attacker-supplied strings** (`<script>…`, `javascript:` and so on). They're bounded to 512 chars, control-char-stripped, and tagged `contains_markup` when they look like HTML, but they are **not HTML-escaped**, because escaping would corrupt the evidence.

In Streamlit:
- **Never** pass event fields to `st.markdown(..., unsafe_allow_html=True)` or `st.html`, or into `components.html`.
- Plain `st.markdown` also interprets Markdown, including links. Show evidence with `st.code`, `st.text`, `st.json` or `st.dataframe`.
- In Plotly hover text, escape `<` and `>` (Plotly renders a subset of HTML tags).

## 4. Campaign IDs

- Header: `X-Campaign-Id`, value `^[A-Za-z0-9_-]{1,64}$`.
- Web trusts the header only from `SIMULATOR_SOURCE_CIDRS` (default `172.28.0.50/32`). From any other source it's discarded and the event is tagged `untrusted_campaign_header`.
- **The simulator must run as a container on `lab_net` with a fixed IP** (proposed `172.28.0.50`). Verified in the Phase 2 container test: anything sent from the host through a published `127.0.0.1:` port reaches the decoy from the Docker gateway (`172.28.0.1`). A host-run simulator would therefore (a) share one source IP with every other host process, breaking per-attacker profiles, and (b) be impossible to tell apart from other host traffic for campaign trust.

## 5. Source IP

Web uses the TCP peer address. `X-Forwarded-For` is ignored unless `TRUST_PROXY=1`, so don't put a reverse proxy in front of the decoy without telling the web owner.

## 6. Health for adapter status

- `GET https://web-decoy:8080/health` (HTTPS only in the container; self-signed certificate regenerated at each start, so skip verification for this lab call) returns detailed JSON (sensor id, collector reachability, queue depth, dropped events, spool backlog, detection counters). Field list: PLAN.md §3.1.
- This only works from `HEALTH_ALLOWED_CIDRS` (default `127.0.0.1/32`). **Give the collector a fixed lab IP and tell the web owner**, so it can be added as a `/32`. Never the whole subnet (see §4: the gateway address would then be trusted). Other sources get a normal 404, so attackers can't tell the site is a honeypot.

## 7. Event vocabulary (as built, Phase 3)

Sample of 11 real events from an end-to-end container run: `services/web/samples/web-events.sample.jsonl`.

| Field | Values from web-01 |
|---|---|
| `event_type` | `http_request`, `authentication` (POST /login), `file_transfer` (POST /upload) |
| `action` | `page_view`, `route_probe`, `login_attempt`, `upload_attempt` |
| `outcome` | `observed`, `failed` / `succeeded` (login), `blocked` (size limit) |
| `tags` | `authenticated_session`, `contains_markup`, `untrusted_campaign_header`, `body_rejected`; Phase 4 adds `probe:*`, `enum:*`, `auth:*` labels |
| `session_id` | Opaque UUID, the same across one login session; **not** the cookie |
| `raw_evidence_redacted` | `headers` (allowlisted), `query`/`form`/`json` (redacted), `body` (type + size), `upload` (name, sizes, sha256, sniffed type, `stored:false`), `detections[]` |

Not emitted: successful static asset loads, and `/health` polls from `HEALTH_ALLOWED_CIDRS`.

## 8. Network setup the team compose must copy (containment)

The web decoy's standalone compose proves this layout. The team `docker-compose.yml` should keep it:

```yaml
networks:
  lab_net:
    internal: true                                   # no internet egress
    driver_opts:
      com.docker.network.bridge.inhibit_ipv4: "true"  # decoys cannot reach the Docker host either
    ipam: { config: [ { subnet: 172.28.0.0/16 } ] }
```

- Why both settings: `internal` alone still let a container reach services listening on the host via `172.28.0.1` (verified; web PLAN.md P12).
- Decoys (web `172.28.0.10`), the simulator (`172.28.0.50`) and the collector (proposed `172.28.0.20`) sit on `lab_net`.
- The dashboard and the collector's host-facing port need a **separate** non-internal network. Don't attach decoys to it, or they get egress back.
- Proof command and expected output: `services/web/README.md` → Containment proof.

**Recommendation (not blocking for the hackathon):** any container on `lab_net` can POST to `/api/events`, including a compromised decoy, and could forge events. A per-sensor ingest token checked by the collector would close that. Tell the web owner if you add one; the emitter needs one header.

## 9. Requests to you

0. Publish `collector/schema.py` and a running collector so the web module can finish Phase 5 (swap the schema copy, prove events in `GET /api/events` and the dashboard).
1. Accept or reject the §2 detection shape.
2. Confirm the lab subnet, the collector's fixed IP (§6) and the simulator's fixed IP (§4).
3. Confirm the dashboard renders evidence as plain text only (§3).
4. Deduplicate on `event_id` (§1).
5. Group repeated behaviour-rule hits by `(source_ip, rule)` if you want one alert per attack (§2).

## 10. Collector request limits and read access (Stage 4)

Code and tests only. None of this runs until the collector is rebuilt at Stage 5. Web and Database senders need no changes.

**Limits, in `collector/guards.py`:**

| Rule | Value | Result |
|---|---|---|
| `POST /api/events`, `/api/adaptations` | 16 MiB | `413` |
| `POST /api/sensors/heartbeat` | 2 MiB | `413` |
| Any request with `Authorization` | 1 MiB | `413` |
| Whole body must arrive within | 15 s, absolute | `408` |
| Bodies in progress at once | 32 MiB, held until the app finishes | `503` |
| Bodies over 1 MiB: commas outside strings | 1,500,000 | `413` |
| Bodies over 1 MiB: `[` and `{` outside strings | 100,000 | `413` |
| One read of stored data | 64 MiB of text, newest first | Result may be incomplete |
| Both `Content-Length` and `Transfer-Encoding`, or a body on any method but POST | | `400` |
| POST to an unknown path | | `404` |

Every guard refusal above closes the connection, so unread bytes cannot become another request. A sender may see a reset instead of the status, and treats that as a normal failed send.

**The guard runs after the HTTP parser, not before it.** h11 keeps both framing headers, so the guard sees them, but h11 may already have decoded up to about 64 KiB of a body it received. No body reaches the application until the guard passes it. This depends on h11, so `h11` and `--http h11` are pinned and a test fails if the behaviour changes. Identical duplicate lengths are merged by h11 before the guard sees them, which is safe because only one length remains.

**The 32 MiB budget is not a memory ceiling.** It limits raw bytes in progress. Parsed JSON can be about 25 times its text. Two bodies of empty lists killed an unprotected server under a 1536 MiB limit, which is why the structure check and read cap exist. A collector memory limit stays mandatory at Stage 5.

**A refused Database event batch blocks all later Database telemetry.** The Database sender retries the head of its queue forever (`emitter.py`), so any `4xx` stops delivery until a person steps in. Nothing is lost: events stay in its spool and JSONL log. This already happens today with one invalid event. It is why no collector limit may refuse a real batch, and why text inside strings is never counted. The largest batch measured is 4.62 MiB. A test pins this behaviour, and it should change with the sender.

**A refused heartbeat loses only a status update.** A session's table list has no cap, so an attacker can push a heartbeat over 2 MiB and make the Database sensor look stale until newer sessions replace it. Event delivery is not affected.

**Before Database or Web get write tokens:** the 1 MiB limit applies to anything with `Authorization`, which would refuse a real 4.62 MiB Database batch and block its queue. That limit must become per-token first.

**Reading:** with `SOC_READ_TOKEN_FILE` set, everything except POST needs the read token, and `/health` without it returns only `{"status":"ok"}`. Anyone calling the API by hand must send the token. Unset, reads stay open, and the collector refuses all SSH data with `503`.

**Stage 5 gates, in order. If any fails, SSH delivery stays disabled:** Docker secrets in place; collector memory limit set; `--http h11` running in the built image; body, header and memory tests repeated against the real container; read authentication on; the real dashboard container reads every protected endpoint with its own token, no token and a wrong token both get `401`, and the page loads data. Only then set `enabled = true`.
