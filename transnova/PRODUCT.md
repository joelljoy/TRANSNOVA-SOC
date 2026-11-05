# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

React + TypeScript + Vite, chosen by the owner in the migration brief. It replaces the Streamlit dashboard. The backend stays the FastAPI collector (`collector/`, SQLite).

## Users

There are two audiences, weighted equally (confirmed 2026-11-01):
- A SOC analyst at a desktop monitor who triages alerts and investigates sources over long sessions.
- The project owner presenting to hackathon judges on a laptop or projector. They walk through events, alerts and source profiles live.

## Product Purpose

TransNova SOC is the defender's console for a three-honeypot lab: a web decoy, a MariaDB database decoy and a Cowrie SSH decoy. Every interaction a decoy observes becomes a stored, immutable event. A small evidence-backed alert layer sits on top. Analysts use the console to answer four questions: is the SOC working, does anything verified need attention, are the sensors healthy, and what should I investigate next. Success means every number on screen traces to a stored event, and no source is called malicious without evidence.

## Positioning

The console separates what was observed from what was inferred. Events are evidence. Detections are rule matches with stated rationale and confidence. Alerts are deduplicated per rule and source. AI explanations are labelled interpretation and never confirm anything. A shared IP is shown as a hint, never as proof of one actor.

## Operating Context

- The decoys run in Docker on isolated networks (`lab_net` is internal, with no egress). The dashboard reaches only the collector, through `soc_edge`, and is bound to 127.0.0.1.
- The collector requires a read token for every non-POST route once `SOC_READ_TOKEN_FILE` is set. The dashboard backend holds that token; the browser never does.
- Attacker strings (SQL, shell commands, URLs, `<script>` payloads) are stored unescaped as evidence and must only ever be rendered as text.

## Capabilities and Constraints

- Event vocabulary: `service` is ssh, web or database. `event_type` is connection, authentication, command, http_request, sql_query or file_transfer. `outcome` is observed, succeeded, failed, blocked or simulated.
- Detection rules come from the sensors (W-*, D-*, SSH-*) plus the collector's cross-service rule (X-CORR-01). Each one carries a rule ID, confidence, rationale and candidate ATT&CK techniques. The web sensor emits OWASP 2021 labels; the SOC reports them under OWASP Top 10:2025 and keeps both.
- SSH delivery is gated: the collector refuses SSH data until read authentication and the SSH ingest token are both configured.
- Nothing in the live interface may be hardcoded, sampled or simulated. Empty, offline and error states are shown as they are.

## Brand Commitments

The product name is "TransNova SOC" (owner's choice, 2026-11-01). The decoy company "TransNova Logistics" is a separate fiction inside the database honeypot. There are no logo assets.

## Evidence on Hand

- Real event samples: `services/web/samples/*.jsonl` and `services/ssh/docs/examples/sample-records.jsonl`. These are test fixtures only, never live UI.
- There are no customers, testimonials or benchmarks, and none may be invented.

## Product Principles

1. Evidence before interpretation: the raw observation is always one click from any claim.
2. An event is not an alert, and an alert is not an incident.
3. Honest states: offline, stale, empty and unavailable are first-class, never filled in.
4. Calm by default: severity colour is earned by evidence, not used as decoration.

## Accessibility & Inclusion

WCAG 2.1 AA. Text must stay readable on a projector, so contrast and type size come before density.
