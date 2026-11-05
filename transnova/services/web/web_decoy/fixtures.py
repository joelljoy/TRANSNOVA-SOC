"""Synthetic, in-memory business data. Every name, email, order and file here is fake."""

from __future__ import annotations

USERS: dict[int, dict] = {
    1001: {"id": 1001, "username": "j.miller", "name": "Jordan Miller", "role": "partner",
           "email": "j.miller@transnova-logistics.example", "company": "Brightwater Imports"},
    1002: {"id": 1002, "username": "a.okafor", "name": "Ada Okafor", "role": "partner",
           "email": "a.okafor@transnova-logistics.example", "company": "Okafor Textiles"},
    1003: {"id": 1003, "username": "s.lindqvist", "name": "Sven Lindqvist", "role": "ops",
           "email": "s.lindqvist@transnova-logistics.example", "company": "TransNova Logistics"},
    1004: {"id": 1004, "username": "m.kowalski", "name": "Marta Kowalski", "role": "partner",
           "email": "m.kowalski@transnova-logistics.example", "company": "Vistula Agro Export"},
    1005: {"id": 1005, "username": "r.patel", "name": "Ravi Patel", "role": "partner",
           "email": "r.patel@transnova-logistics.example", "company": "Patel Components Ltd"},
    1006: {"id": 1006, "username": "l.berg", "name": "Lena Berg", "role": "ops",
           "email": "l.berg@transnova-logistics.example", "company": "TransNova Logistics"},
}

USER_BY_NAME = {u["username"]: u for u in USERS.values()}

SHIPMENTS: dict[int, dict] = {
    50211: {"id": 50211, "owner_id": 1001, "origin": "Rotterdam", "destination": "Gdansk",
            "status": "In transit", "eta": "2026-11-04", "containers": 2},
    50212: {"id": 50212, "owner_id": 1001, "origin": "Hamburg", "destination": "Oslo",
            "status": "Customs hold", "eta": "2026-11-07", "containers": 1},
    50318: {"id": 50318, "owner_id": 1002, "origin": "Antwerp", "destination": "Riga",
            "status": "Delivered", "eta": "2026-10-28", "containers": 4},
    50344: {"id": 50344, "owner_id": 1001, "origin": "Gothenburg", "destination": "Tallinn",
            "status": "Loading", "eta": "2026-11-09", "containers": 3},
    50402: {"id": 50402, "owner_id": 1004, "origin": "Gdynia", "destination": "Felixstowe",
            "status": "In transit", "eta": "2026-11-05", "containers": 6},
    50417: {"id": 50417, "owner_id": 1005, "origin": "Le Havre", "destination": "Aarhus",
            "status": "Awaiting pickup", "eta": "2026-11-03", "containers": 1},
}

# Portal noise: things a live partner portal shows. Times are minutes before "now" so the
# page always looks current; nothing here is real or comes from a request.
ACTIVITY: list[tuple[int, str]] = [
    (7, "Shipment #50211 passed Kiel Canal checkpoint"),
    (26, "Customs pre-clearance approved for #50344 (EORI verified)"),
    (58, "Invoice INV-2026-10-4471 issued"),
    (140, "Container TNLU1234567 gate-in at Rotterdam ECT Delta"),
    (310, "Partner API key rotated by ops (scheduled)"),
    (1320, "Shipment #50212 placed on customs hold: missing certificate of origin"),
]

ANNOUNCEMENTS: list[tuple[str, str]] = [
    ("Scheduled maintenance", "Sunday 02:00-04:00 CET: document uploads unavailable while we migrate storage."),
    ("New customs rules", "From 1 December, EU ICS2 release 3 filings are required for all inbound sea freight."),
    ("Partner API v1 deprecation", "v1 endpoints are retired in Q1 2027. Contact your account manager for v2 access."),
]

STATUS_COMPONENTS: list[tuple[str, str]] = [
    ("Shipment tracking", "Operational"),
    ("Partner API (v1)", "Operational"),
    ("EDI gateway (EDIFACT / IFTMIN)", "Degraded performance"),
    ("Customs document upload", "Operational"),
    ("Invoice portal", "Operational"),
]

INCIDENTS: list[tuple[str, str, str]] = [
    ("2026-10-29", "EDI gateway delays", "Some IFTSTA status messages were delayed by up to 40 minutes. Monitoring."),
    ("2026-10-14", "Login errors for some partners", "Resolved. An expired SSO certificate was renewed."),
    ("2026-09-30", "Planned database migration", "Completed. Partner reporting now reads from the new ERP replica."),
]

CHANGELOG: list[tuple[str, str, list[str]]] = [
    ("3.8.2", "2026-10-29", ["Fixed CSV manifest template encoding", "Faster shipment search for container numbers"]),
    ("3.8.1", "2026-10-16", ["SSO certificate renewed", "Session timeout raised to 8 hours on partner request"]),
    ("3.8.0", "2026-10-02", ["Document upload size limit set to 960 KB", "Partner reporting moved to the ERP replica",
                             "Legacy link preview endpoint kept for older ERP plugins (to be removed in 3.9)"]),
    ("3.7.4", "2026-09-11", ["Admin console moved behind /admin/login", "Minor accessibility fixes"]),
]

ORDERS: dict[int, dict] = {
    9001: {"id": 9001, "owner_id": 1001, "shipment_id": 50211, "amount_eur": 4120.00, "state": "invoiced"},
    9002: {"id": 9002, "owner_id": 1001, "shipment_id": 50212, "amount_eur": 1875.50, "state": "open"},
    9003: {"id": 9003, "owner_id": 1002, "shipment_id": 50318, "amount_eur": 9930.00, "state": "paid"},
}

# /download serves ONLY these exact keys from memory. Request input never reaches the filesystem.
FAKE_FILES: dict[str, tuple[str, str]] = {
    "manifest-template.csv": (
        "text/csv",
        "shipment_id,container,weight_kg,hs_code\n50211,TNLU1234567,18400,8471.30\n",
    ),
    "partner-onboarding.txt": (
        "text/plain",
        "TransNova Logistics partner onboarding checklist (sample).\n1. Request portal account.\n",
    ),
}

API_INDEX = {
    "service": "transnova-partner-api",
    "version": "v1",
    "endpoints": ["/api/v1/users", "/api/v1/users/{id}", "/api/v1/orders", "/api/v1/preview"],
}
