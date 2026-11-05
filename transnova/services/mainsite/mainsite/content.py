"""Public, synthetic company content. Shipment numbers match the partner portal's story."""

from __future__ import annotations

SERVICES = [
    ("Short-sea container shipping", "Weekly sailings between Rotterdam, Hamburg, Gdansk, Riga, Tallinn and Felixstowe."),
    ("Customs brokerage", "ICS2-ready filings, EORI checks and pre-clearance for EU and UK trade lanes."),
    ("Rail and road on-carriage", "Door delivery across Benelux, Germany, Poland and the Baltics."),
    ("Temperature-controlled freight", "Reefer capacity for food and pharmaceuticals with live temperature logging."),
    ("Warehousing", "Bonded and general storage in Rotterdam and Gdynia, 41,000 m2 in total."),
    ("Project cargo", "Out-of-gauge and heavy-lift moves with dedicated engineering support."),
]

STATS = [("38", "years in the Baltic trade"), ("1,240", "containers moved weekly"),
         ("11", "ports served"), ("96.4%", "on-time arrival (Q3 2026)")]

# Public tracking: status only, never the customer or commercial details.
TRACKING = {
    "TNL50211": {"route": "Rotterdam -> Gdansk", "status": "In transit", "eta": "2026-11-04",
                 "steps": [("2026-10-27", "Booked"), ("2026-10-29", "Loaded on MV Nordic Tern"),
                           ("2026-10-31", "Passed Kiel Canal")]},
    "TNL50212": {"route": "Hamburg -> Oslo", "status": "Customs hold", "eta": "2026-11-07",
                 "steps": [("2026-10-25", "Booked"), ("2026-10-30", "Arrived Oslo"),
                           ("2026-10-31", "Held: documents requested")]},
    "TNL50318": {"route": "Antwerp -> Riga", "status": "Delivered", "eta": "2026-10-28",
                 "steps": [("2026-10-18", "Booked"), ("2026-10-22", "Departed Antwerp"),
                           ("2026-10-28", "Delivered")]},
    "TNL50402": {"route": "Gdynia -> Felixstowe", "status": "In transit", "eta": "2026-11-05",
                 "steps": [("2026-10-28", "Booked"), ("2026-10-31", "Departed Gdynia")]},
}

JOBS = [
    ("Customs Declarant", "Rotterdam", "Full-time"),
    ("Operations Planner, Baltic lanes", "Gdynia", "Full-time"),
    ("IT Support Engineer", "Rotterdam (hybrid)", "Full-time"),
    ("Warehouse Team Lead", "Gdynia", "Shift-based"),
]

NEWS = [
    ("2026-10-21", "New weekly Gdynia-Felixstowe loop starts in November"),
    ("2026-09-30", "TransNova completes ERP migration for faster customs clearance"),
    ("2026-09-02", "Reefer fleet expanded with 120 new 40' units"),
]

# Next sailings, shown on the home page as the company's real product: the schedule.
SAILINGS = [
    ("MV Nordic Tern", "NS1", "Rotterdam", "Gdansk", "Mon 04 Nov 18:00", "Sun 03 Nov 12:00"),
    ("MV Kaja", "BL2", "Hamburg", "Riga", "Tue 05 Nov 06:00", "Mon 04 Nov 16:00"),
    ("MV Sound Runner", "NS3", "Gdynia", "Felixstowe", "Wed 06 Nov 22:00", "Tue 05 Nov 22:00"),
    ("MV Nordic Tern", "NS1", "Gdansk", "Tallinn", "Thu 07 Nov 09:00", "Wed 06 Nov 18:00"),
    ("MV Baltic Lark", "BL2", "Riga", "Rotterdam", "Fri 08 Nov 15:00", "Thu 07 Nov 23:00"),
]

LOOPS = [
    ("NS1", "North Sea - Baltic", "Rotterdam, Hamburg, Gdansk, Tallinn", "weekly, 9-day rotation"),
    ("BL2", "Baltic shuttle", "Hamburg, Riga, Rotterdam", "weekly"),
    ("NS3", "UK loop", "Gdynia, Felixstowe, Antwerp, Le Havre, Aarhus", "weekly, from November"),
]
