"""Generate initdb/02_seed.sql: deterministic synthetic data for TransNova Logistics.

    python services/database/seed/generate_seed.py            # default seed 20261031
    python services/database/seed/generate_seed.py --seed 7

Same seed + same Faker version = byte-identical output. The output file is committed, so
the Docker build needs neither Python nor Faker. Rows are generated parents-first, so every
foreign key points at a row that already exists.
"""

from __future__ import annotations

import argparse
import hashlib
import random
from datetime import date, datetime, timedelta
from decimal import Decimal
from pathlib import Path

from faker import Faker

ANCHOR = datetime(2026, 10, 1, 8, 0, 0)  # fixed "now": wall-clock time would break reproducibility
OUT = Path(__file__).resolve().parent.parent / "initdb" / "02_seed.sql"

CITIES = [("Mumbai", "Maharashtra"), ("Pune", "Maharashtra"), ("Delhi", "Delhi"),
          ("Bengaluru", "Karnataka"), ("Chennai", "Tamil Nadu"), ("Hyderabad", "Telangana"),
          ("Kolkata", "West Bengal"), ("Ahmedabad", "Gujarat")]
SKUS = [("TN-EL-1001", "Server rack power units"), ("TN-EL-1002", "Network switch cartons"),
        ("TN-PH-2001", "Cold-chain vaccine boxes"), ("TN-AU-3001", "Brake pad assemblies"),
        ("TN-AU-3002", "Alternator crates"), ("TN-TX-4001", "Cotton fabric rolls"),
        ("TN-FM-5001", "Packaged food pallets"), ("TN-IN-6001", "Industrial bearing kits"),
        ("TN-IN-6002", "Hydraulic pump units"), ("TN-RT-7001", "Consumer electronics cartons")]
TRACK_FLOW = ["Booked", "Picked Up", "At Origin Hub", "In Transit", "At Destination Hub",
              "Out for Delivery"]
PARTNERS = [("BlueWake Ocean Lines", "Ocean Freight", "Singapore"),
            ("Skybridge Air Cargo", "Air Freight", "UAE"),
            ("Konkan RailFreight", "Rail", "India"),
            ("QuickLast Couriers", "Last Mile", "India"),
            ("Meridian Customs Brokers", "Customs Broker", "India"),
            ("NorthStar Logistics GmbH", "Air Freight", "Germany"),
            ("Deccan Express Carriers", "Last Mile", "India"),
            ("Harbourline Shipping", "Ocean Freight", "Netherlands")]


def lit(v) -> str:
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, (int, Decimal)):
        return str(v)
    if isinstance(v, float):
        return f"{v:.2f}"
    if isinstance(v, datetime):
        return f"'{v:%Y-%m-%d %H:%M:%S}'"
    if isinstance(v, date):
        return f"'{v:%Y-%m-%d}'"
    return "'" + str(v).replace("\\", "\\\\").replace("'", "''") + "'"


class Seed:
    def __init__(self, seed: int) -> None:
        self.r = random.Random(seed)
        self.fake = Faker("en_IN")
        self.fake.seed_instance(seed)
        self.out: list[str] = []
        self.counts: dict[str, int] = {}

    def insert(self, table: str, cols: list[str], rows: list[tuple]) -> None:
        self.counts[table] = len(rows)
        head = f"INSERT INTO {table} ({','.join(cols)}) VALUES\n"
        for i in range(0, len(rows), 100):  # stays under max_allowed_packet (64K)
            chunk = rows[i:i + 100]
            self.out.append(head + ",\n".join("(" + ",".join(lit(v) for v in row) + ")" for row in chunk) + ";\n")

    def hexstr(self, n: int) -> str:
        return "".join(self.r.choice("0123456789abcdef") for _ in range(n))

    def when(self, days_back: int) -> datetime:
        return ANCHOR - timedelta(days=self.r.randint(0, days_back), minutes=self.r.randint(0, 1439))

    def inr(self, lo: int, hi: int) -> Decimal:
        return Decimal(self.r.randint(lo * 100, hi * 100)) / 100

    def build(self) -> None:
        r, fake = self.r, self.fake

        # warehouses
        wh = []
        for i, (city, state) in enumerate(CITIES, 1):
            wh.append((i, f"WH{city[:3].upper()}{i}"[:6], f"TransNova {city} Hub", city, state,
                       r.randint(4, 30) * 1000, "Maintenance" if i == 7 else "Active",
                       (ANCHOR - timedelta(days=r.randint(900, 3600))).date()))
        self.insert("warehouses", ["warehouse_id", "code", "name", "city", "state", "capacity_units",
                                   "status", "opened_on"], wh)
        wh_ids = [w[0] for w in wh]

        # employees: first 5 are executives; they manage everyone else
        depts = {"Operations": ["Operations Lead", "Hub Supervisor", "Dispatch Coordinator"],
                 "Finance": ["Accounts Analyst", "Billing Executive"],
                 "IT": ["Systems Engineer", "Database Administrator", "Integration Developer"],
                 "Security": ["Site Security Officer"],
                 "Customer Support": ["Support Associate", "Escalations Manager"],
                 "Fleet": ["Delivery Executive", "Fleet Technician"]}
        emp = []
        n_emp, seen = 45, set()
        for i in range(1, n_emp + 1):
            first, last = fake.first_name(), fake.last_name()
            local = f"{first}.{last}".lower().replace(" ", "")
            while local in seen:
                local += str(r.randint(1, 9))
            seen.add(local)
            if i <= 5:
                dept, title, mgr, wid = "Executive", ["Chief Executive Officer", "Chief Financial Officer",
                                                      "Chief Operating Officer", "Chief Information Officer",
                                                      "VP Security"][i - 1], None if i == 1 else 1, None
            elif i <= 28:
                dept, title, mgr, wid = "Fleet", "Delivery Executive", r.randint(2, 5), r.choice(wh_ids)
            else:
                dept = r.choice([d for d in depts if d != "Fleet"])
                title, mgr, wid = r.choice(depts[dept]), r.randint(2, 5), r.choice(wh_ids)
            emp.append((i, f"TN{100000 + i}", first, last, f"{local}@transnova-logistics.example", dept, title, wid,
                        mgr, (ANCHOR - timedelta(days=r.randint(90, 3000))).date(),
                        "On Leave" if i % 17 == 0 else "Active"))
        self.insert("employees", ["employee_id", "employee_no", "first_name", "last_name", "email", "department",
                                  "job_title", "warehouse_id", "manager_id", "hired_on", "status"], emp)

        # vehicles
        vehicles = []
        for i in range(1, 16):
            vtype = r.choice(["Van", "Light Truck", "Heavy Truck", "Refrigerated Truck"])
            vehicles.append((i, f"MH{r.randint(1, 48):02d}TN{r.randint(1000, 9999)}", vtype,
                             {"Van": 1200, "Light Truck": 3500, "Heavy Truck": 16000,
                              "Refrigerated Truck": 9000}[vtype], r.choice(wh_ids),
                             r.choice(["Available", "In Service", "In Service", "Maintenance"]),
                             (ANCHOR - timedelta(days=r.randint(5, 200))).date()))
        self.insert("vehicles", ["vehicle_id", "registration_no", "vehicle_type", "capacity_kg", "home_warehouse_id",
                                 "status", "last_service_on"], vehicles)

        # delivery agents: the 23 Fleet employees
        agents = []
        for aid, e in enumerate(emp[5:28], 1):
            agents.append((aid, e[0], f"DL{r.randint(10**9, 10**10 - 1)}",
                           (ANCHOR + timedelta(days=r.randint(60, 1500))).date(),
                           ((aid - 1) % len(vehicles)) + 1, Decimal(r.randint(32, 50)) / 10,
                           r.choice(["On Duty", "On Duty", "Off Duty"])))
        self.insert("delivery_agents", ["agent_id", "employee_id", "license_no", "license_expiry", "vehicle_id",
                                        "rating", "status"], agents)

        # routes
        routes, rid = [], 0
        for o in wh_ids:
            for d in wh_ids:
                if o != d and r.random() < 0.45:
                    rid += 1
                    km = r.randint(150, 2200)
                    routes.append((rid, f"RT-{rid:04d}{chr(65 + o)}"[:9], o, d, km, round(km / 55, 1),
                                   r.choice(["Low", "Low", "Medium", "High"]), True))
        self.insert("routes", ["route_id", "route_code", "origin_warehouse_id", "dest_warehouse_id", "distance_km",
                               "est_hours", "risk_level", "active"], routes)

        # inventory
        inv, iid = [], 0
        for w in wh_ids:
            for sku, desc in r.sample(SKUS, 7):
                iid += 1
                inv.append((iid, w, sku, desc, r.randint(0, 3000), r.randint(50, 400), self.when(14)))
        self.insert("inventory", ["inventory_id", "warehouse_id", "sku", "description", "quantity", "reorder_level",
                                  "updated_at"], inv)

        # maintenance
        maint = []
        for i in range(1, 46):
            v = r.choice(vehicles)
            maint.append((i, v[0], (ANCHOR - timedelta(days=r.randint(5, 700))).date(),
                          r.choice(["Routine", "Brake", "Engine", "Tyres", "Inspection"]),
                          self.inr(2500, 85000), r.randint(9000, 240000), fake.sentence(nb_words=6)[:200]))
        self.insert("maintenance_records", ["maintenance_id", "vehicle_id", "service_date", "service_type", "cost_inr",
                                            "odometer_km", "notes"], maint)

        # partners + integrations
        partners = [(i, n, t, f"ops@{n.split()[0].lower()}-partner.example", c, "Active" if i != 6 else "Suspended")
                    for i, (n, t, c) in enumerate(PARTNERS, 1)]
        self.insert("shipping_partners", ["partner_id", "partner_name", "partner_type", "contact_email", "country",
                                          "status"], partners)
        integ, iid = [], 0
        for p in partners:
            for env in ("production", "staging"):
                iid += 1
                slug = p[1].split()[0].lower()
                integ.append((iid, p[0], f"{p[1].split()[0]} {r.choice(['Booking', 'Tracking', 'Billing'])} API",
                              f"https://api.{env}.{slug}-partner.example/v2",
                              r.choice(["API Key", "OAuth2 Client", "mTLS", "HMAC"]), env, self.when(3),
                              r.choice(["Healthy", "Healthy", "Degraded"])))
        self.insert("api_integrations", ["integration_id", "partner_id", "system_name", "base_url", "auth_type",
                                         "environment", "last_sync_at", "status"], integ)

        # customers + addresses
        cust, addr, aid = [], [], 0
        for i in range(1, 151):
            name = fake.company()
            slug = "".join(c for c in name.lower() if c.isalnum())[:18]
            tier = r.choices(["Standard", "Business", "Premium"], [60, 30, 10])[0]
            cust.append((i, f"TNC{100000 + i}", name, fake.name(), f"logistics@{slug}.example",
                         f"+91-555-{r.randint(1000000, 9999999)}", tier,
                         self.inr(50000, 5000000), self.when(1500)))
            for j in range(r.randint(1, 3)):
                aid += 1
                city, state = r.choice(CITIES)
                addr.append((aid, i, ["Head Office", "Plant", "Regional Depot"][j],
                             fake.street_address().replace("\n", ", ")[:120], city, state,
                             fake.postcode(), j == 0))
        self.insert("customers", ["customer_id", "account_no", "company_name", "contact_name", "email", "phone",
                                  "tier", "credit_limit_inr", "created_at"], cust)
        self.insert("delivery_addresses", ["address_id", "customer_id", "label", "line1", "city", "state",
                                           "postal_code", "is_default"], addr)
        by_cust: dict[int, list[int]] = {}
        for a in addr:
            by_cust.setdefault(a[1], []).append(a[0])

        # shipments and children
        ships, items, track, invs, pays, disp, iid, tid, pid, did = [], [], [], [], [], [], 0, 0, 0, 0
        statuses = (["Delivered"] * 50 + ["In Transit"] * 22 + ["Pending"] * 10 + ["Delayed"] * 10
                    + ["Failed Delivery"] * 5 + ["Under Investigation"] * 3)
        for s in range(1, 381):
            c = r.choice(cust)[0]
            st = r.choice(statuses)
            created = self.when(240)
            route = r.choice(routes)
            agent = r.choice(agents)
            promised = (created + timedelta(days=r.randint(2, 9))).date()
            delivered = created + timedelta(days=r.randint(1, 9), hours=r.randint(0, 20)) if st == "Delivered" else None
            ships.append((s, f"TN{r.randint(10**11, 10**12 - 1)}", c, r.choice(by_cust[c]), route[2], route[0],
                           None if st == "Pending" else agent[0], r.choice(partners)[0] if r.random() < .25 else None,
                           st, self.inr(4, 3500), self.inr(5000, 900000), created, promised, delivered))
            for _ in range(r.randint(1, 4)):
                iid += 1
                sku, desc = r.choice(SKUS)
                items.append((iid, s, sku, desc, r.randint(1, 80), self.inr(150, 30000)))
            depth = {"Pending": 1, "In Transit": 4, "Delivered": 6, "Delayed": 4, "Failed Delivery": 6,
                     "Under Investigation": 5}[st]
            t = created
            for step in TRACK_FLOW[:depth]:
                tid += 1
                t += timedelta(hours=r.randint(3, 22))
                track.append((tid, s, t, r.choice(CITIES)[0], step, None))
            if st in ("Delivered", "Failed Delivery", "Delayed", "Under Investigation"):
                tid += 1
                t += timedelta(hours=r.randint(3, 22))
                track.append((tid, s, t, r.choice(CITIES)[0], st, "Customer notified" if st != "Delivered" else "POD captured"))
            if st != "Pending":
                did += 1
                disp.append((did, s, route[0], agent[0], agent[4], created + timedelta(hours=4),
                             "Completed" if st == "Delivered" else "Departed"))
            amount = self.inr(1800, 95000)
            due = created.date() + timedelta(days=30)
            inv_status = r.choice(["Paid", "Paid", "Paid", "Issued", "Overdue", "Disputed"])
            invs.append((s, f"INV{s:09d}", c, s, amount, (amount * Decimal("0.18")).quantize(Decimal("0.01")),
                         created.date(), due, inv_status))
            if inv_status == "Paid":
                pid += 1
                pays.append((pid, s, due - timedelta(days=r.randint(1, 20)), amount, r.choice(["NEFT", "RTGS", "UPI", "Cheque"]),
                             f"UTRTN{r.randint(10**12, 10**13 - 1)}"))
        self.insert("shipments", ["shipment_id", "tracking_no", "customer_id", "address_id", "origin_warehouse_id",
                                  "route_id", "agent_id", "partner_id", "status", "weight_kg", "declared_value_inr",
                                  "created_at", "promised_on", "delivered_at"], ships)
        self.insert("shipment_items", ["item_id", "shipment_id", "sku", "description", "quantity", "unit_value_inr"], items)
        self.insert("tracking_events", ["tracking_event_id", "shipment_id", "event_time", "location", "status",
                                        "remarks"], track)
        self.insert("invoices", ["invoice_id", "invoice_no", "customer_id", "shipment_id", "amount_inr", "tax_inr",
                                 "issued_on", "due_on", "status"], invs)
        self.insert("payments", ["payment_id", "invoice_id", "paid_on", "amount_inr", "method", "reference"], pays)
        self.insert("dispatch_records", ["dispatch_id", "shipment_id", "route_id", "agent_id", "vehicle_id",
                                         "dispatched_at", "status"], disp)

        # support tickets
        tickets = []
        subjects = {"Delay": "Consignment past promised date", "Damage": "Cartons damaged on arrival",
                    "Billing": "Invoice amount mismatch", "Lost Parcel": "Parcel not traceable",
                    "General": "Request to update delivery contact"}
        support = [e[0] for e in emp if e[5] == "Customer Support"] or [emp[28][0]]
        for i in range(1, 91):
            s = r.choice(ships)
            cat = r.choice(list(subjects))
            tickets.append((i, f"TKT{i:08d}", s[2], s[0], r.choice(support), cat,
                            r.choice(["Low", "Normal", "Normal", "High", "Urgent"]),
                            r.choice(["Open", "In Progress", "Resolved", "Closed"]), subjects[cat], self.when(120)))
        self.insert("support_tickets", ["ticket_id", "ticket_no", "customer_id", "shipment_id", "assigned_to", "category",
                                        "priority", "status", "subject", "opened_at"], tickets)

        # sensitive-looking decoys: TEST-marked, example-domain, documentation-range values
        it_staff = [e[0] for e in emp if e[5] == "IT"] or [4]
        creds = [(i, it[0], f"{it[2].split()[0].lower()}-svc-key", f"tnk_TEST_{self.hexstr(32)}",
                  f"tns_TEST_{self.hexstr(40)}", (ANCHOR - timedelta(days=r.randint(10, 400))).date(), r.choice(it_staff))
                 for i, it in enumerate(integ, 1)]
        self.insert("api_credentials", ["credential_id", "integration_id", "key_name", "api_key", "api_secret",
                                        "rotated_on", "owner_employee_id"], creds)
        admins = []
        for i, (e, role) in enumerate(zip(r.sample(emp[:5] + emp[28:], 10),
                                          ["dba", "dba", "sysadmin", "sysadmin", "sysadmin", "finance_admin",
                                           "finance_admin", "ops_admin", "ops_admin", "ops_admin"]), 1):
            uname = f"{e[2][0]}{e[3]}".lower().replace(" ", "") + str(i)
            admins.append((i, e[0], uname, hashlib.sha256(f"decoy-{uname}".encode()).hexdigest(), role,
                           r.random() < .6, self.when(30)))
        self.insert("admin_accounts", ["admin_id", "employee_id", "username", "password_hash", "role", "mfa_enabled",
                                       "last_login_at"], admins)
        access = []
        for i in range(1, 41):
            access.append((i, r.choice(wh_ids), r.choice(emp)[0], f"BDG{100000 + i:07d}", f"{r.randint(0, 999999):06d}",
                           r.choice(["Dock", "Floor", "Floor", "Cage", "Vault"]),
                           (ANCHOR + timedelta(days=r.randint(30, 400))).date()))
        self.insert("warehouse_access", ["access_id", "warehouse_id", "employee_id", "badge_no", "door_pin",
                                         "access_level", "valid_until"], access)
        contracts = [(i, p[0], f"CTR{2026}{i:05d}", self.inr(1200000, 95000000), Decimal(r.randint(150, 900)) / 100,
                      (ANCHOR - timedelta(days=r.randint(100, 700))).date(),
                      (ANCHOR + timedelta(days=r.randint(60, 900))).date(),
                      f"Volume rebate above {r.randint(5, 40)}k tonnes; exclusivity on {r.choice(CITIES)[0]} lane")
                     for i, p in enumerate(partners, 1)]
        self.insert("partner_contracts", ["contract_id", "partner_id", "contract_no", "annual_value_inr", "rebate_percent",
                                          "signed_on", "expires_on", "confidential_terms"], contracts)
        assets = []
        roles = ["wms-app", "erp-db", "tms-api", "backup-store", "bastion", "ad-dc", "cctv-nvr", "fileshare"]
        for i in range(1, 25):  # 198.18.0.0/15 is reserved for benchmarking: never routable here
            role = roles[(i - 1) % len(roles)]
            assets.append((i, f"tn-{role}-{i:02d}.corp.example", f"198.18.{r.randint(0, 3)}.{i + 10}", role,
                           r.choice(["prod", "prod", "dr", "corp"]), r.choice(wh_ids + [None]),
                           r.choice(["Ubuntu 22.04", "RHEL 8.9", "Windows Server 2019"])))
        self.insert("internal_network_assets", ["asset_id", "hostname", "ip_address", "role", "environment",
                                                "warehouse_id", "os_version"], assets)

        # adaptive decoys: consistent with the base tables above
        delivered = [s for s in ships if s[8] == "Delivered"]
        cname = {c[0]: c[2] for c in cust}
        self.insert("shipment_archive", ["archive_id", "shipment_id", "tracking_no", "customer_name", "final_status",
                                         "archived_on", "storage_ref"],
                    [(i, s[0], s[1], cname[s[2]], s[8], (ANCHOR - timedelta(days=r.randint(1, 60))).date(),
                      f"archive/2026/q3/{s[1]}.parquet") for i, s in enumerate(r.sample(delivered, 60), 1)])
        premium = [c for c in cust if c[6] == "Premium"]
        self.insert("premium_customer_records", ["record_id", "customer_id", "account_manager", "annual_spend_inr",
                                                 "negotiated_discount", "notes"],
                    [(i, c[0], f"{r.choice(emp)[2]} {r.choice(emp)[3]}", self.inr(2500000, 90000000),
                      Decimal(r.randint(200, 1800)) / 100, "Priority lane; escalate delays to account manager")
                     for i, c in enumerate(premium, 1)])
        self.insert("restricted_routes", ["restricted_route_id", "route_id", "cargo_class", "escort_required",
                                          "checkpoint_notes"],
                    [(i, rt[0], r.choice(["High Value", "Pharma", "Defence Spares", "Bullion"]), r.random() < .7,
                      f"Checkpoint call-in every {r.randint(2, 6)} hours; no unscheduled halts")
                     for i, rt in enumerate(r.sample(routes, 12), 1)])
        self.insert("backup_credentials", ["backup_cred_id", "system_name", "account", "secret_value", "vault_path",
                                           "last_verified"],
                    [(i, sysname, acct, f"TEST-only-{self.hexstr(24)}", f"vault/transnova/{sysname.lower()}/{acct}",
                      (ANCHOR - timedelta(days=r.randint(1, 90))).date())
                     for i, (sysname, acct) in enumerate([("ERP", "erp_backup"), ("WMS", "wms_restore"),
                                                          ("TMS", "tms_ro"), ("NAS", "nas_admin"), ("AD", "svc_backup"),
                                                          ("Veeam", "veeam_svc"), ("CCTV", "nvr_admin"),
                                                          ("VPN", "vpn_break_glass")], 1)])
        self.insert("warehouse_security_logs", ["log_id", "warehouse_id", "badge_no", "door", "logged_at", "result"],
                    [(i, a[1], a[3], r.choice(["Dock 2", "Cage A", "Vault Door", "Server Room"]), self.when(30),
                      r.choice(["Granted", "Granted", "Granted", "Denied", "Forced"]))
                     for i, a in enumerate((r.choice(access) for _ in range(120)), 1)])
        self.insert("internal_transfer_records", ["transfer_id", "from_warehouse_id", "to_warehouse_id", "sku", "quantity",
                                                  "approved_by", "transferred_on"],
                    [(i, rt[2], rt[3], r.choice(SKUS)[0], r.randint(10, 900), r.choice(emp[:5])[0],
                      (ANCHOR - timedelta(days=r.randint(1, 200))).date())
                     for i, rt in enumerate((r.choice(routes) for _ in range(50)), 1)])
        self.insert("executive_shipments", ["exec_shipment_id", "shipment_id", "executive_employee_id", "purpose",
                                            "handling_notes"],
                    [(i, s[0], r.randint(1, 5), r.choice(["Board pack delivery", "Legal originals", "Prototype samples"]),
                      "Hand to named recipient only; do not record in partner systems")
                     for i, s in enumerate(r.sample(ships, 14), 1)])
        self.insert("disaster_recovery_backup", ["dr_id", "asset_id", "backup_set", "location", "encryption_key_ref",
                                                 "last_success_at"],
                    [(i, a[0], f"dr-{a[3]}-weekly", f"s3://transnova-dr.example/{a[3]}/", f"kms-ref-TEST-{self.hexstr(16)}",
                      self.when(7)) for i, a in enumerate(assets, 1)])

    def write(self, path: Path) -> None:
        header = ("-- GENERATED by seed/generate_seed.py. Do not edit by hand.\n"
                  "-- Fictional synthetic data for the TransNova deception lab.\n"
                  "USE transnova_logistics;\nSET FOREIGN_KEY_CHECKS=1;\nSET autocommit=0;\n")
        path.write_text(header + "\n".join(self.out) + "COMMIT;\n", encoding="utf-8", newline="\n")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", type=int, default=20261031)
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args()
    s = Seed(args.seed)
    s.build()
    s.write(args.out)
    for table, n in s.counts.items():
        print(f"{table:28s} {n}")
    print(f"wrote {args.out} ({args.out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
