# Tor and VPN handling: what we do, how, and the honest limits

**Decision (owner, 2026-11-01): the main site blocks Tor, VPN and hosting visitors; the honeypot lets them in and labels them.**

## Why not just "block VPNs and Tor" everywhere?
- **You can't make a website immune to them.** Tor exit addresses change daily. VPN providers rent new
  server ranges constantly. Residential proxies use real home connections that look exactly like customers.
- **On a honeypot, blocking defeats the purpose.** We *want* the attacker's activity. Blocking also tells
  them the site is watching. So the honeypot records them and labels them instead.
- **On the real service (main site)**, blocking anonymizers removes most automated abuse and lazy attackers.
  That's why many banks and shops do it.

## How it works (one shared module: `services/anonintel/anonintel.py`)
1. **Lists, downloaded ahead of time** by `python scripts/refresh_anon_lists.py` into `services/anonintel/data/`:

   | File | What | Source |
   |---|---|---|
   | `tor_exits.txt` | every current Tor exit IP (~1,700) | Tor Project bulk exit list (GitHub mirror as fallback) |
   | `vpn_ipv4.txt` | commercial VPN provider ranges (~11,000 CIDRs) | X4BNet `lists_vpn` |
   | `datacenter_ipv4.txt` | hosting / cloud ranges (~44,600 CIDRs) | X4BNet `lists_vpn` |
   | `demo.txt` | hand-written test entries, e.g. `192.168.43.77 tor` | you |
   | `META.json` | when and where they were fetched | the script |

   The repo ships a real snapshot from 2026-11-01. Run the script again before the demo, on a machine with internet.
   The honeypot never downloads anything (it may have no internet at all). Both services re-read the files within 30 s of a change.
2. **Lookup:** the visitor's **real TCP address** is checked: Tor first, then VPN, then hosting. Lookups use
   sorted ranges and binary search, so they take microseconds.
3. **`X-Forwarded-For` is never trusted.** Otherwise anyone could bypass the block with one header, or make an innocent IP look like Tor. Both servers start with `proxy_headers=False`, and a test proves it.
4. **Private / LAN addresses** (192.168.x, 10.x, 127.0.0.1) are never matched by the real lists, even if a list
   wrongly contains them. Only `demo.txt` can label them. That's how you rehearse on a hotspot, where nobody really uses Tor.

## Main site (the real service): block
- Tor, VPN or hosting → **403 "Access restricted"** page, before any page code runs (even `/admin` doesn't redirect).
- Each refusal is written to `data/mainsite-blocked.jsonl` (time, IP, category, list, path).
- Configure with `ANON_BLOCK=tor,vpn,hosting` (the default). `ANON_BLOCK=tor` blocks Tor only; empty means block nothing.

## Honeypot (partner portal): allow + label
- The page works normally. The event gets:
  - **W-ANON-01** (Tor exit, medium, ATT&CK candidate **T1090.003 Multi-hop Proxy**): opens an alert on the dashboard.
  - **W-ANON-02** (VPN or hosting, low, candidate **T1090 Proxy**): recorded on the event, no alert on its own.
  - `raw_evidence_redacted.anonymizer = {category, source, list_date}` and tag `anon:tor` / `anon:vpn_or_hosting`.
- **`client_fp`**: a 16-character hash of User-Agent + Accept + Accept-Language + Accept-Encoding, on every event.
  When one attacker hops between Tor exits or VPN servers, the IP changes but the browser usually doesn't.
  The same `client_fp` across different IPs links them. It's a hint, not proof: identical default browsers share
  one, and a careful attacker can change headers. The header values themselves aren't stored.

## What still gets through (say this to judges before they ask)
| Bypass | Why it works | What we still see |
|---|---|---|
| New Tor exit since the last refresh | the list is a snapshot | refresh more often (cron / scheduled task) |
| Residential proxy / hacked home PC | looks like a normal home user | behaviour rules still fire (scan, brute force, SQLi...) |
| Private VPN on a fresh VPS | its range may be in `datacenter_ipv4.txt`, or not | W-ANON-02 if listed; `client_fp` otherwise |
| Attacker on the same LAN | private addresses are never looked up | everything else is still detected |

**One-line pitch:** "We don't pretend to stop VPNs. We block known anonymizers on the real site, and on the honeypot we
let them in so we can watch them, label them with the ATT&CK proxy technique, and link IP-hopping visitors by browser fingerprint."

## Practice questions
1. Why does the main site use the TCP address and not `X-Forwarded-For`?
2. An attacker switches from a Tor exit to a VPN halfway through. Which field links the two halves?
3. Why is W-ANON-02 not allowed to open an alert by itself, when W-ANON-01 is?
4. How do you make your friend's phone look like Tor on the hotspot for the demo?

(Answers: 1, the header is attacker-controlled. 2, `client_fp`. 3, VPN/hosting has many legitimate users and the lists are best effort, while Tor exits are an exact public list. 4, add `<phone-ip> tor` to `demo.txt`.)
