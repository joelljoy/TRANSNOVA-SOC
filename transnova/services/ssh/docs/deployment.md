# Deployment: honeypot laptop on the controlled team network

Planned topology:

```
Attacker laptop  --(team LAN / hotspot)-->  Honeypot laptop  --(team LAN)-->  SOC laptop
 ssh, paramiko                               cowrie (+ web, DB decoys)          shared backend
                                             collector -> HTTP sink ----------> (endpoint TBD)
```

## Requirements

- Docker Engine with Compose v2.
- **Prefer a Linux host (native Docker Engine) on the honeypot laptop.** Docker Engine on Linux publishes ports with iptables DNAT, which is expected to keep the real client IP visible to Cowrie.
- **Docker Desktop (Windows/macOS) hides the client IP on published ports.** On the Windows dev machine, a connection from the host showed up in Cowrie as `172.18.0.1` (the bridge gateway), not the real client.
  - LAN clients behind Docker Desktop are expected to show a gateway address too. That has **not** been verified with a second laptop.
  - Run the first check below before the demo. If `source_ip` is a gateway address, source-IP correlation in the SOC will not work.
- Clock sync (NTP) on all three laptops, so the SOC timeline ordering is right.

## Configure

```bash
cp .env.example .env
# edit .env:
COWRIE_BIND_ADDR=192.168.50.10   # this laptop's IP on the team network (never 0.0.0.0 / public)
COWRIE_SSH_PORT=22               # or 2222; use 22 only if no real sshd is listening on 22
COWRIE_SENSOR_NAME=cowrie-ssh-01
SOC_INGEST_URL=                  # leave empty until the backend endpoint exists
```

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f collector
```

## First check from the attacker laptop

```bash
ssh -p 22 backup@192.168.50.10        # password: Backup@2024 (synthetic)
```

Run `whoami` and `exit`. Then, on the honeypot laptop:

```bash
docker compose exec collector tail -n 3 /data/state/normalized.jsonl
```

Confirm that `source_ip` is the attacker laptop's LAN IP. If it shows a `172.x` or `192.168.65.x` gateway address, the host is masking client IPs. Use a Linux Docker host, or treat source IP as unreliable and say so in the demo.

## Host firewall (honeypot laptop, Linux)

These rules are **examples that need adapting**. They were written for a Linux Docker host and were **not run** on the Windows dev machine.

The compose file pins the decoy network's bridge name to `br-ps04-decoy` so rules can refer to it. `DOCKER-USER` is the chain Docker reserves for user rules. Replace `192.168.50.0/24` with the team subnet.

```bash
# --- Forwarded traffic (decoy -> internet, other Docker networks, other hosts) ---
# Replies to connections the decoy accepted are always allowed.
sudo iptables -I DOCKER-USER 1 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
# The decoy may not open NEW outbound connections anywhere (defense in depth beyond out_addr).
sudo iptables -I DOCKER-USER 2 -i br-ps04-decoy -m conntrack --ctstate NEW -j DROP
# Only the team subnet may reach the decoy (after DNAT the destination port is the container's 2222).
sudo iptables -I DOCKER-USER 3 -o br-ps04-decoy -p tcp --dport 2222 ! -s 192.168.50.0/24 -j DROP

# --- Traffic to the honeypot laptop itself (DOCKER-USER does NOT see this) ---
# Without this rule the decoy can open host services on the bridge gateway / host IPs.
sudo iptables -I INPUT 1 -i br-ps04-decoy -m conntrack --ctstate NEW -j DROP
```

`wget` from the decoy shell is **not** a valid test of these rules, because Cowrie's `out_addr` already makes it fail. Test with a plain socket inside the container instead, which is what code running after a Cowrie compromise would use. With the DROP rules in place, every line must print `blocked timeout`. `ConnectionRefusedError` only means nothing is listening on that port, so it does not prove the firewall works.

```bash
docker compose exec cowrie /cowrie/cowrie-env/bin/python3 -c "
import socket
gw = open('/proc/net/route').read().split('\n')[1].split()[2]
gw = '.'.join(str(int(gw[i:i+2], 16)) for i in (6, 4, 2, 0))
for h, p in [('1.1.1.1', 443), (gw, 22), (gw, 8088), ('<SOC-laptop-IP>', 80)]:
    s = socket.socket(); s.settimeout(3)
    try: s.connect((h, p)); print(h, p, 'OPEN  <-- not blocked')
    except OSError as e: print(h, p, 'blocked', type(e).__name__)
    finally: s.close()"
sudo iptables -L DOCKER-USER -v -n; sudo iptables -L INPUT -v -n | head   # drop counters should increase
```

Also confirm that SSH to the decoy from the attacker laptop still works after adding the rules.

**On Docker Desktop (Windows/macOS) these rules cannot be applied from the host.** Verified on the dev machine: the decoy reached 12 of 13 probed host services through `host.docker.internal`, including services bound to 127.0.0.1. See [safety-and-isolation.md](safety-and-isolation.md). Use a Linux honeypot laptop for the team demo, or accept and state that limitation.

Also block the honeypot laptop's own inbound ports other than the decoys (for example with `ufw`), and keep it off untrusted networks during the demo.

## Pointing the collector at the SOC backend

Once the backend teammate provides the endpoint, set `SOC_INGEST_URL` (and `SOC_INGEST_TOKEN`) in `.env`, then run:

```bash
docker compose up -d
```

Follow [integration-contract.md](integration-contract.md#how-to-verify-integration-once-the-endpoint-exists) to verify.

Only records still in the outbox are sent to a newly enabled sink. That means the newest `retain_delivered_records` (20,000 by default) plus anything undelivered. Older history is in `normalized.jsonl` and Cowrie's own log, and can be re-processed with `cowrie-soc replay` if the backend needs it.

## Running the collector without Docker

The collector is pure standard-library Python 3.11+ and needs no dependencies:

```bash
cd collector
pip install .
COWRIE_SOC_LOG_DIR=/path/to/cowrie/var/log/cowrie COWRIE_SOC_STATE_DB=./state/collector.db \
  cowrie-soc run --config config/collector.toml
```

`[sinks.jsonl] path` defaults to `/data/state/normalized.jsonl`. Override it in a copy of the TOML when running outside Docker.

## Reset after a demo

Do not use `down -v`, `docker volume rm` or `docker volume prune`. In the merged project they can delete shared database and SOC data. Leave volumes in place between demos.
