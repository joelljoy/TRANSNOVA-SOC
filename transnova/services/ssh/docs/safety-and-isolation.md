# Safety and isolation

This decoy is a lab honeypot for authorized demo traffic on a controlled team network. Everything it exposes is synthetic.

**Docker is not a complete security boundary.** The controls below reduce risk; they do not make the decoy safe to expose to the internet.

## Controls and how they were verified

Checks were run on 2026-10-31 on the dev machine (Windows 11, Docker Desktop 29.8.0, Cowrie 3.1.4).

| Control | Where | Verified |
|---|---|---|
| The emulated shell runs commands inside Cowrie's Python emulator, never on a host shell | Cowrie design; `backend = shell` default | Commands like `./update.sh` returned emulated "No such file" errors; nothing ran in the container |
| Emulated `wget`/`curl`/`tftp`/`ftpget` cannot reach the network: `out_addr = 127.0.0.1` binds their sockets to loopback | `cowrie/cowrie.cfg` | Inside the running container, a socket bound to 127.0.0.1 connecting to 1.1.1.1:443 failed with `EINVAL`. An unbound socket **did** connect, so the container itself has default Docker egress (see residual risks). The decoy's `wget http://192.0.2.10/...` failed |
| SSH TCP forwarding disabled (`forwarding`, `forward_redirect`, `forward_tunnel = false`) | `cowrie/cowrie.cfg` | `ssh -W 1.1.1.1:443` was refused with `open failed: unknown channel type ... direct-tcpip` |
| Telnet disabled | `cowrie/cowrie.cfg` | Only port 2222 is listening |
| Downloads and uploads capped at 1 MiB (`download_limit_size`) | `cowrie/cowrie.cfg` | Config only; no successful transfer was possible to test |
| Decoy published on 127.0.0.1 by default | `docker-compose.yml` (`COWRIE_BIND_ADDR`) | `docker inspect`: `127.0.0.1:2222->2222/tcp` |
| No host bind mounts; config and decoy files baked into the image; named volumes only | `cowrie/Dockerfile`, compose | `docker inspect` lists only Docker volumes |
| Cowrie and collector run as non-root (999 / 10001), with a read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, and pids, memory and CPU limits; neither is privileged | compose | `docker inspect` shows `readonly=true capdrop=[ALL] privileged=false` |
| Config, userdb and filesystem pickle are root-owned and read-only to the cowrie user | `cowrie/Dockerfile` | File modes 0444, directory 0555 |
| The collector reads Cowrie's logs **read-only**, has no listening port, and is on a separate compose network | compose (`:ro`, separate networks) | Collector mount `rw=false`; Cowrie is on `decoy-net`, the collector on `soc-uplink`. Note that separate networks only stop **name resolution** on Docker Desktop; by IP, Cowrie can reach `soc-uplink` containers (see residual risk 2) |
| Dev receiver requires a token for reads and writes and refuses to start without one (compose `dev` profile) | `devreceiver.py`, compose | 2026-11-01: without a token the container exits with code 2. From inside Cowrie, unauthenticated `GET /records` and `POST /ingest` (by IP and via `host.docker.internal`) returned **401** |
| No secrets in the decoy | compose | `docker inspect`: the Cowrie container's environment contains only `COWRIE_HONEYPOT_SENSOR_NAME`. `SOC_INGEST_TOKEN` is given only to the collector and dev receiver, and credentials are stripped from the ingest URL in log messages |
| No Docker socket mounted anywhere | compose | Mounts inspected |
| All credentials, files and "secrets" are synthetic; honeytoken markers `HT-DB-0001` and `HT-API-0001` | `cowrie/userdb.txt`, `cowrie/decoy-fs/` | Manual review |
| Log content treated as untrusted | collector | Parsing is `json.loads` only. Command text is tokenized, never executed. SQLite uses parameter binding. The HTTP sink only accepts http(s) URLs from config. Tests cover injection-shaped input |
| No automatic response or blocking | collector | Findings contain advisory `recommended_action` text only |
| Demo traffic generator is bounded | `demo-attacker/scenarios.py` | Target allow-list (`cowrie`, `localhost`, `127.0.0.1` by default), fixed command lists, at most 12 auth attempts. Downloads use TEST-NET-1 (192.0.2.0/24), which is never routed |

## What is stored about attacker input

Project rule: attacker input is not recorded unless it is needed. Cowrie is patched at build time (`cowrie/harden_cowrie.py`) so that every event passes through `soc_redact.py` before anything is written, and the sensor repeats the same cleaning before it stores anything. Each event type has a list of allowed fields. Everything else is dropped, and an unknown event type keeps only its metadata. If cleaning fails, the event is cut down to metadata.

| Input | What is kept |
|---|---|
| Login passwords | Nothing. They are removed from Cowrie's own login events |
| Usernames | Common account names (`root`, `backup`, ...) as typed. Anything else becomes `user_<8 hex>`, keyed by a value held in memory and new at each start |
| Commands | Programs the detection rules use keep their arguments, with known secret patterns and random-looking values removed. Any other program keeps only its name and flag names |
| Input typed into a running program (`passwd`, `su`, `ssh` prompts, `cat`, `tee`) | Nothing. Replaced with `__REDACTED__` |
| Environment variables | Name only, except `LANG`, `LC_*` and `TERM` |
| Piped input and redirected output | In memory only, lost on restart. Content and hash are not logged |
| Uploads | Content in memory only, lost on restart. The SHA-256 is logged. The file name becomes `file_<8 hex>` |
| Keystroke recordings | Off (`ttylog = false`) |
| Docker logs | No log is stored for the decoy (`driver: none`). Its console prints only level and module |
| Sensor quarantine | Offset, SHA-256 and a fixed reason. No line content |
| Sensor diagnostics | No exception text and no collector response bodies |

Verified live with `tests/live/run_marker_test.py`, which reports counts only.

**This does not find every secret. Limits:**

- An ordinary word passed to an allowed program looks like a filename and is kept, for example `cat maple7`.
- A URL path can hold a secret. Only credentials and known query keys are removed from URLs.
- The SHA-256 of an upload is kept, so very short or guessable content could be confirmed by guessing.
- Uploaded files are gone after a restart, so samples cannot be analysed later.
- There is no session replay, and `docker logs ssh-honeypot` shows nothing. Use the container status and `cowrie.json` to debug.
- `user_<8 hex>` values change on restart, so usernames cannot be matched across restarts.
- A compromised Cowrie can still write fake log lines and can read what it receives in memory.
- Log files written before this change, and Stage 2 test sessions in the `tty/` folder, were kept and were not rewritten.

The log directory is writable by Cowrie, so the sensor treats it as hostile. It reads only regular files directly inside it, opens each with `O_NOFOLLOW` relative to a held directory handle, checks the type on that open handle, and uses the same handle for every read. Symlinks, FIFOs, sockets, devices, directories and hard links are rejected. `tests/live/linux_tailer_check.py` runs these attacks in the real sensor image.

## Residual risks and required mitigations

1. **Container egress is open at the Docker level.**
   - Cowrie's own outbound features are confined by `out_addr` and disabled forwarding.
   - A Cowrie vulnerability that gave code execution in the container would still have normal Docker egress.
   - On the honeypot laptop, add the host firewall rules in [deployment.md](deployment.md#host-firewall-honeypot-laptop-linux) to block new outbound connections from the `br-ps04-decoy` bridge.
   - Those rules are written for a Linux host and were **not executed** on this Windows dev machine.
2. **On Docker Desktop, the decoy can reach host services (12 of 13 probed) and other compose networks by IP.**
   - Verified on 2026-11-01 (Windows 11, Docker Desktop) with plain TCP connects from inside the Cowrie container. That is what a process could do after compromising Cowrie; emulated shell commands cannot do this, because `out_addr` blocks them.
   - `host.docker.internal` (192.168.65.254) reached **12 of the 13 host TCP listeners probed, including ones bound to 127.0.0.1**. Only NetBIOS 139, bound to 192.168.56.1, refused. Reached:
     - RPC 135, SMB 445, mysqld 3307, svchost 5040, TeamViewer 5939
     - dev receiver 8088, Edge WebView debug 9222, mongod 27017
     - lsass RPC 49664, and others
   - The dev receiver on `soc-uplink` was reachable **by IP** (172.18.0.3:8088). Only its DNS name is hidden.
   - Mitigations in place:
     - The dev receiver requires a token (it returned 401 to the decoy).
     - No secrets exist in the decoy.
     - The real SOC backend **must** require a token.
   - Required for the demo:
     - **Do not run the honeypot on a laptop with personal or sensitive services.**
     - Use a Linux Docker Engine host with the INPUT and DOCKER-USER firewall rules in [deployment.md](deployment.md#host-firewall-honeypot-laptop-linux).
     - On Linux, containers cannot reach the host's 127.0.0.1 services, and the rules block new connections from the decoy bridge to the host and to other networks.
   - These Linux rules were **not executed** here: the dev machine is Windows/Docker Desktop, and changing its Docker VM firewall was out of scope.
3. **Exposure.**
   - Only publish on the team's private LAN or hotspot IP.
   - Never bind to `0.0.0.0` on a laptop that is also on another network (campus Wi-Fi, for example).
   - Allow only the lab subnet with a host firewall.
4. **Decoy fidelity.** Cowrie's emulation is detectable by a skilled attacker. For example, the `backup` user can read `/etc/shadow`, and `ip` is "not found". That is acceptable for a lab demo.
5. **Passwords tried are not recorded,** because attackers sometimes try real passwords from other systems. See "What is stored about attacker input" for what is kept and for the limits.
6. **Upstream image anonymous volumes.** The upstream Cowrie image declares `VOLUME`s for `etc` and `var`, so Docker creates anonymous volumes for them. They hold only Cowrie runtime state. Leave them in place: `down -v` can delete shared data.
