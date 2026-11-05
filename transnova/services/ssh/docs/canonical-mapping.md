# SSH to shared SOC event mapping

`sensor/src/cowrie_soc/canonical.py` turns clean SSH records into `CanonicalEvent` (`collector/schema.py`). `tests/integration/test_collector_contract.py` checks it against that real model.

**Status: not integrated.** Delivery is off (`enabled = false`) and nothing has been sent to a live collector.

## How events reach the SOC

```text
Cowrie line -> clean -> normalize -> detect -> outbox + normalized.jsonl (local evidence)
                                       |
                                   translate -> validate -> soc_outbox -> collector
                                                   |
                                               soc_skipped (safe ID and fixed reason only)
```

- `soc_outbox` holds only validated canonical events. The local `outbox` is never sent.
- Translation starts only when delivery is enabled, so earlier records are never queued.
- Each record is cleaned again here, so an older or tampered record cannot pass raw text through.
- A skipped record keeps its `event_id` if that is a strict UUID, otherwise `sha256:<line hash>`, plus one fixed reason: `bad_record`, `bad_event_id`, `bad_timestamp`, `bad_sensor_id`, `bad_session`, `translator_error`, `failed_validation`, `oversized` or `queue_full`.

## Event mapping

| Cowrie event | `event_type` | `action` | `outcome` |
|---|---|---|---|
| `session.connect` | `connection` | `ssh_connect` | `observed` |
| `session.closed` | `connection` | `ssh_disconnect` | `observed` |
| `client.version` | `connection` | `ssh_client_version` | `observed` |
| `client.kex` | `connection` | `ssh_client_kex` | `observed` |
| `client.size` | `connection` | `ssh_terminal_size` | `observed` |
| `client.var` | `connection` | `ssh_client_env` | `observed` |
| `session.params` | `connection` | `ssh_session_params` | `observed` |
| `client.fingerprint` | `authentication` | `ssh_publickey_offered` | `observed` |
| `login.failed` | `authentication` | `ssh_login` | `failed` |
| `login.success` | `authentication` | `ssh_login` | `succeeded` |
| `command.input` | `command` | `shell_command` | `observed` |
| `command.failed` | `command` | `shell_command_not_found` | `failed` |
| `command.success`, `session.input` | `command` | `typed_input_hidden` | `observed` |
| `command.chpasswd` | `command` | `password_change_attempt` | `observed` |
| `session.file_download` | `file_transfer` | `file_download` | `observed` |
| The same event for piped or redirected input | `file_transfer` | `input_captured` | `observed` |
| `session.file_download.failed` | `file_transfer` | `file_download` | `failed` |
| `session.file_upload` | `file_transfer` | `file_upload` | `observed` |
| Anything else | `connection` | `cowrie_other` | `observed` |

## Evidence for outcomes

Source paths are inside the pinned Cowrie image, under `src/cowrie/`.

| Event | What the source shows | Outcome |
|---|---|---|
| SFTP upload (`shell/fs.py:532-553`) | Fired when a file closes. In a live test, 30 uploads of 900 KB were all reported with only 16 MB of space, so it does not prove the content was stored | `observed` |
| SCP upload (`commands/scp.py:96-120`) | Same event type, so the same limit applies | `observed` |
| Download with a URL (`core/download.py:164-194`, `commands/tftp.py:460-476`, `commands/ftpget.py:343-360`) | Cowrie calls it completed, but `out_addr` blocks real transfers, and none has been seen live | `observed` |
| `Saved stdin`, `Saved redir` (`insults/insults.py:195-241`) | Input was captured. This is not a transfer | `observed` |
| `session.file_download.failed` (`core/download.py:197-207`) | The source says the download never completed | `failed` |
| `login.success`, `login.failed` (`core/checkers.py:160-176`) | The real result of the password check | `succeeded`, `failed` |
| `command.failed` (`shell/honeypot.py:1191`) | The program was not found | `failed` |

No file transfer is marked `succeeded`.

## Identity and source address

| Field | Value |
|---|---|
| `sensor_id` | Must be exactly `ssh-01`. Anything else is skipped |
| `service`, `destination_service` | `ssh`, `ssh-honeypot` |
| `session_id` | Cowrie's session ID, which must be hexadecimal |
| `campaign_id` | Always null |
| `source_ip` | The real address, validated, with no alias |
| `source_ip` when missing or invalid | `unknown-ssh-<session_id>` |

**Why not `unknown`:** the collector groups and correlates on this exact string, and the database sensor already sends `unknown`. A test shows that sharing that word raises a false `X-CORR-01`. A session label keeps one session together, and never links it to anything else.

Separate demo attackers have different addresses, so `X-CORR-01` does not link SSH with Database or Web activity. That is the correct result for this design.

## Detections

`label`, `category`, `rationale` and `attack_stage` come from a fixed table per rule. Severity and confidence must be exact allowed values, IDs must be strict UUIDs, and technique names come from the sensor's own catalogue by ID. Finding titles, explanations, observed values and event messages are never read.

The only cleaned attacker-derived text in an event is `command`, `username`, `file_name` and fields inside `raw_evidence_redacted`. The limits in [safety-and-isolation.md](safety-and-isolation.md#what-is-stored-about-attacker-input) apply, for example `cat maple7` keeps the word.

## Validation

The collector accepts more than its schema suggests: an empty `event_id`, a port of `"22"`, `True` or `70000`, or a number as `timestamp`. `validate()` is stricter on purpose, and tests prove it rejects everything the real model rejects. Extra checks: strict UUID and timestamp, ports 0 to 65535, unused fields must be null or empty, and evidence at most 8 KiB.

## Delivery behaviour

| Situation | Attempts | State | What happens |
|---|---|---|---|
| Network error, timeout, 408, 425, 429, 500, 502, 503, 504 | Keeps trying, delay doubling from 1 s to at most 60 s | `retrying` | Recovers by itself. At most one try a minute once at the cap |
| 401, 403 | 3, then stops | `unauthorized` | Needs a person |
| Token file missing, empty or unusable | 3, then stops | `token_unavailable` | Needs a person |
| 3xx | 1 | `misconfigured` | Needs a person |
| Any other 4xx, or an event failing the last check before sending | 1 | `rejected` | Needs a person |

- Events stay queued in every state. The SOC route never dead-letters or discards.
- A stopped state makes no more requests. Fix the cause, then restart `ssh-sensor`.
- Only status codes are kept, never bodies, headers or tokens.
- `cowrie-soc status` shows the state, attempts, last status, queue size and skip counts.
- If `soc_outbox` reaches `max_soc_pending`, new events are skipped as `queue_full`, and local logging carries on.

## What the collector requires

The collector checks this itself and does not rely on the sensor. The code is in `collector/ssh_ingest.py`. Nothing here is deployed until Stage 5.

| Setting | Holds | If unset or unusable |
|---|---|---|
| `SSH_INGEST_TOKEN_FILE` | File with the SSH write token | SSH gets `503`; Web and Database are unaffected |
| `SOC_READ_TOKEN_FILE` | File with the dashboard's read token | SSH gets `503`, so SSH data cannot arrive while reads are open |
| `SSH_SENSOR_PEER` | Optional sensor address | Unset does nothing. Set, the token works only from that address, and that address can only use the two POST routes |

A request claims SSH if any item has `service` of `ssh`, a `sensor_id` starting `ssh` or `cowrie`, a `destination_service` containing `ssh-honeypot`, a tag starting `ssh`, or a detection `rule` or `label` starting `ssh`. Values are compared after Unicode normalization, ignoring case and punctuation. Look-alike letters from other alphabets are not caught.

| Situation | Response | Sensor state |
|---|---|---|
| Valid token, every event passes | `200` | Delivered |
| Claim with a missing or wrong token | `401`, same body | `unauthorized` |
| Valid token with any non-SSH item | `403`, nothing stored | `unauthorized` |
| Any adaptation claiming SSH, even with a token | `403` | Not used by the sensor |
| Any event fails a strict check | `422`, whole batch refused | `rejected` |
| A token file unusable, or both tokens identical | `503` | `retrying` |
| Body over 1 MiB (anything with `Authorization`) | `413` | `rejected` |

The header must be exactly one `Authorization: Bearer <token>`. Two headers are refused even if one is correct. Tokens are read on each request, so a new token works without a restart.

Strict checks: identity exactly `ssh-01`, `ssh`, `ssh-honeypot`; strict UUID and timestamp; hex session; an IP or `unknown-ssh-<this event's session>`; port 0 to 65535 or null; unused fields null or empty; `ssh:` tags; evidence at most 8 KiB and 16 levels deep with `honeypot_type: ssh`; no `password`, `message`, `format` or `ttylog` key at any depth, apart from `raw.format`; known rules with exact labels, allowed keys and bounded text.

`unknown-ssh-<session>` is not a claim on its own, because a forged audit line can put it on a Database event and a refusal would stall that sender. The collector instead never correlates a source with that prefix.

Alerts for SSH rules use fixed titles and actions from `collector/detections.py`, and link the finding's evidence event IDs, up to the existing limit of 200.

## Not yet done

SSH has no risk score. Delivery stays off until the Stage 5 gates pass.
