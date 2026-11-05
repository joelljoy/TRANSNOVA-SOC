"""Command line entry point: `cowrie-soc <command>`.

  run           follow Cowrie's log continuously and deliver records (service mode)
  replay        process Cowrie JSON log file(s) once and print records as JSONL
  status        show checkpoint, outbox, sink, quarantine and dead-letter state
  validate      check a JSONL file of records against the output contract
  dev-receiver  start the LOCAL DEVELOPMENT receiver (not the SOC backend)
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

from cowrie_soc.config import ConfigError, load_config
from cowrie_soc.parser import ParseError, RawLine
from cowrie_soc.schema import validate_record


def _read_file_lines(path: Path) -> Iterator[RawLine]:
    offset = 0
    with path.open("rb") as fh:
        for line in fh:
            yield RawLine(line.rstrip(b"\r\n"), path.name, offset, unterminated=not line.endswith(b"\n"))
            offset += len(line)


def cmd_run(args: argparse.Namespace) -> int:
    from cowrie_soc.pipeline import Pipeline

    cfg = load_config(args.config)
    pipeline = Pipeline(cfg)
    signal.signal(signal.SIGTERM, lambda *_: pipeline.stop())
    signal.signal(signal.SIGINT, lambda *_: pipeline.stop())
    pipeline.run_forever()
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    from cowrie_soc.pipeline import replay

    cfg = load_config(args.config)
    if args.sensor_id:
        cfg.collector.sensor_id = args.sensor_id
    out = sys.stdout if args.output == "-" else open(args.output, "w", encoding="utf-8")  # noqa: SIM115
    counts: Counter[str] = Counter()
    try:
        for path in args.files:
            for item in replay(_read_file_lines(Path(path)), cfg):
                if isinstance(item, ParseError):
                    counts["quarantined"] += 1
                    print(f"QUARANTINED {item.source}@{item.offset}: {item.reason}", file=sys.stderr)
                    continue
                counts[item["record_type"]] += 1
                if args.findings_only and item["record_type"] != "finding":
                    continue
                if args.summary:
                    if item["record_type"] == "finding":
                        techs = ",".join(t["technique_id"] for t in item["attack"])
                        out.write(f"{item['severity'].upper():8} {item['rule_id']:14} {item['title']}  [{techs}]\n")
                    continue
                out.write(json.dumps(item, ensure_ascii=False) + "\n")
    finally:
        if out is not sys.stdout:
            out.close()
    print(f"replay: {dict(counts)}", file=sys.stderr)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    from cowrie_soc.store import Store

    cfg = load_config(args.config)
    store = Store(cfg.collector.state_db)
    status = store.status()
    status["recent_quarantine"] = store.quarantine_rows(args.quarantine)
    print(json.dumps(status, indent=2))
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    bad = total = 0
    with open(args.file, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            total += 1
            try:
                problems = validate_record(json.loads(line))
            except json.JSONDecodeError as exc:
                problems = [f"invalid JSON: {exc}"]
            if problems:
                bad += 1
                print(f"line {n}: {'; '.join(problems)}")
    print(f"validate: {total - bad}/{total} records valid")
    return 1 if bad else 0


def _raise_keyboard_interrupt(*_: object) -> None:
    raise KeyboardInterrupt


def cmd_dev_receiver(args: argparse.Namespace) -> int:
    from cowrie_soc.devreceiver import BANNER, ReceiverConfigError, serve

    try:
        server = serve(args.host, args.port, args.out, args.token_env)
    except ReceiverConfigError as exc:
        print(f"dev-receiver refused to start: {exc}", file=sys.stderr)
        return 2
    auth = f"token required (${args.token_env})" if args.token_env else "NO AUTH"
    print(f"*** {BANNER} ***\nlistening on http://{args.host}:{args.port}/ingest ({auth}), writing {args.out}",
          flush=True)
    signal.signal(signal.SIGTERM, _raise_keyboard_interrupt)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cowrie-soc", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="follow Cowrie logs continuously")
    run.add_argument("--config", required=True)
    run.set_defaults(func=cmd_run)

    rp = sub.add_parser("replay", help="process Cowrie JSON log files once")
    rp.add_argument("files", nargs="+")
    rp.add_argument("--config", help="collector TOML (detection thresholds, honeytokens)")
    rp.add_argument("--sensor-id")
    rp.add_argument("--output", default="-", help="output JSONL path (default stdout)")
    rp.add_argument("--findings-only", action="store_true")
    rp.add_argument("--summary", action="store_true", help="print one line per finding instead of JSON")
    rp.set_defaults(func=cmd_replay)

    st = sub.add_parser("status", help="show collector state")
    st.add_argument("--config", required=True)
    st.add_argument("--quarantine", type=int, default=5, help="recent quarantined lines to show")
    st.set_defaults(func=cmd_status)

    va = sub.add_parser("validate", help="validate a JSONL file of output records")
    va.add_argument("file")
    va.set_defaults(func=cmd_validate)

    dr = sub.add_parser("dev-receiver", help="LOCAL DEV receiver (not the SOC backend)")
    dr.add_argument("--host", default="127.0.0.1")
    dr.add_argument("--port", type=int, default=8088)
    dr.add_argument("--out", default="dev-received.jsonl")
    dr.add_argument("--token-env", help="require 'Bearer $TOKEN_ENV' on POST")
    dr.set_defaults(func=cmd_dev_receiver)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        return int(args.func(args))
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
