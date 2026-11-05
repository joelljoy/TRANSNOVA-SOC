from __future__ import annotations

from pathlib import Path

from cowrie_soc.store import Checkpoint
from cowrie_soc.tailer import LogFollower, fingerprint

from .conftest import cowrie_line

L = [cowrie_line("cowrie.session.connect", f"s{i:011d}", at=i) for i in range(10)]


def write(path: Path, *lines: str, newline: bool = True) -> None:
    with path.open("ab") as fh:
        for i, line in enumerate(lines):
            fh.write(line.encode() + (b"\n" if newline or i < len(lines) - 1 else b""))


def drain(f: LogFollower, cp: Checkpoint | None, max_lines: int = 500) -> tuple[list[bytes], Checkpoint | None, list[str]]:
    out: list[bytes] = []
    notices: list[str] = []
    for _ in range(20):
        r = f.poll(cp, max_lines)
        notices += r.notices
        out += [ln.data for ln in r.lines]
        if not r.lines and r.checkpoint == cp:
            break
        cp = r.checkpoint
    return out, cp, notices


def test_waits_for_file_and_first_line(tmp_path: Path) -> None:
    f = LogFollower(tmp_path)
    assert f.poll(None).checkpoint is None
    write(tmp_path / "cowrie.json", L[0][:20], newline=False)
    assert f.poll(None).checkpoint is None
    assert fingerprint(tmp_path / "cowrie.json") is None


def test_partial_line_is_not_consumed_until_complete(tmp_path: Path) -> None:
    log = tmp_path / "cowrie.json"
    write(log, L[0], L[1][:30], newline=False)
    f = LogFollower(tmp_path)
    lines, cp, _ = drain(f, None)
    assert lines == [L[0].encode()]
    with log.open("ab") as fh:
        fh.write(L[1][30:].encode() + b"\n")
    more, cp2, _ = drain(f, cp)
    assert more == [L[1].encode()]
    assert cp2 is not None and cp2.offset == log.stat().st_size


def test_offsets_point_at_line_starts(tmp_path: Path) -> None:
    write(tmp_path / "cowrie.json", *L[:3])
    r = LogFollower(tmp_path).poll(None)
    assert [ln.offset for ln in r.lines] == [0, len(L[0]) + 1, len(L[0]) + len(L[1]) + 2]


def test_resume_from_checkpoint_no_duplicates(tmp_path: Path) -> None:
    log = tmp_path / "cowrie.json"
    write(log, *L[:3])
    f = LogFollower(tmp_path)
    first, cp, _ = drain(f, None)
    write(log, *L[3:5])
    # A fresh follower (collector restart) resumes from the stored checkpoint.
    second, _, _ = drain(LogFollower(tmp_path), cp)
    assert first + second == [x.encode() for x in L[:5]]


def test_rotation_drains_old_file_then_follows_new(tmp_path: Path) -> None:
    log = tmp_path / "cowrie.json"
    write(log, *L[:3])
    f = LogFollower(tmp_path)
    got, cp, _ = drain(f, None)
    write(log, L[3])                          # written just before rotation, not yet read
    log.rename(tmp_path / "cowrie.json.2026-10-31")
    write(log, L[4], L[5])                    # Cowrie opens a new cowrie.json
    more, cp, notices = drain(f, cp)
    assert got + more == [x.encode() for x in L[:6]]
    assert cp is not None and cp.file == "cowrie.json"
    assert any("finished rotated file" in n for n in notices)


def test_rotation_before_new_file_exists(tmp_path: Path) -> None:
    log = tmp_path / "cowrie.json"
    write(log, *L[:2])
    f = LogFollower(tmp_path)
    _, cp, _ = drain(f, None)
    write(log, L[2])
    log.rename(tmp_path / "cowrie.json.2026-10-31")
    more, cp, _ = drain(f, cp)
    assert more == [L[2].encode()]
    write(log, L[3])
    later, _, _ = drain(f, cp)
    assert later == [L[3].encode()]


def test_rotated_file_with_unterminated_tail_is_flushed(tmp_path: Path) -> None:
    log = tmp_path / "cowrie.json"
    write(log, L[0])
    f = LogFollower(tmp_path)
    _, cp, _ = drain(f, None)
    write(log, '{"broken', newline=False)
    log.rename(tmp_path / "cowrie.json.2026-10-31")
    write(log, L[1])
    r1 = f.poll(cp)
    assert [ln.unterminated for ln in r1.lines] == [True]
    rest, _, _ = drain(f, r1.checkpoint)
    assert rest == [L[1].encode()]


def test_truncation_is_reported(tmp_path: Path) -> None:
    log = tmp_path / "cowrie.json"
    write(log, *L[:3])
    f = LogFollower(tmp_path)
    _, cp, _ = drain(f, None)
    log.write_bytes(b"")
    write(log, L[0])  # same first line -> same fingerprint, but shorter
    more, _, notices = drain(f, cp)
    assert more == [L[0].encode()]
    assert any("truncated" in n for n in notices)


def test_missing_checkpoint_file_is_reported_not_silent(tmp_path: Path) -> None:
    log = tmp_path / "cowrie.json"
    write(log, L[0])
    f = LogFollower(tmp_path)
    _, cp, _ = drain(f, None)
    log.unlink()
    write(log, L[5])
    more, _, notices = drain(f, cp)
    assert more == [L[5].encode()]
    assert any("POSSIBLE DATA LOSS" in n for n in notices)


def test_start_at_end_skips_history(tmp_path: Path) -> None:
    log = tmp_path / "cowrie.json"
    write(log, *L[:3])
    f = LogFollower(tmp_path, start_at_end=True)
    lines, cp, _ = drain(f, None)
    assert lines == []
    write(log, L[3])
    more, _, _ = drain(f, cp)
    assert more == [L[3].encode()]


def test_oversized_line_is_flagged_and_skipped(tmp_path: Path) -> None:
    log = tmp_path / "cowrie.json"
    write(log, L[0], "x" * 5000, L[1])
    f = LogFollower(tmp_path, max_line_bytes=1024)
    r = f.poll(None)
    assert [ln.oversized for ln in r.lines] == [False, True, False]
    assert r.lines[2].data == L[1].encode()


def test_batch_limit(tmp_path: Path) -> None:
    write(tmp_path / "cowrie.json", *L)
    f = LogFollower(tmp_path)
    r = f.poll(None, max_lines=4)
    assert len(r.lines) == 4
    rest, _, _ = drain(f, r.checkpoint, max_lines=4)
    assert len(rest) == 6


def test_rotated_file_with_oversized_unterminated_tail_is_not_silently_skipped(tmp_path: Path) -> None:
    log = tmp_path / "cowrie.json"
    write(log, L[0])
    f = LogFollower(tmp_path, max_line_bytes=1024)
    _, cp, _ = drain(f, None)
    write(log, "y" * 5000, newline=False)
    log.rename(tmp_path / "cowrie.json.2026-10-31")
    write(log, L[1])
    r1 = f.poll(cp)
    assert [(ln.oversized, ln.unterminated) for ln in r1.lines] == [(True, True)]
    rest, _, _ = drain(f, r1.checkpoint)
    assert rest == [L[1].encode()]
