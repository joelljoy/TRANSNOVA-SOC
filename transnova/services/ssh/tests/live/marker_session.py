"""Real SSH traffic carrying fake marker secrets. Prints step names only, never values."""

from __future__ import annotations

import io
import json
import os
import time

import paramiko

HOST, PORT = "172.31.77.20", 2222
M = json.loads(os.environ["MARKERS"])
DECOY_PASSWORD = os.environ["DECOY_PASSWORD"]


def connect(user: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, port=PORT, username=user, password=password, look_for_keys=False,
                   allow_agent=False, timeout=10, banner_timeout=10, auth_timeout=10)
    return client


def step(name: str, action) -> None:
    try:
        action()
        print(f"ok {name}", flush=True)
    except Exception as exc:  # noqa: BLE001 - the type only: exception text could quote a marker
        print(f"FAILED {name} ({type(exc).__name__})", flush=True)


def rejected(user: str, password: str) -> None:
    try:
        connect(user, password).close()
    except paramiko.AuthenticationException:
        return
    raise RuntimeError("login unexpectedly accepted")


def type_lines(chan: paramiko.Channel, *lines: tuple[str, float]) -> None:
    for text, pause in lines:
        chan.send((text + "\n").encode())
        time.sleep(pause)
        while chan.recv_ready():
            chan.recv(65536)


def shell(client: paramiko.SSHClient) -> paramiko.Channel:
    chan = client.get_transport().open_session()
    chan.get_pty(term="xterm", width=120, height=40)
    chan.update_environment({"DB_SECRET": M["env"], "LANG": "C.UTF-8"})
    chan.invoke_shell()
    chan.settimeout(5)
    time.sleep(1)
    return chan


def run_form(client: paramiko.SSHClient, form: str) -> None:
    chan = client.get_transport().open_session()
    try:
        chan.exec_command(form)
    except paramiko.SSHException:
        return  # Cowrie closes at once for a program that does not exist; the command was received
    deadline = time.monotonic() + 1.2
    while time.monotonic() < deadline and not chan.exit_status_ready():
        time.sleep(0.05)
    chan.close()


def run_forms(forms: list[str]) -> None:
    """Each form gets its own connection: some leave a fake program holding the session."""
    sent = 0
    for form in forms:
        client = connect("backup", DECOY_PASSWORD)
        try:
            run_form(client, form)
            sent += 1
        finally:
            client.close()
    print(f"forms sent: {sent} of {len(forms)}", flush=True)
    if sent != len(forms):
        raise RuntimeError("not every form was sent")


def piped_exec(client: paramiko.SSHClient) -> None:
    chan = client.get_transport().open_session()
    chan.exec_command("cat > /tmp/exec-input")
    chan.sendall(M["exec_stdin"].encode())
    chan.shutdown_write()
    time.sleep(1)
    chan.close()


def upload(client: paramiko.SSHClient) -> None:
    sftp = client.open_sftp()
    sftp.putfo(io.BytesIO(("content " + M["sftp"] + "\n").encode()), "/tmp/upload-a.bin")
    sftp.putfo(io.BytesIO(b"second upload\n"), f"/tmp/{M['sftp_name']}.txt")
    sftp.close()


def main() -> None:
    step("login password", lambda: rejected("root", M["login"]))
    step("username ordinary word", lambda: rejected(M["user_word"], "wrong"))
    step("username random", lambda: rejected(M["user_random"], "wrong"))
    client = connect("backup", DECOY_PASSWORD)
    print("ok decoy login", flush=True)
    chan = shell(client)
    print("ok shell with environment variables", flush=True)
    step("passwd prompt", lambda: type_lines(chan, ("passwd", 0.7), (M["passwd"], 0.5), (M["passwd"], 0.7)))
    step("su prompt", lambda: type_lines(chan, ("su root", 0.7), (M["su"], 0.8), ("exit", 0.7)))
    # The fake ssh login returns to this same shell, so no `exit` here.
    step("ssh prompt", lambda: type_lines(chan, ("ssh root@10.0.0.9", 0.7), ("yes", 0.7), (M["ssh"], 3.5)))
    step("redirected output", lambda: type_lines(chan, (f"echo {M['redirect']} > /tmp/redir-a", 0.7)))
    step("typed stdin to cat", lambda: type_lines(chan, ("cat > /tmp/redir-b", 0.5), (M["stdin_cat"], 0.5), ("\x04", 0.7)))
    step("typed stdin to tee", lambda: type_lines(chan, ("tee /tmp/redir-c", 0.5), (M["stdin_tee"], 0.5), ("\x04", 0.7)))
    step("pipe", lambda: type_lines(chan, (f"echo {M['pipe']} | cat > /tmp/redir-d", 0.7)))
    step("control value", lambda: type_lines(chan, (f"cat /var/backups/db/{M['control']}", 0.7), ("exit", 0.5)))
    chan.close()
    step("exec channel stdin", lambda: piped_exec(client))
    step("sftp upload", lambda: upload(client))
    client.close()
    step(f"{len(M['forms'])} command forms", lambda: run_forms(M["forms"]))


if __name__ == "__main__":
    main()
