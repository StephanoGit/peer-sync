"""
Daemon lifecycle and connection-accept loop for `share`.
"""

from __future__ import annotations

import os
import signal
import socket
import sys
import threading
from typing import Optional

from . import config, peers, protocol


def _daemon_pid() -> Optional[int]:
    """
    Return the PID from the daemon PID file, or None if it is missing/invalid.
    """
    if config.PID_FILE.exists():
        try:
            return int(config.PID_FILE.read_text().strip())
        except ValueError:
            return None
    return None


def cmd_daemon_start() -> None:
    """
    Start the background daemon process.

    The daemon:
    - Accepts incoming connections on `config.PORT`.
    - Only serves connections from IPs present in `peers.json`.
    - Writes logs to `config.LOG_FILE`.
    """
    if _daemon_pid() is not None:
        print("Daemon is already running. Use: share daemon status")
        return

    if not peers.load_peers():
        raise SystemExit(
            "No trusted peers yet — pair first so the daemon knows who to accept."
        )

    config.CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    pid = os.fork()

    if pid > 0:
        # Parent: save PID and return to the shell.
        config.PID_FILE.write_text(str(pid))
        print(f"✓ Daemon started (PID {pid}).")
        print(f"  Files will appear in: {config.INBOX}/")
        print(f"  Logs at:              {config.LOG_FILE}")
        return

    # Child: detach and run the accept loop.
    os.setsid()

    devnull = open(os.devnull, "rb")
    logfile = open(config.LOG_FILE, "a")
    os.dup2(devnull.fileno(), sys.stdin.fileno())
    os.dup2(logfile.fileno(), sys.stdout.fileno())
    os.dup2(logfile.fileno(), sys.stderr.fileno())

    _daemon_loop()


def _daemon_loop() -> None:
    """
    Blocking accept loop for the background daemon.

    This function runs in the forked child process. It accepts incoming
    TCP connections, checks the connecting IP against the trusted peers,
    and then hands off each connection to a worker thread that calls
    `protocol.handle_transfer`.
    """
    print(f"[{protocol.ts()}] Daemon started on port {config.PORT}", flush=True)

    def _handle_client(conn: socket.socket, src_ip: str) -> None:
        """
        Handle a single client connection in a worker thread.
        """
        try:
            trusted_ips = set(peers.load_peers().values())
            if src_ip not in trusted_ips:
                print(
                    f"[{protocol.ts()}] Rejected connection from untrusted {src_ip}",
                    flush=True,
                )
                conn.close()
                return

            with conn:
                protocol.handle_transfer(conn, src_ip)
        except Exception as exc:  # pragma: no cover - defensive
            print(f"[{protocol.ts()}] Error from {src_ip}: {exc}", flush=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("", config.PORT))
        srv.listen(5)

        while True:
            try:
                conn, (src_ip, _) = srv.accept()
            except OSError:
                break  # socket closed, likely due to SIGTERM

            t = threading.Thread(target=_handle_client, args=(conn, src_ip), daemon=True)
            t.start()

    print(f"[{protocol.ts()}] Daemon stopped.", flush=True)


def cmd_daemon_stop() -> None:
    """
    Stop the background daemon if it is running.
    """
    pid = _daemon_pid()
    if pid is None:
        print("Daemon is not running.")
        return
    try:
        os.kill(pid, signal.SIGTERM)
        config.PID_FILE.unlink(missing_ok=True)
        print(f"✓ Daemon (PID {pid}) stopped.")
    except ProcessLookupError:
        config.PID_FILE.unlink(missing_ok=True)
        print("Daemon was not running (stale PID file cleaned up).")


def cmd_daemon_status() -> None:
    """
    Print a human-readable status line about the daemon process.
    """
    pid = _daemon_pid()
    if pid is None:
        print("Daemon is NOT running.")
        return
    try:
        # Signal 0 only checks for existence / permission, sends nothing.
        os.kill(pid, 0)
        print(f"Daemon is running (PID {pid}).")
        print(f"  Log:   {config.LOG_FILE}")
        print(f"  Inbox: {config.INBOX}/")
    except ProcessLookupError:
        config.PID_FILE.unlink(missing_ok=True)
        print("Daemon is NOT running (stale PID file cleaned up).")

