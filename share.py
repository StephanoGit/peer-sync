#!/usr/bin/env python3
"""
share — minimal local-network file & message sharing
stdlib only, no external dependencies.

Usage:
  share pair --listen          Wait for a peer to connect and pair with you
  share pair <ip>              Initiate pairing with a peer at <ip>
  share send <file> [peer]     Send a file to a peer
  share msg  <text> [peer]     Send a short message to a peer
  share daemon start           Start background listener (auto-receives everything)
  share daemon stop            Stop the background listener
  share daemon status          Check if the daemon is running
  share peers                  List all trusted peers

Design philosophy
─────────────────
• Optional self-backgrounding daemon.
  `share daemon start` forks the process into the background using os.fork()
  (POSIX only — works on macOS and Linux, not Windows).
  It writes its PID to ~/.config/share/daemon.pid so it can be stopped later.
  Logs go to ~/.config/share/daemon.log.

• Whitelist-only.
  The daemon only accepts connections from IPs that are in peers.json.
  Everything else is silently dropped. You must pair first.

• Fixed TCP port (PORT constant below).
  No mDNS/zeroconf to keep dependencies at zero.
  Peers are identified by name; their IP is stored at pairing time.

• One-shot connections.
  Each transfer opens a socket, does its work, and closes.
  The daemon loops back to accept() immediately after.

• Simple wire protocol.
  [4 bytes: big-endian length of header JSON]
  [N bytes: UTF-8 JSON header]
  [remaining bytes: raw file payload (empty for messages)]
"""

import argparse
import json
import os
import signal
import socket
import struct
import sys
from pathlib import Path
from datetime import datetime

# ── Configuration ─────────────────────────────────────────────────────────────

PORT       = 57890
INBOX      = Path.home() / "ShareInbox"
CONFIG_DIR = Path.home() / ".config" / "share"
PEERS_FILE = CONFIG_DIR / "peers.json"
PID_FILE   = CONFIG_DIR / "daemon.pid"
LOG_FILE   = CONFIG_DIR / "daemon.log"
CHUNK      = 65536   # bytes per read/write iteration
TIMEOUT    = 10      # socket timeout in seconds

# ── Peer store ────────────────────────────────────────────────────────────────
# Stored as { "alice": "192.168.1.42", ... } in a plain JSON file.

def load_peers() -> dict:
    if PEERS_FILE.exists():
        return json.loads(PEERS_FILE.read_text())
    return {}

def save_peers(peers: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    PEERS_FILE.write_text(json.dumps(peers, indent=2))

def pick_peer(peers: dict, hint: str | None) -> tuple[str, str]:
    """Return (name, ip) for the chosen peer, or exit with an error."""
    if not peers:
        die("No trusted peers yet. Run: share pair <ip>")

    if hint:
        if hint not in peers:
            die(f"Unknown peer '{hint}'. Known peers: {', '.join(peers)}")
        return hint, peers[hint]

    if len(peers) == 1:
        name, ip = next(iter(peers.items()))
        return name, ip

    print("Multiple peers available:")
    names = list(peers)
    for i, n in enumerate(names, 1):
        print(f"  {i}) {n}  ({peers[n]})")
    try:
        choice = int(input("Send to (number): ")) - 1
        name = names[choice]
        return name, peers[name]
    except (ValueError, IndexError):
        die("Invalid choice.")

# ── Wire protocol helpers ─────────────────────────────────────────────────────

def send_header(sock: socket.socket, header: dict):
    """Encode and send a length-prefixed JSON header."""
    data = json.dumps(header).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)

def recv_header(sock: socket.socket) -> dict:
    """Read and decode a length-prefixed JSON header."""
    raw_len = _recv_exactly(sock, 4)
    length  = struct.unpack(">I", raw_len)[0]
    return json.loads(_recv_exactly(sock, length))

def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes; raise on short read (connection dropped)."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        buf += chunk
    return buf

def my_name() -> str:
    """Use hostname as our identity — simple and requires nothing extra."""
    return socket.gethostname()

# ── Pairing ───────────────────────────────────────────────────────────────────
# Trust-on-first-use: both sides exchange hostnames over a raw TCP connection.
# No crypto — use a VPN if you need that on an untrusted network.

def cmd_pair_listen():
    """Wait for a peer to connect, exchange names, save them."""
    print(f"Waiting for a peer to connect on port {PORT} …  (Ctrl-C to cancel)")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("", PORT))
        srv.listen(1)
        conn, (peer_ip, _) = srv.accept()

    with conn:
        conn.settimeout(TIMEOUT)
        peer_name = _recv_exactly(conn, 256).rstrip(b"\x00").decode()
        conn.sendall(my_name().encode().ljust(256, b"\x00"))

    peers = load_peers()
    peers[peer_name] = peer_ip
    save_peers(peers)
    print(f"✓ Paired with '{peer_name}' ({peer_ip}).")

def cmd_pair_connect(ip: str):
    """Connect to a listening peer, exchange names, save them."""
    print(f"Connecting to {ip}:{PORT} …")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(TIMEOUT)
        try:
            s.connect((ip, PORT))
        except (ConnectionRefusedError, TimeoutError, OSError) as e:
            die(f"Could not connect to {ip}:{PORT} — {e}\nMake sure the other side runs: share pair --listen")

        s.sendall(my_name().encode().ljust(256, b"\x00"))
        peer_name = _recv_exactly(s, 256).rstrip(b"\x00").decode()

    peers = load_peers()
    peers[peer_name] = ip
    save_peers(peers)
    print(f"✓ Paired with '{peer_name}' ({ip}).")

# ── Send ──────────────────────────────────────────────────────────────────────

def cmd_send(filepath: str, peer_hint: str | None):
    path = Path(filepath)
    if not path.exists():
        die(f"File not found: {filepath}")

    peers = load_peers()
    name, ip = pick_peer(peers, peer_hint)
    size = path.stat().st_size
    print(f"Sending '{path.name}' ({_fmt_size(size)}) to {name} ({ip}) …")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(TIMEOUT)
        try:
            s.connect((ip, PORT))
        except (ConnectionRefusedError, TimeoutError, OSError) as e:
            die(f"Could not reach {name} ({ip}:{PORT}) — {e}\nIs their daemon running? share daemon status")

        send_header(s, {
            "type":     "file",
            "from":     my_name(),
            "filename": path.name,
            "size":     size,
        })

        sent = 0
        with path.open("rb") as f:
            while chunk := f.read(CHUNK):
                s.sendall(chunk)
                sent += len(chunk)
                _progress(sent, size)

    print(f"\n✓ Sent.")

def cmd_msg(text: str, peer_hint: str | None):
    peers = load_peers()
    name, ip = pick_peer(peers, peer_hint)
    print(f"Sending message to {name} ({ip}) …")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(TIMEOUT)
        try:
            s.connect((ip, PORT))
        except (ConnectionRefusedError, TimeoutError, OSError) as e:
            die(f"Could not reach {name} ({ip}:{PORT}) — {e}")

        send_header(s, {"type": "message", "from": my_name(), "text": text})

    print("✓ Sent.")

# ── Transfer handler (used by daemon loop) ────────────────────────────────────

def handle_transfer(conn: socket.socket, src_ip: str):
    """Process one incoming connection: save file or print message."""
    conn.settimeout(TIMEOUT)
    header = recv_header(conn)
    sender = header.get("from", src_ip)
    ts     = _ts()

    if header["type"] == "message":
        print(f"[{ts}] Message from {sender}: {header['text']}", flush=True)

    elif header["type"] == "file":
        INBOX.mkdir(parents=True, exist_ok=True)
        filename = Path(header["filename"]).name  # strip any path prefix for safety
        dest     = _unique_path(INBOX / filename)
        size     = header["size"]

        print(f"[{ts}] Receiving '{filename}' ({_fmt_size(size)}) from {sender} …", flush=True)

        received = 0
        with dest.open("wb") as f:
            while received < size:
                chunk = conn.recv(min(CHUNK, size - received))
                if not chunk:
                    break
                f.write(chunk)
                received += len(chunk)

        print(f"[{ts}] Saved to {dest}", flush=True)

    else:
        print(f"[{ts}] Unknown type '{header['type']}' from {src_ip} — ignored.", flush=True)

# ── Daemon ────────────────────────────────────────────────────────────────────
# How forking works here:
#   1. os.fork() splits the process. Parent gets child PID; child gets 0.
#   2. Parent saves child PID to daemon.pid, prints a message, exits.
#      The shell gets control back immediately — feels like a normal command.
#   3. Child calls os.setsid() → becomes session leader with no controlling
#      terminal, so it won't be killed when the terminal closes.
#   4. Child replaces stdin/stdout/stderr with /dev/null and the log file.
#   5. Child enters _daemon_loop() which accepts connections forever.

def cmd_daemon_start():
    if _daemon_pid() is not None:
        print("Daemon is already running. Use: share daemon status")
        return

    peers = load_peers()
    if not peers:
        die("No trusted peers yet — pair first so the daemon knows who to accept.")

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    pid = os.fork()

    if pid > 0:
        # ── Parent: save PID and return to shell ──
        PID_FILE.write_text(str(pid))
        print(f"✓ Daemon started (PID {pid}).")
        print(f"  Files will appear in: {INBOX}/")
        print(f"  Logs at:              {LOG_FILE}")
        return

    # ── Child: detach and loop ──
    os.setsid()

    devnull = open(os.devnull, "rb")
    logfile = open(LOG_FILE, "a")
    os.dup2(devnull.fileno(), sys.stdin.fileno())
    os.dup2(logfile.fileno(), sys.stdout.fileno())
    os.dup2(logfile.fileno(), sys.stderr.fileno())

    _daemon_loop()

def _daemon_loop():
    """
    Runs in the forked child forever.
    Opens one server socket and handles incoming transfers in sequence.
    Peers are reloaded on every connection so new pairings take effect
    without restarting the daemon.
    """
    print(f"[{_ts()}] Daemon started on port {PORT}", flush=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("", PORT))
        srv.listen(5)

        while True:
            try:
                conn, (src_ip, _) = srv.accept()
            except OSError:
                break  # socket closed, likely by SIGTERM

            # Reload whitelist every time — picks up pairs made after daemon started
            trusted_ips = set(load_peers().values())

            if src_ip not in trusted_ips:
                print(f"[{_ts()}] Rejected connection from untrusted {src_ip}", flush=True)
                conn.close()
                continue

            try:
                with conn:
                    handle_transfer(conn, src_ip)
            except Exception as e:
                print(f"[{_ts()}] Error from {src_ip}: {e}", flush=True)

    print(f"[{_ts()}] Daemon stopped.", flush=True)

def cmd_daemon_stop():
    pid = _daemon_pid()
    if pid is None:
        print("Daemon is not running.")
        return
    try:
        os.kill(pid, signal.SIGTERM)
        PID_FILE.unlink(missing_ok=True)
        print(f"✓ Daemon (PID {pid}) stopped.")
    except ProcessLookupError:
        PID_FILE.unlink(missing_ok=True)
        print("Daemon was not running (stale PID file cleaned up).")

def cmd_daemon_status():
    pid = _daemon_pid()
    if pid is None:
        print("Daemon is NOT running.")
        return
    try:
        os.kill(pid, 0)   # signal 0 = "does this process exist?" — sends nothing
        print(f"Daemon is running (PID {pid}).")
        print(f"  Log:   {LOG_FILE}")
        print(f"  Inbox: {INBOX}/")
    except ProcessLookupError:
        PID_FILE.unlink(missing_ok=True)
        print("Daemon is NOT running (stale PID file cleaned up).")

def _daemon_pid() -> int | None:
    """Return the PID from daemon.pid, or None if it doesn't exist."""
    if PID_FILE.exists():
        try:
            return int(PID_FILE.read_text().strip())
        except ValueError:
            return None
    return None

def _ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ── Peers list ────────────────────────────────────────────────────────────────

def cmd_peers():
    peers = load_peers()
    if not peers:
        print("No trusted peers. Run: share pair <ip>")
        return
    print("Trusted peers:")
    for name, ip in peers.items():
        print(f"  {name:<20} {ip}")

# ── Utilities ─────────────────────────────────────────────────────────────────

def die(msg: str):
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(1)

def _fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"

def _progress(done: int, total: int):
    if total == 0:
        return
    pct = done / total * 100
    bar = "#" * int(pct / 2)
    print(f"\r  [{bar:<50}] {pct:5.1f}%", end="", flush=True)

def _unique_path(p: Path) -> Path:
    """Append a counter if the file already exists, to avoid overwriting."""
    if not p.exists():
        return p
    stem, suffix = p.stem, p.suffix
    i = 1
    while True:
        candidate = p.with_name(f"{stem}_{i}{suffix}")
        if not candidate.exists():
            return candidate
        i += 1

# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="share",
        description="Minimal local-network file & message sharing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # One-time pairing
  share pair --listen          # machine A waits
  share pair 192.168.1.10      # machine B connects

  # Start always-on background receiver (once per machine)
  share daemon start
  share daemon status
  share daemon stop

  # Send any time — no action needed on the receiving side
  share send photo.jpg
  share send report.pdf alice  # specify peer if you have more than one
  share msg "dinner at 7?"

  share peers
""",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_pair = sub.add_parser("pair", help="Pair with a new peer")
    p_pair.add_argument("ip", nargs="?", help="IP of peer to connect to")
    p_pair.add_argument("--listen", action="store_true", help="Wait for peer to connect")

    p_send = sub.add_parser("send", help="Send a file")
    p_send.add_argument("file")
    p_send.add_argument("peer", nargs="?", help="Peer name (optional if only one peer)")

    p_msg = sub.add_parser("msg", help="Send a short message")
    p_msg.add_argument("text")
    p_msg.add_argument("peer", nargs="?")

    p_daemon = sub.add_parser("daemon", help="Manage the background receiver")
    p_daemon.add_argument("action", choices=["start", "stop", "status"])

    sub.add_parser("peers", help="List trusted peers")

    args = parser.parse_args()

    if args.cmd == "pair":
        if args.listen or not args.ip:
            cmd_pair_listen()
        else:
            cmd_pair_connect(args.ip)
    elif args.cmd == "send":
        cmd_send(args.file, args.peer)
    elif args.cmd == "msg":
        cmd_msg(args.text, args.peer)
    elif args.cmd == "daemon":
        if args.action == "start":
            cmd_daemon_start()
        elif args.action == "stop":
            cmd_daemon_stop()
        elif args.action == "status":
            cmd_daemon_status()
    elif args.cmd == "peers":
        cmd_peers()

if __name__ == "__main__":
    main()
