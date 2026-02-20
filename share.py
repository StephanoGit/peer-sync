#!/usr/bin/env python3
"""
share — minimal local-network file & message sharing
stdlib only, no external dependencies.

Usage:
  share pair --listen          Wait for a peer to connect and pair with you
  share pair <ip>              Initiate pairing with a peer at <ip>
  share send <file> [peer]     Send a file to a peer
  share msg  <text> [peer]     Send a short message to a peer
  share recv                   Wait for ONE incoming transfer, then exit
  share peers                  List all trusted peers

Design philosophy
─────────────────
• No daemon / background process.
  The receiver manually runs `share recv` when they want to accept something.
  This avoids systemd/launchd complexity and keeps the tool auditable.

• Whitelist-only.
  You must explicitly pair before any transfer is accepted.
  Peers are stored in ~/.config/share/peers.json.

• Fixed TCP port (PORT constant below).
  mDNS/zeroconf discovery was deliberately left out to avoid dependencies.
  You identify peers by the name you give them at pairing time; their IP is
  remembered. If a peer's IP changes (DHCP), just re-pair.

• One-shot connections.
  Each send/recv opens a socket, does its work, and closes.
  No keep-alive, no multiplexing — easier to reason about.

• Simple wire protocol.
  [4 bytes: big-endian length of header JSON]
  [N bytes: UTF-8 JSON header]
  [remaining bytes: raw file payload (empty for messages)]
  The header carries type, sender name, filename, and file size.
"""

import argparse
import json
import os
import socket
import struct
import sys
from pathlib import Path
from datetime import datetime

# ── Configuration ─────────────────────────────────────────────────────────────

PORT        = 57890          # arbitrary unprivileged port; change if it collides
INBOX       = Path.home() / "ShareInbox"
CONFIG_DIR  = Path.home() / ".config" / "share"
PEERS_FILE  = CONFIG_DIR / "peers.json"
CHUNK       = 65536          # bytes to read/write per loop iteration
TIMEOUT     = 10             # socket timeout in seconds

# ── Peer store ────────────────────────────────────────────────────────────────
# Peers are stored as { "alice": "192.168.1.42", ... }
# We use a plain dict serialised to JSON — no database needed at this scale.

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

    # Multiple peers — let the user choose
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
    """Read exactly n bytes from the socket, raising on short read."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        buf += chunk
    return buf

def my_name() -> str:
    """Use the machine hostname as our identity (good enough for LAN use)."""
    return socket.gethostname()

# ── Pairing ───────────────────────────────────────────────────────────────────
# Pairing is a two-step mutual exchange:
#   1. Both sides send their name.
#   2. Both sides receive the other's name.
#   3. Each side saves (name -> ip) in its peer store.
#
# No crypto / certificates — this is a trust-on-first-use model for a LAN.
# If you need security, put it on a VPN or add TLS later.

def cmd_pair_listen():
    """Wait for a peer to connect, exchange names, save them."""
    print(f"Waiting for a peer to connect on port {PORT} …  (Ctrl-C to cancel)")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        # SO_REUSEADDR lets us restart quickly without waiting for TIME_WAIT
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("", PORT))
        srv.listen(1)
        conn, (peer_ip, _) = srv.accept()

    with conn:
        conn.settimeout(TIMEOUT)
        # Exchange names — initiator sends first, listener responds
        peer_name_raw = _recv_exactly(conn, 256).rstrip(b"\x00").decode()
        conn.sendall(my_name().encode().ljust(256, b"\x00"))

    peers = load_peers()
    peers[peer_name_raw] = peer_ip
    save_peers(peers)
    print(f"✓ Paired with '{peer_name_raw}' ({peer_ip}). They can now send you files.")

def cmd_pair_connect(ip: str):
    """Connect to a listening peer, exchange names, save them."""
    print(f"Connecting to {ip}:{PORT} …")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(TIMEOUT)
        try:
            s.connect((ip, PORT))
        except (ConnectionRefusedError, TimeoutError):
            die(f"Could not connect to {ip}:{PORT}. Make sure the other side runs: share pair --listen")

        s.sendall(my_name().encode().ljust(256, b"\x00"))
        peer_name_raw = _recv_exactly(s, 256).rstrip(b"\x00").decode()

    peers = load_peers()
    peers[peer_name_raw] = ip
    save_peers(peers)
    print(f"✓ Paired with '{peer_name_raw}' ({ip}). You can now send them files.")

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
        except (ConnectionRefusedError, TimeoutError):
            die(f"Could not reach {name} ({ip}:{PORT}). Ask them to run: share recv")

        # Send header first so the receiver knows what's coming
        send_header(s, {
            "type":     "file",
            "from":     my_name(),
            "filename": path.name,
            "size":     size,
        })

        # Stream the file in chunks to handle large files without loading into RAM
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
        except (ConnectionRefusedError, TimeoutError):
            die(f"Could not reach {name} ({ip}:{PORT}). Ask them to run: share recv")

        send_header(s, {
            "type": "message",
            "from": my_name(),
            "text": text,
        })

    print("✓ Sent.")

# ── Receive ───────────────────────────────────────────────────────────────────

def cmd_recv():
    """
    Listen for exactly one incoming transfer, handle it, then exit.
    We accept only connections whose source IP is in our peer whitelist.
    """
    peers = load_peers()
    if not peers:
        die("No trusted peers yet. Run: share pair  first.")

    trusted_ips = set(peers.values())
    INBOX.mkdir(parents=True, exist_ok=True)

    print(f"Waiting for one incoming transfer on port {PORT} …  (Ctrl-C to cancel)")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("", PORT))
        srv.listen(1)

        # Keep trying until we get a trusted connection
        while True:
            conn, (src_ip, _) = srv.accept()
            if src_ip in trusted_ips:
                break
            # Reject and log untrusted sources
            conn.close()
            print(f"  [ignored] Connection from untrusted IP {src_ip}")

    with conn:
        conn.settimeout(TIMEOUT)
        header = recv_header(conn)

        sender = header.get("from", src_ip)

        if header["type"] == "message":
            ts = datetime.now().strftime("%H:%M")
            print(f"\n[{ts}] Message from {sender}:")
            print(f"  {header['text']}\n")

        elif header["type"] == "file":
            filename = Path(header["filename"]).name  # strip any path component for safety
            dest     = _unique_path(INBOX / filename)
            size     = header["size"]

            print(f"Receiving '{filename}' ({_fmt_size(size)}) from {sender} …")

            received = 0
            with dest.open("wb") as f:
                while received < size:
                    chunk = conn.recv(min(CHUNK, size - received))
                    if not chunk:
                        break
                    f.write(chunk)
                    received += len(chunk)
                    _progress(received, size)

            print(f"\n✓ Saved to {dest}")

        else:
            print(f"Unknown transfer type '{header['type']}' — ignored.")

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
    pct  = done / total * 100
    bar  = "#" * int(pct / 2)
    print(f"\r  [{bar:<50}] {pct:5.1f}%", end="", flush=True)

def _unique_path(p: Path) -> Path:
    """If a file already exists at p, append a counter to avoid overwriting."""
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
  share pair --listen          # machine A waits
  share pair 192.168.1.10      # machine B connects → both are now paired

  share recv                   # machine A waits for one transfer
  share send photo.jpg         # machine B sends (auto-picks the only peer)
  share msg "dinner at 7?"     # machine B sends a message

  share peers                  # see who you've paired with
""",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # pair
    p_pair = sub.add_parser("pair", help="Pair with a new peer")
    p_pair.add_argument("ip", nargs="?", help="IP address of peer (omit to listen)")
    p_pair.add_argument("--listen", action="store_true", help="Wait for peer to connect")

    # send
    p_send = sub.add_parser("send", help="Send a file")
    p_send.add_argument("file")
    p_send.add_argument("peer", nargs="?", help="Peer name (optional if only one peer)")

    # msg
    p_msg = sub.add_parser("msg", help="Send a short text message")
    p_msg.add_argument("text")
    p_msg.add_argument("peer", nargs="?")

    # recv
    sub.add_parser("recv", help="Receive one incoming transfer")

    # peers
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
    elif args.cmd == "recv":
        cmd_recv()
    elif args.cmd == "peers":
        cmd_peers()

if __name__ == "__main__":
    main()
