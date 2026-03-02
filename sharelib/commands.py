"""
High-level user commands for the `share` CLI.

These functions implement the behavior behind subcommands such as:

- `pair --listen` / `pair <ip>`
- `send`
- `msg`
- `daemon start|stop|status` (delegated to `sharelib.daemon`)
- `peers`
- `inbox`
- `scan`
"""

from __future__ import annotations

import socket
from typing import Optional

from . import config, daemon, peers, protocol


def cmd_pair_listen() -> None:
    """
    Wait for a peer to connect, exchange names, and save them as trusted.

    This runs a one-shot TCP listener on `config.PORT` (the same port
    the daemon uses), accepts a single incoming connection, performs
    a small hostname exchange, and records the peer IP + name into
    `peers.json`.
    """
    local_ip = peers.guess_local_ipv4() or "unknown"

    print(f"Waiting for a peer to connect on port {config.PORT} …  (Ctrl-C to cancel)")
    print(f"Give them this IP: {local_ip}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("", config.PORT))
        srv.listen(1)
        conn, (peer_ip, _) = srv.accept()

    with conn:
        conn.settimeout(config.TIMEOUT)
        peer_name = protocol._recv_exactly(conn, 256).rstrip(b"\x00").decode()
        conn.sendall(peers.my_name().encode().ljust(256, b"\x00"))

    all_peers = peers.load_peers()
    all_peers[peer_name] = peer_ip
    peers.save_peers(all_peers)
    print(f"✓ Paired with '{peer_name}' ({peer_ip}).")


def cmd_pair_connect(ip: str) -> None:
    """
    Connect to a peer that is running `share pair --listen`.

    After connecting, this performs the same small hostname exchange as
    `cmd_pair_listen` and records the resulting peer into `peers.json`.
    """
    print(f"Connecting to {ip}:{config.PORT} …")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(config.TIMEOUT)
        try:
            s.connect((ip, config.PORT))
        except (ConnectionRefusedError, TimeoutError, OSError) as exc:
            raise SystemExit(
                f"Could not connect to {ip}:{config.PORT} — {exc}\n"
                "Make sure the other side runs: share pair --listen"
            )

        s.sendall(peers.my_name().encode().ljust(256, b"\x00"))
        peer_name = protocol._recv_exactly(s, 256).rstrip(b"\x00").decode()

    all_peers = peers.load_peers()
    all_peers[peer_name] = ip
    peers.save_peers(all_peers)
    print(f"✓ Paired with '{peer_name}' ({ip}).")


def cmd_scan() -> None:
    """
    Scan for potential peers on the local /24 subnet.

    This is a best-effort, unauthenticated discovery mechanism: it simply
    attempts a short TCP connect to every address in `A.B.C.1-254` on
    `config.PORT` and reports which ones accepted the connection.

    It also reports this machine's own IP (labelled as \"(this machine)\").
    """
    local_ip = peers.guess_local_ipv4()
    if not local_ip or "." not in local_ip:
        raise SystemExit("Could not determine a local IPv4 address for scanning.")

    octets = local_ip.split(".")
    if len(octets) != 4:
        raise SystemExit(f"Unrecognised IPv4 address format: {local_ip}")

    prefix = ".".join(octets[:3])
    print(f"Scanning {prefix}.1-254 on port {config.PORT} …", flush=True)

    responsive: list[str] = []
    timeout = 0.2  # modest timeout so scans finish quickly

    def try_host(last_octet: int) -> None:
        ip = f"{prefix}.{last_octet}"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, config.PORT))
            responsive.append(ip)
        except OSError:
            return

    import threading

    threads: list[threading.Thread] = []
    for i in range(1, 255):
        t = threading.Thread(target=try_host, args=(i,))
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    if not responsive:
        print("No hosts with an open share port found.")
        return

    print("Hosts with the share port open:")
    for ip in sorted(responsive):
        if ip == local_ip:
            print(f"  {ip}  (this machine)")
        else:
            print(f"  {ip}")


def cmd_send(filepath: str, peer_hint: Optional[str]) -> None:
    """
    Send a file to a chosen peer.

    The peer is resolved using the same rules as `peers.pick_peer`.
    """
    path = config.Path(filepath) if isinstance(filepath, str) else filepath  # type: ignore[attr-defined]
    if not path.exists():
        raise SystemExit(f"File not found: {filepath}")

    all_peers = peers.load_peers()
    try:
        name, ip = peers.pick_peer(all_peers, peer_hint)
    except (ValueError, KeyError) as exc:
        raise SystemExit(str(exc))

    size = path.stat().st_size
    print(f"Sending '{path.name}' ({protocol.fmt_size(size)}) to {name} ({ip}) …")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(config.TIMEOUT)
        try:
            s.connect((ip, config.PORT))
        except (ConnectionRefusedError, TimeoutError, OSError) as exc:
            raise SystemExit(
                f"Could not reach {name} ({ip}:{config.PORT}) — {exc}\n"
                "Is their daemon running? share daemon status"
            )

        protocol.send_header(
            s,
            {
                "type": "file",
                "from": peers.my_name(),
                "filename": path.name,
                "size": size,
            },
        )

        sent = 0
        with path.open("rb") as f:
            while True:
                chunk = f.read(config.CHUNK)
                if not chunk:
                    break
                s.sendall(chunk)
                sent += len(chunk)
                protocol.progress(sent, size)

    print(f"\n✓ Sent.")


def cmd_msg(text: str, peer_hint: Optional[str]) -> None:
    """
    Send a short text message to a chosen peer.
    """
    all_peers = peers.load_peers()
    try:
        name, ip = peers.pick_peer(all_peers, peer_hint)
    except (ValueError, KeyError) as exc:
        raise SystemExit(str(exc))

    print(f"Sending message to {name} ({ip}) …")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(config.TIMEOUT)
        try:
            s.connect((ip, config.PORT))
        except (ConnectionRefusedError, TimeoutError, OSError) as exc:
            raise SystemExit(f"Could not reach {name} ({ip}:{config.PORT}) — {exc}")

        protocol.send_header(
            s,
            {
                "type": "message",
                "from": peers.my_name(),
                "text": text,
            },
        )

    print("✓ Sent.")


def cmd_peers() -> None:
    """
    Print the list of trusted peers and their associated IP addresses.
    """
    all_peers = peers.load_peers()
    if not all_peers:
        print("No trusted peers. Run: share pair <ip>")
        return
    print("Trusted peers:")
    for name, ip in all_peers.items():
        print(f"  {name:<20} {ip}")


def cmd_inbox() -> None:
    """
    Show the current inbox folder and ensure it exists on disk.
    """
    config.INBOX.mkdir(parents=True, exist_ok=True)
    print(f"Inbox folder: {config.INBOX}")

