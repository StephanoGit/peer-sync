"""
Wire protocol helpers and transfer handling for `share`.

Protocol framing:
    [4 bytes: big-endian JSON header length]
    [N bytes: UTF-8 JSON header]
    [remaining bytes: raw file payload (optional)]
"""

from __future__ import annotations

import json
import struct
import socket
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from . import config


def send_header(sock: socket.socket, header: Dict[str, Any]) -> None:
    """
    Encode and send a length-prefixed JSON header.

    Args:
        sock: Connected TCP socket.
        header: Mapping that can be JSON-encoded.
    """
    data = json.dumps(header).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_header(sock: socket.socket) -> Dict[str, Any]:
    """
    Read and decode a length-prefixed JSON header.

    Args:
        sock: Connected TCP socket.

    Returns:
        Parsed header mapping.
    """
    raw_len = _recv_exactly(sock, 4)
    length = struct.unpack(">I", raw_len)[0]
    return json.loads(_recv_exactly(sock, length))


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """
    Read exactly *n* bytes from a socket.

    Raises:
        ConnectionError: if the connection closes before *n* bytes arrive.
    """
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        buf += chunk
    return buf


def ts() -> str:
    """Return a human-readable timestamp string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def fmt_size(n: int) -> str:
    """Render a file size in human-friendly units."""
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def progress(done: int, total: int) -> None:
    """
    Print a simple progress bar on a single terminal line.

    No output is produced if `total` is zero.
    """
    if total == 0:
        return
    pct = done / total * 100
    bar = "#" * int(pct / 2)
    print(f"\r  [{bar:<50}] {pct:5.1f}%", end="", flush=True)


def unique_path(p: Path) -> Path:
    """
    Return a path that does not overwrite an existing file.

    If `p` already exists, a numeric suffix is appended before the file
    extension: `file.txt` → `file_1.txt`, `file_2.txt`, ...
    """
    if not p.exists():
        return p
    stem, suffix = p.stem, p.suffix
    i = 1
    while True:
        candidate = p.with_name(f"{stem}_{i}{suffix}")
        if not candidate.exists():
            return candidate
        i += 1


def handle_transfer(conn: socket.socket, src_ip: str) -> None:
    """
    Process a single incoming connection: save file or print message.

    This function reads exactly one header and, depending on the header
    type, either:

    - prints a message to stdout; or
    - writes a file into the inbox directory.
    """
    conn.settimeout(config.TIMEOUT)
    header = recv_header(conn)
    sender = header.get("from", src_ip)
    stamp = ts()

    if header.get("type") == "message":
        text = header.get("text", "")
        print(f"[{stamp}] Message from {sender}: {text}", flush=True)
        return

    if header.get("type") == "file":
        config.INBOX.mkdir(parents=True, exist_ok=True)
        filename = Path(header.get("filename", "unnamed")).name
        dest = unique_path(config.INBOX / filename)
        size = int(header.get("size", 0))

        print(
            f"[{stamp}] Receiving '{filename}' ({fmt_size(size)}) from {sender} …",
            flush=True,
        )

        received = 0
        with dest.open("wb") as f:
            while received < size:
                chunk = conn.recv(min(config.CHUNK, size - received))
                if not chunk:
                    break
                f.write(chunk)
                received += len(chunk)

        print(f"[{stamp}] Saved to {dest}", flush=True)
        return

    print(
        f"[{stamp}] Unknown type '{header.get('type')}' from {src_ip} — ignored.",
        flush=True,
    )

