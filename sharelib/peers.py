"""
Peer storage and selection helpers.

Peers are stored as a simple JSON mapping:

    { "alice": "192.168.1.42", ... }
"""

from __future__ import annotations

import json
import socket
from typing import Dict, Tuple, Optional

from . import config


def load_peers() -> Dict[str, str]:
    """
    Load the trusted peers mapping from disk.

    Returns a mapping of peer name to IPv4/IPv6 string. If the file does
    not exist yet, an empty mapping is returned.
    """
    if config.PEERS_FILE.exists():
        return json.loads(config.PEERS_FILE.read_text())
    return {}


def save_peers(peers: Dict[str, str]) -> None:
    """
    Persist the trusted peers mapping to disk.

    The directory is created if necessary. The JSON file is written with
    indentation for readability.
    """
    config.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    config.PEERS_FILE.write_text(json.dumps(peers, indent=2))


def my_name() -> str:
    """
    Return this machine's identity string.

    For now this is the hostname, which is simple and requires no extra
    configuration. It is sent to peers during pairing and used as the
    default display name.
    """
    return socket.gethostname()


def guess_local_ipv4() -> Optional[str]:
    """
    Best-effort guess of the primary local IPv4 address.

    This opens a temporary UDP socket and "connects" to a public IP
    (no packets are actually sent). The OS chooses the outbound
    interface and we inspect its local address.

    Returns the IPv4 string, or None if it could not be determined.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tmp:
            tmp.connect(("8.8.8.8", 80))
            return tmp.getsockname()[0]
    except OSError:
        return None


def pick_peer(peers: Dict[str, str], hint: Optional[str]) -> Tuple[str, str]:
    """
    Choose a peer to talk to based on an optional hint.

    - If there are no peers, raises `ValueError`.
    - If `hint` is provided, it must be the name of a known peer.
    - If there is exactly one peer, that peer is chosen automatically.
    - Otherwise, the user is presented with a numbered list and asked
      to select a single peer.

    Returns:
        (name, ip) tuple for the chosen peer.
    """
    if not peers:
        raise ValueError("No trusted peers configured.")

    if hint:
        if hint not in peers:
            raise KeyError(hint)
        return hint, peers[hint]

    if len(peers) == 1:
        name, ip = next(iter(peers.items()))
        return name, ip

    print("Multiple peers available:")
    names = list(peers)
    for i, n in enumerate(names, 1):
        print(f"  {i}) {n}  ({peers[n]})")
    choice = int(input("Send to (number): ")) - 1
    name = names[choice]
    return name, peers[name]

