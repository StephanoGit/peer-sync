"""
Configuration constants and filesystem locations for the `share` tool.
"""

from __future__ import annotations

from pathlib import Path

# Network configuration
PORT: int = 57890
CHUNK: int = 65_536          # bytes per read/write iteration
TIMEOUT: int = 60            # socket timeout in seconds

# Filesystem locations
INBOX: Path = Path.home() / "ShareInbox"
CONFIG_DIR: Path = Path.home() / ".config" / "share"
PEERS_FILE: Path = CONFIG_DIR / "peers.json"
PID_FILE: Path = CONFIG_DIR / "daemon.pid"
LOG_FILE: Path = CONFIG_DIR / "daemon.log"

