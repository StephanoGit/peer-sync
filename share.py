#!/usr/bin/env python3
"""
share - a simple peer-to-peer file transfer CLI
Usage:
  share            - interactive mode: discover peers, select file, send
  share --listen   - run as background daemon (auto-starts on install)
  share --pair     - pair with a new peer
  share --peers    - list trusted peers
"""

import os
import sys
import json
import socket
import struct
import hashlib
import threading
import time
import signal
import argparse
from pathlib import Path
from datetime import datetime

# ── deps ──────────────────────────────────────────────────────────────────────
try:
    from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, BarColumn, TransferSpeedColumn, TimeRemainingColumn
    from rich.prompt import Confirm
    from rich import print as rprint
    import questionary
    from questionary import Style as QStyle
except ImportError:
    print("\n  Missing dependencies. Install with:\n")
    print("  pip install zeroconf rich questionary\n")
    sys.exit(1)

# ── config ────────────────────────────────────────────────────────────────────
APP_DIR       = Path.home() / ".share-cli"
INBOX_DIR     = Path.home() / "ShareInbox"
PEERS_FILE    = APP_DIR / "trusted_peers.json"
KEYS_DIR      = APP_DIR / "keys"
SERVICE_TYPE  = "_sharefile._tcp.local."
TRANSFER_PORT = 55100
PAIR_PORT     = 55101
CHUNK_SIZE    = 65536  # 64KB

console = Console()

STYLE = QStyle([
    ("qmark",        "fg:#61afef bold"),
    ("question",     "bold"),
    ("answer",       "fg:#98c379 bold"),
    ("pointer",      "fg:#61afef bold"),
    ("highlighted",  "fg:#61afef bold"),
    ("selected",     "fg:#98c379"),
    ("separator",    "fg:#5c6370"),
    ("instruction",  "fg:#5c6370"),
    ("text",         ""),
    ("disabled",     "fg:#5c6370 italic"),
])

# ── setup ─────────────────────────────────────────────────────────────────────
def setup_dirs():
    APP_DIR.mkdir(exist_ok=True)
    KEYS_DIR.mkdir(exist_ok=True)
    INBOX_DIR.mkdir(exist_ok=True)
    if not PEERS_FILE.exists():
        PEERS_FILE.write_text(json.dumps({}))

def load_peers() -> dict:
    try:
        return json.loads(PEERS_FILE.read_text())
    except Exception:
        return {}

def save_peers(peers: dict):
    PEERS_FILE.write_text(json.dumps(peers, indent=2))

def get_my_id() -> str:
    id_file = APP_DIR / "my_id"
    if id_file.exists():
        return id_file.read_text().strip()
    import uuid
    my_id = str(uuid.uuid4())[:8]
    id_file.write_text(my_id)
    return my_id

def get_hostname() -> str:
    return socket.gethostname().replace(".local", "")

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

# ── discovery ─────────────────────────────────────────────────────────────────
def get_zeroconf_iface() -> str | None:
    """Return the best network interface for zeroconf (prefers en0, then first non-loopback)."""
    import netifaces  # optional, fall back gracefully
    pass

def make_zeroconf() -> Zeroconf:
    """Create a Zeroconf instance bound to the correct interface."""
    import socket
    # Try to find a real LAN interface — prefer en0 (WiFi on macOS)
    preferred = ["en0", "en1", "eth0", "wlan0"]
    iface = None
    for name in preferred:
        try:
            socket.if_nametoindex(name)
            iface = name
            break
        except OSError:
            continue

    if iface:
        from zeroconf import InterfaceChoice
        try:
            # bind to the specific interface ip
            ip = get_local_ip()
            return Zeroconf(interfaces=[ip])
        except Exception:
            pass
    return Zeroconf()

class PeerDiscovery:
    def __init__(self):
        self.zeroconf   = make_zeroconf()
        self.peers      = {}   # name -> {ip, port, id, hostname}
        self._lock      = threading.Lock()
        self._browser   = None
        self._info      = None

    def start_advertising(self):
        my_ip   = get_local_ip()
        my_id   = get_my_id()
        my_name = get_hostname()
        name    = f"{my_name}-{my_id}.{SERVICE_TYPE}"

        self._info = ServiceInfo(
            SERVICE_TYPE,
            name,
            addresses=[socket.inet_aton(my_ip)],
            port=TRANSFER_PORT,
            properties={
                b"id":       my_id.encode(),
                b"hostname": my_name.encode(),
            },
        )
        self.zeroconf.register_service(self._info)

    def start_browsing(self):
        self._browser = ServiceBrowser(self.zeroconf, SERVICE_TYPE, self)

    def add_service(self, zc, type_, name):
        info = zc.get_service_info(type_, name)
        if not info:
            return
        peer_id = info.properties.get(b"id", b"").decode()
        if peer_id == get_my_id():
            return   # that's me
        hostname = info.properties.get(b"hostname", b"unknown").decode()
        ip = socket.inet_ntoa(info.addresses[0])
        with self._lock:
            self.peers[peer_id] = {
                "ip":       ip,
                "port":     info.port,
                "id":       peer_id,
                "hostname": hostname,
            }

    def remove_service(self, zc, type_, name):
        # Don't call get_service_info here — the service is already gone
        # and zeroconf may be shutting down, causing NotRunningException.
        # The service name is formatted as "{hostname}-{id}._sharefile._tcp.local."
        # so we extract the id from the name string directly.
        try:
            # name looks like: "myhostname-ab12cd34._sharefile._tcp.local."
            short = name.replace(f".{type_}", "").replace(type_, "")
            # last segment after final "-" is the peer id
            peer_id = short.rsplit("-", 1)[-1].strip(".")
        except Exception:
            return
        with self._lock:
            self.peers.pop(peer_id, None)

    def update_service(self, zc, type_, name):
        self.add_service(zc, type_, name)

    def get_peers(self) -> dict:
        with self._lock:
            return dict(self.peers)

    def stop(self):
        if self._info:
            self.zeroconf.unregister_service(self._info)
        self.zeroconf.close()

# ── pairing ───────────────────────────────────────────────────────────────────
def generate_pair_code() -> str:
    import random, string
    return "".join(random.choices(string.digits, k=6))

def pair_request_handler(conn: socket.socket, addr):
    """Handle incoming pair requests."""
    try:
        data = conn.recv(4096).decode()
        req  = json.loads(data)

        if req.get("type") != "pair_request":
            conn.close()
            return

        peer_hostname = req["hostname"]
        peer_id       = req["id"]
        code          = req["code"]

        console.print(f"\n[bold yellow]  Pairing request from [cyan]{peer_hostname}[/cyan][/bold yellow]")
        console.print(f"  Verification code: [bold green]{code}[/bold green]")
        console.print("  Make sure this matches what they see on their screen.\n")

        accept = Confirm.ask("  Accept pairing?", default=False)

        if accept:
            peers = load_peers()
            peers[peer_id] = {
                "hostname":  peer_hostname,
                "id":        peer_id,
                "paired_at": datetime.now().isoformat(),
            }
            save_peers(peers)
            resp = {"type": "pair_accepted", "hostname": get_hostname(), "id": get_my_id()}
            console.print(f"  [green]✓[/green] Paired with [cyan]{peer_hostname}[/cyan]")
        else:
            resp = {"type": "pair_rejected"}
            console.print("  [yellow]Pairing declined.[/yellow]")

        conn.send(json.dumps(resp).encode())
    except Exception as e:
        console.print(f"  [red]Pairing error: {e}[/red]")
    finally:
        conn.close()

def start_pair_listener():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PAIR_PORT))
    srv.listen(5)
    srv.settimeout(1)
    while True:
        try:
            conn, addr = srv.accept()
            t = threading.Thread(target=pair_request_handler, args=(conn, addr), daemon=True)
            t.start()
        except socket.timeout:
            continue
        except OSError:
            break

def do_pair(peer_ip: str, peer_hostname: str):
    """Initiate pairing with a peer."""
    code = generate_pair_code()
    console.print(f"\n  Pairing code: [bold green]{code}[/bold green]")
    console.print("  Share this code verbally with the other person.\n")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(30)
        s.connect((peer_ip, PAIR_PORT))
        req = {
            "type":     "pair_request",
            "hostname": get_hostname(),
            "id":       get_my_id(),
            "code":     code,
        }
        s.send(json.dumps(req).encode())
        resp_data = s.recv(4096).decode()
        resp = json.loads(resp_data)
        s.close()

        if resp.get("type") == "pair_accepted":
            peer_id = resp["id"]
            peers = load_peers()
            peers[peer_id] = {
                "hostname":  peer_hostname,
                "id":        peer_id,
                "paired_at": datetime.now().isoformat(),
            }
            save_peers(peers)
            console.print(f"  [green]✓[/green] Successfully paired with [cyan]{peer_hostname}[/cyan]!")
        else:
            console.print("  [yellow]Pairing was declined.[/yellow]")
    except ConnectionRefusedError:
        console.print(f"  [red]Could not connect. Is {peer_hostname} running share?[/red]")
    except socket.timeout:
        console.print("  [red]Timed out waiting for response.[/red]")
    except Exception as e:
        console.print(f"  [red]Error: {e}[/red]")

# ── file transfer ─────────────────────────────────────────────────────────────
def recv_file_handler(conn: socket.socket, addr):
    """Handle incoming file transfer."""
    try:
        # read header length (4 bytes)
        raw_len = conn.recv(4)
        if not raw_len:
            return
        header_len = struct.unpack(">I", raw_len)[0]
        header_data = b""
        while len(header_data) < header_len:
            chunk = conn.recv(header_len - len(header_data))
            if not chunk:
                return
            header_data += chunk

        header    = json.loads(header_data.decode())
        sender_id = header["sender_id"]
        filename  = Path(header["filename"]).name   # strip any path traversal
        filesize  = header["filesize"]
        checksum  = header["checksum"]

        # verify trust
        peers = load_peers()
        if sender_id not in peers:
            conn.send(b"REJECT")
            console.print(f"\n  [yellow]Rejected file from unknown sender ({addr[0]})[/yellow]")
            return

        sender_name = peers[sender_id]["hostname"]
        conn.send(b"ACCEPT")

        # receive file
        dest = INBOX_DIR / filename
        # avoid overwriting
        if dest.exists():
            stem    = dest.stem
            suffix  = dest.suffix
            counter = 1
            while dest.exists():
                dest = INBOX_DIR / f"{stem}_{counter}{suffix}"
                counter += 1

        received   = 0
        sha256     = hashlib.sha256()

        with open(dest, "wb") as f:
            while received < filesize:
                to_read = min(CHUNK_SIZE, filesize - received)
                chunk   = conn.recv(to_read)
                if not chunk:
                    break
                f.write(chunk)
                sha256.update(chunk)
                received += len(chunk)

        # verify checksum
        if sha256.hexdigest() == checksum:
            conn.send(b"OK")
            console.print(f"\n  [green]✓[/green] Received [cyan]{filename}[/cyan] from [cyan]{sender_name}[/cyan] → {dest}")
        else:
            conn.send(b"CORRUPT")
            dest.unlink(missing_ok=True)
            console.print(f"\n  [red]✗ Corrupted file from {sender_name}, discarded.[/red]")

    except Exception as e:
        console.print(f"\n  [red]Transfer error: {e}[/red]")
    finally:
        conn.close()

def start_transfer_listener():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", TRANSFER_PORT))
    srv.listen(10)
    srv.settimeout(1)
    while True:
        try:
            conn, addr = srv.accept()
            t = threading.Thread(target=recv_file_handler, args=(conn, addr), daemon=True)
            t.start()
        except socket.timeout:
            continue
        except OSError:
            break

def send_file(peer_ip: int, peer_port: int, filepath: Path) -> bool:
    """Send a file to a peer."""
    filesize = filepath.stat().st_size

    # compute checksum
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            sha256.update(chunk)
    checksum = sha256.hexdigest()

    header = json.dumps({
        "sender_id": get_my_id(),
        "filename":  filepath.name,
        "filesize":  filesize,
        "checksum":  checksum,
    }).encode()

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((peer_ip, peer_port))

        # send header
        s.send(struct.pack(">I", len(header)))
        s.send(header)

        # wait for accept/reject
        response = s.recv(6)
        if response != b"ACCEPT":
            console.print("  [red]Transfer rejected by peer (not paired?)[/red]")
            s.close()
            return False

        s.settimeout(60)

        # send file with progress bar
        sent = 0
        with Progress(
            "[progress.description]{task.description}",
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TransferSpeedColumn(),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(f"  Sending [cyan]{filepath.name}[/cyan]", total=filesize)
            with open(filepath, "rb") as f:
                while chunk := f.read(CHUNK_SIZE):
                    s.send(chunk)
                    sent += len(chunk)
                    progress.update(task, advance=len(chunk))

        # wait for confirmation
        result = s.recv(8)
        s.close()

        if result == b"OK":
            return True
        else:
            console.print("  [red]File was corrupted in transit.[/red]")
            return False

    except ConnectionRefusedError:
        console.print(f"  [red]Could not connect to peer. Are they online?[/red]")
        return False
    except Exception as e:
        console.print(f"  [red]Send error: {e}[/red]")
        return False

# ── daemon mode ───────────────────────────────────────────────────────────────
def run_daemon():
    """Run as background listener + advertise on network."""
    console.print(f"\n  [bold]share[/bold] daemon running")
    console.print(f"  Hostname : [cyan]{get_hostname()}[/cyan]")
    console.print(f"  ID       : [cyan]{get_my_id()}[/cyan]")
    console.print(f"  IP       : [cyan]{get_local_ip()}[/cyan]")
    console.print(f"  Inbox    : [cyan]{INBOX_DIR}[/cyan]")
    console.print("  Press Ctrl+C to stop.\n")

    # start listeners
    t1 = threading.Thread(target=start_transfer_listener, daemon=True)
    t2 = threading.Thread(target=start_pair_listener,    daemon=True)
    t1.start()
    t2.start()

    # advertise on network
    discovery = PeerDiscovery()
    discovery.start_advertising()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n  [yellow]Stopping...[/yellow]")
        discovery.stop()

# ── interactive UI ─────────────────────────────────────────────────────────────
def interactive_send():
    """Discover peers and send a file interactively."""
    console.print("\n  [bold]share[/bold] — scanning network...\n")

    discovery = PeerDiscovery()
    discovery.start_advertising()
    discovery.start_browsing()

    # give mDNS time to discover
    with console.status("  Looking for peers..."):
        time.sleep(2)

    peers_online = discovery.get_peers()
    trusted      = load_peers()

    if not peers_online:
        console.print("  [yellow]No peers found on the network.[/yellow]")
        console.print("  Make sure they're running [bold]share --listen[/bold]\n")
        discovery.stop()
        return

    # filter: show all online peers, mark trusted
    choices = []
    for pid, info in peers_online.items():
        label = info["hostname"]
        if pid in trusted:
            label += " [paired]"
        else:
            label += " [not paired]"
        choices.append(questionary.Choice(title=label, value=info))

    peer = questionary.select(
        "Select peer:",
        choices=choices,
        style=STYLE,
    ).ask()

    if not peer:
        discovery.stop()
        return

    peer_id = peer["id"]
    if peer_id not in trusted:
        console.print(f"\n  [yellow]'{peer['hostname']}' is not paired yet.[/yellow]")
        do_pair_now = questionary.confirm("  Pair now?", style=STYLE).ask()
        if do_pair_now:
            do_pair(peer["ip"], peer["hostname"])
            # re-check
            if peer_id not in load_peers():
                discovery.stop()
                return
        else:
            discovery.stop()
            return

    # pick file
    file_path_str = questionary.path(
        "File to send:",
        style=STYLE,
    ).ask()

    if not file_path_str:
        discovery.stop()
        return

    filepath = Path(file_path_str).expanduser()
    if not filepath.exists() or not filepath.is_file():
        console.print(f"  [red]File not found: {filepath}[/red]")
        discovery.stop()
        return

    console.print()
    ok = send_file(peer["ip"], peer["port"], filepath)
    if ok:
        console.print(f"\n  [green]✓[/green] [bold]{filepath.name}[/bold] sent to [cyan]{peer['hostname']}[/cyan]\n")
    else:
        console.print(f"\n  [red]✗ Failed to send {filepath.name}[/red]\n")

    discovery.stop()

def interactive_pair():
    """Pair with a peer interactively."""
    console.print("\n  [bold]share --pair[/bold] — scanning network...\n")

    discovery = PeerDiscovery()
    discovery.start_advertising()
    discovery.start_browsing()

    with console.status("  Looking for peers..."):
        time.sleep(2)

    peers_online = discovery.get_peers()
    trusted      = load_peers()

    if not peers_online:
        console.print("  [yellow]No peers found.[/yellow]\n")
        discovery.stop()
        return

    choices = []
    for pid, info in peers_online.items():
        label = info["hostname"]
        if pid in trusted:
            label += "  (already paired)"
        choices.append(questionary.Choice(title=label, value=info))

    peer = questionary.select(
        "Select peer to pair with:",
        choices=choices,
        style=STYLE,
    ).ask()

    if peer:
        do_pair(peer["ip"], peer["hostname"])

    discovery.stop()

def list_peers():
    """Show trusted peers."""
    peers = load_peers()
    if not peers:
        console.print("\n  No trusted peers yet. Run [bold]share --pair[/bold] to add one.\n")
        return

    table = Table(title="Trusted Peers", border_style="bright_black", header_style="bold cyan")
    table.add_column("Hostname",  style="cyan")
    table.add_column("ID",        style="dim")
    table.add_column("Paired At", style="dim")

    for pid, info in peers.items():
        table.add_row(info["hostname"], info["id"], info.get("paired_at", "—"))

    console.print()
    console.print(table)
    console.print()

# ── entrypoint ────────────────────────────────────────────────────────────────
def main():
    setup_dirs()

    parser = argparse.ArgumentParser(
        prog="share",
        description="Simple peer-to-peer file transfer CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  share               discover peers and send a file interactively
  share --listen      run as listener/daemon (required on receiver side)
  share --pair        pair with a new peer
  share --peers       list trusted peers
        """
    )
    parser.add_argument("--listen", "-l", action="store_true", help="run as background daemon")
    parser.add_argument("--pair",   "-p", action="store_true", help="pair with a new peer")
    parser.add_argument("--peers",        action="store_true", help="list trusted peers")
    args = parser.parse_args()

    if args.listen:
        run_daemon()
    elif args.pair:
        interactive_pair()
    elif args.peers:
        list_peers()
    else:
        interactive_send()

if __name__ == "__main__":
    main()
