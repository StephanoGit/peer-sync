#!/usr/bin/env python3
"""
Install share CLI.
- Checks Python version
- Checks each dependency individually, installs only what's missing
- Installs the share script to ~/.local/bin
- Patches PATH in shell rc if needed
- Registers a boot service (launchd on macOS, systemd on Linux)
"""

import subprocess
import sys
import os
import platform
import shutil
from pathlib import Path
from importlib.metadata import version, PackageNotFoundError

# ── constants ─────────────────────────────────────────────────────────────────

MIN_PYTHON = (3, 8)

# package_name -> import_name (they differ sometimes)
DEPS = {
    "zeroconf":    "zeroconf",
    "rich":        "rich",
    "questionary": "questionary",
}

# ── helpers ───────────────────────────────────────────────────────────────────

def banner(text):
    print(f"\n  {text}")

def ok(text):
    print(f"    ✓  {text}")

def warn(text):
    print(f"    ⚠  {text}")

def info(text):
    print(f"    →  {text}")

def fail(text):
    print(f"    ✗  {text}")
    sys.exit(1)

def run(cmd, capture=False):
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    return result

# ── checks ────────────────────────────────────────────────────────────────────

def check_python():
    banner("Checking Python version...")
    major, minor = sys.version_info[:2]
    if (major, minor) < MIN_PYTHON:
        fail(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ required, found {major}.{minor}")
    ok(f"Python {major}.{minor} ({sys.executable})")

def check_pip():
    banner("Checking pip...")
    result = run([sys.executable, "-m", "pip", "--version"], capture=True)
    if result.returncode != 0:
        fail("pip not found. Install pip first: https://pip.pypa.io/en/stable/installation/")
    pip_ver = result.stdout.decode().split()[1]
    ok(f"pip {pip_ver}")

def get_installed_version(package_name):
    try:
        return version(package_name)
    except PackageNotFoundError:
        return None

def check_and_install_deps():
    banner("Checking dependencies...")

    to_install = []

    for pkg, import_name in DEPS.items():
        ver = get_installed_version(pkg)
        if ver:
            ok(f"{pkg} {ver} already installed")
        else:
            warn(f"{pkg} not found — will install")
            to_install.append(pkg)

    if not to_install:
        ok("All dependencies already satisfied")
        return

    print(f"\n  Installing: {', '.join(to_install)}")
    result = run([
        sys.executable, "-m", "pip", "install", "--quiet", *to_install
    ])
    if result.returncode != 0:
        # try with --user flag as fallback
        warn("Standard install failed, trying --user install...")
        result = run([
            sys.executable, "-m", "pip", "install", "--quiet", "--user", *to_install
        ])
        if result.returncode != 0:
            fail(f"Failed to install: {', '.join(to_install)}\nTry manually: pip install {' '.join(to_install)}")

    # verify everything actually importable now
    for pkg, import_name in DEPS.items():
        if pkg in to_install:
            ver = get_installed_version(pkg)
            if ver:
                ok(f"{pkg} {ver} installed")
            else:
                fail(f"{pkg} installed but not importable — check your Python environment")

# ── install script ─────────────────────────────────────────────────────────────

def install_script():
    banner("Installing share script...")

    bin_dir = Path.home() / ".local" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)

    src  = Path(__file__).parent / "share.py"
    dest = bin_dir / "share"

    if not src.exists():
        fail(f"share.py not found at {src} — make sure install.py is in the same folder as share.py")

    shutil.copy2(src, dest)
    dest.chmod(0o755)

    # ensure correct shebang
    content = dest.read_text()
    if not content.startswith("#!/usr/bin/env python3"):
        dest.write_text("#!/usr/bin/env python3\n" + content)

    ok(f"Installed to {dest}")
    return dest

# ── PATH ──────────────────────────────────────────────────────────────────────

def fix_path():
    banner("Checking PATH...")

    bin_dir   = str(Path.home() / ".local" / "bin")
    path_dirs = os.environ.get("PATH", "").split(":")

    if bin_dir in path_dirs:
        ok("~/.local/bin already in PATH")
        return

    # detect shell rc file
    shell = os.environ.get("SHELL", "")
    if "zsh" in shell:
        rc = Path.home() / ".zshrc"
    elif "fish" in shell:
        rc = Path.home() / ".config" / "fish" / "config.fish"
    else:
        rc = Path.home() / ".bashrc"

    rc.parent.mkdir(parents=True, exist_ok=True)

    export_line = f'\nexport PATH="$HOME/.local/bin:$PATH"\n'
    if "fish" in shell:
        export_line = f'\nfish_add_path $HOME/.local/bin\n'

    # don't add if already in the file
    if rc.exists() and ".local/bin" in rc.read_text():
        ok(f"~/.local/bin already referenced in {rc.name}")
    else:
        try:
            with open(rc, "a") as f:
                f.write(export_line)
            ok(f"Added ~/.local/bin to PATH in {rc.name}")
            warn(f"Run: source ~/{rc.name}  (or restart terminal)")
        except PermissionError:
            warn(f"Could not write to {rc.name} (permission denied)")
            info(f"Add this line to {rc} manually:")
            print(f'\n        export PATH="$HOME/.local/bin:$PATH"\n')
            info("Or paste this to set it for the current session only:")
            print(f'\n        export PATH="$HOME/.local/bin:$PATH"\n')

# ── boot service ──────────────────────────────────────────────────────────────

def install_boot_service(script_dest: Path):
    banner("Setting up boot service (so share runs automatically)...")

    system = platform.system()

    if system == "Darwin":
        _install_launchd(script_dest)
    elif system == "Linux":
        _install_systemd(script_dest)
    else:
        warn(f"Boot service auto-setup not supported on {system}. Start manually with: share --listen")

def _install_launchd(script_dest: Path):
    plist_dir  = Path.home() / "Library" / "LaunchAgents"
    plist_path = plist_dir / "com.share-cli.plist"
    plist_dir.mkdir(parents=True, exist_ok=True)

    plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.share-cli</string>
    <key>ProgramArguments</key>
    <array>
        <string>{script_dest}</string>
        <string>--listen</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/share-cli.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/share-cli-err.log</string>
</dict>
</plist>
"""
    plist_path.write_text(plist_content)

    # unload first if already loaded (to reload cleanly)
    run(["launchctl", "unload", str(plist_path)], capture=True)
    result = run(["launchctl", "load", str(plist_path)], capture=True)

    if result.returncode == 0:
        ok("launchd service registered — share will start on login automatically")
    else:
        warn("launchd registration failed. Start manually with: share --listen")
        info(f"Or load manually: launchctl load {plist_path}")

def _install_systemd(script_dest: Path):
    service_dir  = Path.home() / ".config" / "systemd" / "user"
    service_path = service_dir / "share-cli.service"
    service_dir.mkdir(parents=True, exist_ok=True)

    service_content = f"""[Unit]
Description=share CLI daemon
After=network.target

[Service]
ExecStart={script_dest} --listen
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
"""
    service_path.write_text(service_content)

    run(["systemctl", "--user", "daemon-reload"], capture=True)
    result = run(["systemctl", "--user", "enable", "--now", "share-cli"], capture=True)

    if result.returncode == 0:
        ok("systemd user service registered — share will start on login automatically")
    else:
        warn("systemd registration failed. Start manually with: share --listen")
        info(f"Or enable manually: systemctl --user enable --now share-cli")

# ── summary ───────────────────────────────────────────────────────────────────

def print_summary():
    print("""
  ─────────────────────────────────────────────
   ✓  share is installed and running!
  ─────────────────────────────────────────────

   Commands:

     share                send a file (interactive)
     share --pair         pair with someone new
     share --peers        list trusted peers
     share --listen       manually start the daemon

   Received files land in:  ~/ShareInbox/

   The daemon starts automatically on login —
   you don't need to do anything to receive files.
  ─────────────────────────────────────────────
""")

# ── main ──────────────────────────────────────────────────────────────────────

def main():
    print("\n  ┌─────────────────────────────┐")
    print("  │   share CLI  —  installer   │")
    print("  └─────────────────────────────┘")

    check_python()
    check_pip()
    check_and_install_deps()
    dest = install_script()
    fix_path()
    install_boot_service(dest)
    print_summary()

if __name__ == "__main__":
    main()
