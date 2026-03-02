## peer-sync

Minimal terminal tool for sharing files and short messages between machines on the same LAN, with a simple always-on daemon and a trusted-peers list.

### 1. Prerequisites

- **Python**: 3.9+ installed (`python3 --version`).
- **OS**: macOS or Linux (daemon uses `os.fork`, not supported on Windows).
- Make sure `~/.local/bin` is on your `PATH` (most modern distros do this by default).

### 2. Clone the repository

```bash
git clone https://github.com/stephano/peer-sync.git
cd peer-sync
```

### 3. Install the `share` command

There are two common options; pick one.

#### Option A: simple symlink (recommended while developing)

```bash
chmod +x share.py
mkdir -p ~/.local/bin
ln -sf "$(pwd)/share.py" ~/.local/bin/share
```

Ensure `~/.local/bin` is on your `PATH` (add this to `~/.zshrc` or `~/.bashrc` if needed):

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Then reload your shell or source your config:

```bash
source ~/.zshrc    # or ~/.bashrc
```

Now `share` should work:

```bash
share --help
```

#### Option B: alias (quick and local to your shell)

Add to your shell rc file (e.g. `~/.zshrc`):

```bash
alias share='python3 ~/GitHub/peer-sync/share.py'
```

Reload:

```bash
source ~/.zshrc
```

Then:

```bash
share --help
```

### 4. One-time pairing between two machines

On **machine A** (listener):

```bash
share daemon stop              # make sure daemon is not using the port
share pair --listen            # waits for a connection
```

The command prints something like:

```text
Waiting for a peer to connect on port 57890 …  (Ctrl-C to cancel)
Give them this IP: 192.168.1.23
```

On **machine B** (connector), use that IP:

```bash
share pair 192.168.1.23
```

After a successful pairing, both machines store each other in `~/.config/share/peers.json`.

### 5. Start the always-on daemon

On **each** machine, once peers are paired:

```bash
share daemon start
share daemon status
```

You should see:

```text
Daemon is running (PID 12345).
  Log:   /Users/you/.config/share/daemon.log
  Inbox: /Users/you/ShareInbox/
```

The daemon:

- Listens for incoming transfers on a fixed TCP port.
- Only accepts connections from trusted peers (from `peers.json`).
- Writes received files into your `ShareInbox` folder.

To see / create the inbox directory explicitly:

```bash
share inbox
```

### 6. Sending files and messages

From either machine (symmetric; both can send/receive once trusted):

```bash
# Send a file
share send path/to/file.txt            # if only one peer, sends there
share send path/to/file.txt alice      # specify peer by name

# Send a short message
share msg "hello from A"               # will prompt if multiple peers
share msg "hello from A" alice
```

When there are multiple peers and you omit the peer name, `share` will show a numbered list and ask which peer to send to.

### 7. Stopping the daemon

On any machine:

```bash
share daemon stop
```

If the PID file is stale (process already gone), the tool cleans it up and reports that the daemon is not running.

### 8. Trusted peers list

To see all trusted peers:

```bash
share peers
```

Peers are stored as a simple JSON mapping in:

```text
~/.config/share/peers.json
```

If needed, you can edit that file by hand or delete entries to “untrust” peers (the daemon reloads peers on each connection, so changes take effect immediately).