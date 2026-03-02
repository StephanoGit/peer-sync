"""
Command-line interface entrypoint for the `share` tool.
"""

from __future__ import annotations

import argparse

from . import commands, daemon


def build_parser() -> argparse.ArgumentParser:
    """
    Construct and return the top-level argument parser for `share`.
    """
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
    p_send.add_argument(
        "peer",
        nargs="?",
        help="Peer name (optional if only one peer)",
    )

    p_msg = sub.add_parser("msg", help="Send a short message")
    p_msg.add_argument("text")
    p_msg.add_argument("peer", nargs="?", help="Peer name (optional)")

    p_daemon = sub.add_parser("daemon", help="Manage the background receiver")
    p_daemon.add_argument("action", choices=["start", "stop", "status"])

    sub.add_parser("peers", help="List trusted peers")
    sub.add_parser("inbox", help="Show the shared inbox folder for received files")
    sub.add_parser("scan", help="Scan the local /24 for hosts with the share port open")

    return parser


def main() -> None:
    """
    Main entrypoint for the `share` command-line tool.
    """
    parser = build_parser()
    args = parser.parse_args()

    if args.cmd == "pair":
        if args.listen or not args.ip:
            commands.cmd_pair_listen()
        else:
            commands.cmd_pair_connect(args.ip)
    elif args.cmd == "send":
        commands.cmd_send(args.file, args.peer)
    elif args.cmd == "msg":
        commands.cmd_msg(args.text, args.peer)
    elif args.cmd == "daemon":
        if args.action == "start":
            daemon.cmd_daemon_start()
        elif args.action == "stop":
            daemon.cmd_daemon_stop()
        elif args.action == "status":
            daemon.cmd_daemon_status()
    elif args.cmd == "peers":
        commands.cmd_peers()
    elif args.cmd == "inbox":
        commands.cmd_inbox()
    elif args.cmd == "scan":
        commands.cmd_scan()

