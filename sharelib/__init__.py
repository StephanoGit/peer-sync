"""
Internal library for the `share` CLI tool.

This package holds the implementation details for:

- Configuration and paths (`config`)
- Peer loading / saving and selection (`peers`)
- Wire protocol helpers and transfer handling (`protocol`)
- Daemon lifecycle (`daemon`)
- High-level user commands (`commands`)
- CLI argument parsing (`cli`)

The top-level `share.py` entrypoint imports and delegates to `sharelib.cli.main()`.
"""

