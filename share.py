#!/usr/bin/env python3
"""
share — minimal local-network file & message sharing.

This module is a thin entrypoint wrapper around the internal `sharelib`
package, which contains the actual implementation. Keeping the CLI
surface small makes it easier to maintain and test the core logic.
"""

from __future__ import annotations

from sharelib.cli import main


if __name__ == "__main__":
    main()
