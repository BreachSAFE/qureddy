# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Allow `python -m qureddy ...` to invoke the CLI."""

from __future__ import annotations

from qureddy.cli import main

if __name__ == "__main__":
    main()
