"""Shared pytest bootstrap.

Redirects the console metadata database to a throw-away file so that running the
suite never writes demo data into ``data/codeguard.db``.
"""

from __future__ import annotations

import os
import tempfile

os.environ.setdefault(
    "CONSOLE_DB_PATH",
    os.path.join(tempfile.gettempdir(), "codeguard_test_console.db"),
)
