"""Ensure the ``corpus`` module (this directory) is importable by name under
pytest's import mode, regardless of collection order."""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
