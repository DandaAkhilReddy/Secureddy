"""Make the analysis helper modules importable by name.

``support`` lives beside the unit tests (pytest's prepend import mode puts this
directory on ``sys.path`` already); ``corpus`` lives with the functional tests
and a couple of unit tests reuse its binary-fixture builders, so this conftest
adds that directory to the path before any test module is imported.
"""

from __future__ import annotations

import sys
from pathlib import Path

_FUNCTIONAL = Path(__file__).resolve().parents[2] / "functional" / "analysis"
if str(_FUNCTIONAL) not in sys.path:
    sys.path.insert(0, str(_FUNCTIONAL))
