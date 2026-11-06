"""The detonation chamber and the Reading Room.

* ``backends`` - where a detonation runs (local subprocess, Docker, Azure ACI)
  and ``DetonationChamber`` / ``make_chamber``, the ``Detonator`` the worker uses.
* ``detonate`` - the code that runs inside the sandbox (also a CLI).
* ``cdr`` - Content Disarm & Reconstruction (safe PDFs from untrusted files).
* ``readingroom`` / ``readingroom_web`` - remote browser isolation and its
  FastAPI router.

Import backends lazily (they pull in Playwright / the Azure SDK); the light
helpers here are safe to import anywhere.
"""

from .common import registrable_domain, sniff_type
from .targets import TargetDecision, decide_target

__all__ = ["TargetDecision", "decide_target", "registrable_domain", "sniff_type"]
