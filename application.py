#!/usr/bin/env python3
"""NovaGate-AIShield entrypoint.

Kept at the repository root because v2 users launch it with
``python application.py``. The real entry point is the ``novagate`` console
script installed by ``pip install -e .``; this file just delegates to it.

    python application.py                    # same as: novagate serve
    python application.py inspect "prompt"    # one-shot verdict
    python application.py scan -f prompts.txt
    python application.py categories

Prefer the console script. This shim exists so muscle memory and old docs keep
working, and it will be removed in v4.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running straight from a clone without installing first.
_SRC = Path(__file__).resolve().parent / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from novagate.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
