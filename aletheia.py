"""Direct CLI launcher for Aletheia (The Incorruptible Witness on Ethereum)."""

import sys
from pathlib import Path

# Automatically ensure src is on python path
src_dir = Path(__file__).parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from chronotrace.cli.main import app

if __name__ == "__main__":
    app()
