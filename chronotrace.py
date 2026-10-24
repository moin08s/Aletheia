"""Direct CLI launcher for ChronoTrace."""

import sys
from pathlib import Path

# Automatically ensure src is on python path
src_dir = Path(__file__).parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

# Support package traversal if this file is imported as 'chronotrace'
__path__ = [str(src_dir / "chronotrace")]

from chronotrace.cli.main import app

if __name__ == "__main__":
    app()
