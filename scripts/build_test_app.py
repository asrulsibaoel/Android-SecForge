#!/usr/bin/env python3
"""Generate analysis/test-apks/AndroidSecForge-TestApp.apk.

Usage:
    PYTHONPATH=backend python scripts/build_test_app.py [output.apk]
"""

import sys
from pathlib import Path

from app.testapp.builder import build_test_apk

DEFAULT = Path("analysis/test-apks/AndroidSecForge-TestApp.apk")


def main() -> None:
    dest = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT
    path = build_test_apk(dest)
    print(f"built {path} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
