#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true", help="Validate every generated train lab")
    parser.add_argument("--case", help="Validate one train lab by case ID")
    args = parser.parse_args()
    if not args.all and not args.case:
        parser.error("use --all or --case <CASE-ID>")
    cmd = [sys.executable, "scripts/build_train_labs.py", "validate"]
    if args.case:
        cmd.extend(["--case", args.case])
    return subprocess.run(cmd, cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
