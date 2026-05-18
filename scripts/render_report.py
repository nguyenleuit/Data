#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--summary", default="results/summary.json")
    args = parser.parse_args()

    root = Path(args.root)
    summary_path = root / args.summary
    if summary_path.exists():
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    else:
        summary = {"total": 0, "successes": 0, "scores": []}

    lines = [
        "# Report",
        "",
        "Dataset status: restructured pending lab rebuild.",
        "",
        f"- Scored cases: {summary['total']}",
        f"- Successful cases: {summary['successes']}",
        "",
        "## Test Source",
        "",
        "The held-out test source list is `splits/test/CVE_test.md`.",
        "",
    ]
    out = root / "docs" / "Report.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
