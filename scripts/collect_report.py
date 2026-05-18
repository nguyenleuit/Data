#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--out", default="results/summary.json")
    args = parser.parse_args()

    root = Path(args.root)
    scores = []
    for score_path in sorted((root / "splits").glob("**/artifacts/score.json")):
        scores.append(json.loads(score_path.read_text(encoding="utf-8")))

    summary = {
        "total": len(scores),
        "successes": sum(1 for score in scores if score.get("success") is True),
        "scores": scores,
    }
    out = root / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
