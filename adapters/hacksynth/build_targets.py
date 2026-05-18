#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

import yaml


def build_target(case_dir: Path) -> tuple[str, dict]:
    task = yaml.safe_load((case_dir / "public_task.yml").read_text(encoding="utf-8"))
    case_id = task["case_id"]
    return case_id, {
        "target": task["target"].get("url", ""),
        "protocol": task["target"].get("protocol"),
        "ports": task["target"].get("exposed_ports", []),
        "type": "cve-lab",
        "title": task.get("title", case_id),
        "description": task["objective"],
        "scope": task.get("scope", {}),
        "constraints": task.get("constraints", []),
        "success_criteria": {
            "type": "dataset-evaluator",
            "value": "Use the dataset runner and evaluator to score this case.",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("cases", help="Directory containing rebuilt cases")
    parser.add_argument("output", help="Output targets.json path")
    args = parser.parse_args()

    cases_root = Path(args.cases)
    targets = {}
    for public_task in sorted(cases_root.glob("**/public_task.yml")):
        case_id, target = build_target(public_task.parent)
        targets[case_id] = target

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(targets, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
