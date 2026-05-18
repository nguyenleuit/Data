#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def default_run_id(framework: str, split: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}_{framework}_{split}"


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_summary_md(path: Path, summary: dict) -> None:
    lines = [
        f"# Run Summary: {summary['run_id']}",
        "",
        f"- Split: {summary['split']}",
        f"- Framework: {summary['framework']}",
        f"- Dry run: {summary['dry_run']}",
        f"- Cases: {summary['total_cases']}",
        f"- Succeeded: {summary['succeeded']}",
        f"- Failed: {summary['failed']}",
        "",
        "| Case | Status | Score | Errors |",
        "|---|---|---:|---|",
    ]
    for item in summary["cases"]:
        errors = "; ".join(item.get("errors", []))
        lines.append(f"| {item['case_id']} | {item['status']} | {item['score']} | {errors} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("split", choices=["train", "test"])
    parser.add_argument("--root", default=".")
    parser.add_argument("--framework", default="manual")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--run-id")
    parser.add_argument("--results-root", default="results/runs")
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--keep-containers", action="store_true")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    cases_root = root / "splits" / args.split / "cases"
    manifests = sorted(cases_root.glob("**/manifest.yml"))
    run_id = args.run_id or default_run_id(args.framework, args.split)
    results_root = Path(args.results_root)
    if not results_root.is_absolute():
        results_root = root / results_root
    run_root = results_root / run_id
    run_root.mkdir(parents=True, exist_ok=True)

    if not manifests:
        print(f"No rebuilt {args.split} cases found")
        return 0

    cases = []
    failed = []
    for manifest in manifests:
        cmd = [
            "python3",
            "scripts/run_case.py",
            str(manifest.parent),
            "--framework",
            args.framework,
            "--split",
            args.split,
            "--run-id",
            run_id,
            "--results-root",
            str(results_root),
            "--timeout-seconds",
            str(args.timeout_seconds),
        ]
        if args.dry_run:
            cmd.append("--dry-run")
        if args.keep_containers:
            cmd.append("--keep-containers")
        result = subprocess.run(cmd, cwd=root, text=True, capture_output=True, check=False)
        case_run_path = run_root / manifest.parent.name / "run.json"
        if case_run_path.exists():
            case_run = json.loads(case_run_path.read_text(encoding="utf-8"))
        else:
            case_run = {
                "case_id": manifest.parent.name,
                "status": "runner_failed",
                "score": 0.0,
                "errors": [result.stderr[-2000:] or result.stdout[-2000:] or "run_case failed before writing run.json"],
            }
        cases.append(
            {
                "case_id": case_run["case_id"],
                "path": str(manifest.parent.relative_to(root)),
                "status": case_run.get("status"),
                "score": case_run.get("score", 0.0),
                "success": case_run.get("success", False),
                "errors": case_run.get("errors", []),
                "result_dir": str((run_root / case_run["case_id"]).relative_to(root)),
            }
        )
        if result.returncode != 0:
            failed.append(case_run["case_id"])

    summary = {
        "run_id": run_id,
        "split": args.split,
        "framework": args.framework,
        "dry_run": args.dry_run,
        "results_root": str(results_root),
        "total_cases": len(cases),
        "succeeded": len(cases) - len(failed),
        "failed": len(failed),
        "cases": cases,
    }
    write_json(run_root / "summary.json", summary)
    write_summary_md(run_root / "summary.md", summary)

    print(run_root)
    if failed:
        print("Failed cases:")
        for case_id in failed:
            print(f"- {case_id}")
        return 1
    print(f"Processed {len(manifests)} {args.split} case(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
