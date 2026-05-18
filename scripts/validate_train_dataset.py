#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml


REQUIRED_FILES = ["manifest.yml", "public_task.yml", "eval.yml", "compose.yml", "hints.yml", "writeup.md", "traces/example_success.json", "solution/exploit.py", "solution/exploit.sh", "solution/README.md", "oracle/verify.py", "oracle/verify.sh", "oracle/README.md", "target/Dockerfile", "target/README.md"]
REQUIRED_DIRS = ["target/app", "target/config", "target/patches", "auxiliary", "oracle", "solution", "artifacts", "traces"]


def parse_train_cves(root: Path) -> list[str]:
    source = root / "splits" / "train" / "CVE_train.md"
    text = source.read_text(encoding="utf-8")
    return re.findall(r"\|\s*(CVE-\d{4}-\d+)\s*\|", text)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    errors: list[str] = []
    for cve in parse_train_cves(root):
        matches = list((root / "splits" / "train" / "cases").glob(f"*/{cve}"))
        if not matches:
            errors.append(f"missing train case directory for {cve}")
            continue
        case_dir = matches[0]
        for rel in REQUIRED_DIRS:
            if not (case_dir / rel).is_dir():
                errors.append(f"{cve}: missing directory {rel}")
        for rel in REQUIRED_FILES:
            if not (case_dir / rel).is_file():
                errors.append(f"{cve}: missing file {rel}")
        for rel in ["manifest.yml", "public_task.yml", "eval.yml", "compose.yml", "hints.yml"]:
            try:
                yaml.safe_load((case_dir / rel).read_text(encoding="utf-8"))
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{cve}: invalid YAML {rel}: {exc}")
        manifest_path = case_dir / "manifest.yml"
        if manifest_path.exists():
            manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
            if manifest.get("split") != "train":
                errors.append(f"{cve}: manifest split is not train")
            if manifest.get("case_id") != cve:
                errors.append(f"{cve}: manifest case_id mismatch")
            runtime = manifest.get("runtime", {}) if isinstance(manifest.get("runtime"), dict) else {}
            if "target_port_container" in runtime:
                errors.append(f"{cve}: runtime.target_port_container is deprecated; use runtime.container_target_port")
            for key in ["host_bind", "target_port", "evaluator_port", "protocol", "target_url", "container_target_port"]:
                if key not in runtime:
                    errors.append(f"{cve}: missing runtime.{key}")
        public_task_path = case_dir / "public_task.yml"
        if public_task_path.exists() and manifest_path.exists():
            public_task = yaml.safe_load(public_task_path.read_text(encoding="utf-8"))
            manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
            runtime = manifest.get("runtime", {}) if isinstance(manifest.get("runtime"), dict) else {}
            target = public_task.get("target", {}) if isinstance(public_task.get("target"), dict) else {}
            scope = public_task.get("scope", {}) if isinstance(public_task.get("scope"), dict) else {}
            if not target.get("url"):
                errors.append(f"{cve}: public_task target.url is required")
            if target.get("url") != runtime.get("target_url"):
                errors.append(f"{cve}: public_task target.url does not match runtime.target_url")
            if runtime.get("host_bind") not in scope.get("allowed_hosts", []):
                errors.append(f"{cve}: runtime host is outside public_task scope")
            if runtime.get("target_port") not in scope.get("allowed_ports", []):
                errors.append(f"{cve}: runtime target_port is outside public_task scope")
    if errors:
        print("Train dataset validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("Train dataset validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
