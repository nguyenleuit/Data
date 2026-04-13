#!/usr/bin/env python3
import argparse
from pathlib import Path

import yaml


REQUIRED_TOP = [
    "cve_id",
    "severity",
    "product",
    "sources",
    "fidelity",
    "runtime",
    "exploit",
    "status",
]


def validate_manifest(path: Path) -> list[str]:
    errors = []
    data = yaml.safe_load(path.read_text())
    if not isinstance(data, dict):
        return [f"{path}: manifest is not a mapping"]

    for key in REQUIRED_TOP:
        if key not in data:
            errors.append(f"{path}: missing top-level key '{key}'")

    status = data.get("status", {})
    if status.get("completeness") not in {"complete", "incomplete", "vuln-only"}:
        errors.append(f"{path}: status.completeness must be complete|incomplete|vuln-only")

    runtime = data.get("runtime", {})
    if runtime.get("host_bind") != "127.0.0.1":
        errors.append(f"{path}: runtime.host_bind must be 127.0.0.1")

    exploit = data.get("exploit", {})
    if exploit.get("auto_exploit_on_startup") is not False:
        errors.append(f"{path}: exploit.auto_exploit_on_startup must be false")

    vendor = data.get("sources", {}).get("vendor", [])
    upstream = data.get("sources", {}).get("upstream", [])
    if not vendor and not upstream:
        errors.append(f"{path}: at least one vendor or upstream source is required")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default="src")
    args = parser.parse_args()

    root = Path(args.root)
    manifests = sorted(root.glob("**/manifest.yml"))
    if not manifests:
        print("No manifests found")
        return 1

    all_errors = []
    for manifest in manifests:
        all_errors.extend(validate_manifest(manifest))

    if all_errors:
        print("Manifest validation failed:")
        for err in all_errors:
            print(f"- {err}")
        return 1

    print(f"Validated {len(manifests)} manifest(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
