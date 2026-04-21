#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path

import yaml


def extract_cves(lines: list[str]) -> list[str]:
    out = []
    for line in lines:
        m = re.search(r"(CVE-\d{4}-\d+)", line)
        if m:
            out.append(m.group(1))
    return out


def load_manifests(src_root: Path) -> dict[str, dict]:
    manifests = {}
    for path in sorted(src_root.glob("**/manifest.yml")):
        data = yaml.safe_load(path.read_text())
        manifests[data["cve_id"]] = {"path": path, "data": data}
    return manifests


def build_report(cve_ids: list[str], meta: dict[str, dict], manifests: dict[str, dict]) -> str:
    lines = [
        "# Report",
        "",
        "This file is a single global report for all processed CVEs.",
        "",
    ]

    for cve_id in cve_ids:
        m = meta.get(cve_id, {})
        if cve_id in manifests:
            d = manifests[cve_id]["data"]
            completeness = d.get("status", {}).get("completeness", "incomplete")
            if completeness == "vuln-only":
                fixed_build_line = "- Fixed build: intentionally omitted by vuln-only lab policy"
                fixed_result_line = "- Fixed result: not evaluated (vulnerable path only)"
            elif d["product"].get("fixed_version"):
                fixed_build_line = "- Fixed build: synthetic fixed control scaffolded"
                fixed_result_line = f"- Fixed result: {d['exploit']['negative_control_expectation']}"
            else:
                fixed_build_line = "- Fixed build: not feasible in-session"
                fixed_result_line = f"- Fixed result: {d['exploit']['negative_control_expectation']}"
            lines.extend(
                [
                    f"## {cve_id}",
                    "",
                    "### Identity",
                    f"- Product: {d['product']['name']}",
                    f"- Component: {d['product'].get('component', 'network-facing service')}",
                    f"- Severity: {d['severity']}",
                    f"- Publication date: {m.get('published', '')}",
                    f"- CVSS: {m.get('cvss_score', '')}",
                    f"- Attack type: {d['exploit']['attack_type']}",
                    "",
                    "### Sources",
                    f"- CVE.org: {d['sources']['cve']}",
                    f"- NVD: {d['sources']['nvd']}",
                    f"- Vendor advisory: {', '.join(d['sources'].get('vendor', [])) if d['sources'].get('vendor') else 'not found in-session'}",
                    f"- Upstream source or binary: {', '.join(d['sources'].get('upstream', [])) if d['sources'].get('upstream') else 'not found in-session'}",
                    f"- Additional references: {', '.join(d['sources'].get('additional', [])) if d['sources'].get('additional') else 'none'}",
                    "",
                    "### Version selection",
                    f"- Vulnerable version chosen: {d['product'].get('vulnerable_version', 'unknown')}",
                    "- Evidence: CVE/NVD description and listed affected range",
                    f"- Fixed version chosen: {d['product'].get('fixed_version', '') or 'unavailable'}",
                    f"- Evidence: {d['product'].get('fixed_version_unavailable_reason', 'vendor/upstream advisory references')}",
                    "- Ambiguities: see limitations",
                    "",
                    "### Lab design",
                    f"- Severity directory: src/{d['severity']}/{cve_id}",
                    f"- Services used: {', '.join(d['runtime'].get('required_services', []))}",
                    f"- Exposed ports: target {d['runtime']['host_bind']}:{d['runtime']['ports'].get('target', 9090)}",
                    "- Network boundaries: host only to target, internal compose network for all service-to-service calls",
                    "- External trigger path: solution container executes explicit attacker request after startup",
                    f"- Success condition: {d['exploit']['success_condition']}",
                    f"- Negative-control expectation: {d['exploit']['negative_control_expectation']}",
                    "",
                    "### Fidelity",
                    f"- Level: {d['fidelity']['level']}",
                    f"- Rationale: {d['fidelity']['rationale']}",
                    f"- Limitations: {'; '.join(d['fidelity'].get('limitations', []))}",
                    "",
                    "### Validation",
                    f"- Completeness: {completeness}",
                    "- Vulnerable build: scaffold prepared; full upstream reproduction pending",
                    "- Vulnerable result: deterministic attacker path defined in solution container",
                    fixed_build_line,
                    fixed_result_line,
                    f"- Blocker if incomplete: {d['status']['blocker']}",
                    "- Notes: processed in order from CVE_list.txt",
                    "",
                ]
            )
        else:
            lines.extend(
                [
                    f"## {cve_id}",
                    "",
                    "### Validation",
                    "- Completeness: incomplete",
                    f"- Blocker if incomplete: {m.get('scope_reason', 'not processed in session')}",
                    f"- Notes: {m.get('decision_note', 'skipped during scope triage')}",
                    "",
                ]
            )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    args = parser.parse_args()
    root = Path(args.root)

    docs_root = root / "docs" if (root / "docs").exists() else root
    src_root = root / "src" if (root / "src").exists() else root / "src"

    lines = (docs_root / "CVE_list.txt").read_text().splitlines()
    cve_ids = extract_cves(lines)

    meta_entries = json.loads((docs_root / "cve_meta.json").read_text())
    meta = {e["cve_id"]: e for e in meta_entries}
    manifests = load_manifests(src_root)

    report = build_report(cve_ids, meta, manifests)
    out = docs_root / "Report.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report + "\n")
    print(f"Rendered {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
