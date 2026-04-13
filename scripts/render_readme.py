#!/usr/bin/env python3
import argparse
from pathlib import Path

import yaml


def render(manifest_path: Path) -> str:
    manifest = yaml.safe_load(manifest_path.read_text())
    cve = manifest["cve_id"]
    services = manifest["runtime"].get("required_services", [])
    optional = manifest["runtime"].get("optional_services", [])
    ports = manifest["runtime"].get("ports", {})
    status = manifest["status"]
    completeness = status.get("completeness", "incomplete")
    fixed = manifest["product"].get("fixed_version", "")
    fixed_reason = manifest["product"].get("fixed_version_unavailable_reason", "")

    lines = [
        f"# {cve} Lab README",
        "",
        "## Purpose",
        f"Reproduce a controlled {manifest['exploit']['attack_type']} path for {manifest['product']['name']} using a deterministic attacker-driven flow.",
        "",
        "## Services",
        f"- required: {', '.join(services) if services else 'target, solution'}",
        f"- optional: {', '.join(optional) if optional else 'none'}",
        "",
        "## Ports",
        f"- target: `127.0.0.1:{ports.get('target', 9090)}`",
        "- verifier: `127.0.0.1:9091` if present",
        "- all other services: internal-only",
        "",
        "## Quick start",
        "```bash",
        "docker compose up -d --build",
        "docker compose ps",
        "```",
        "",
        "## Run exploit",
        "```bash",
        "docker compose run --rm solution sh /work/exploit.sh",
        "```",
        "",
        "## Expected results",
        f"- vulnerable target: {manifest['exploit']['success_condition']}",
    ]

    if completeness == "vuln-only":
        lines.append("- fixed target: intentionally omitted by vuln-only lab policy")
    elif fixed:
        lines.append(
            f"- fixed target ({fixed}): {manifest['exploit']['negative_control_expectation']}"
        )
    else:
        lines.append(f"- fixed target: unavailable ({fixed_reason})")

    lines.extend(
        [
            "",
            "## Status",
            f"- completeness: `{completeness}`",
            f"- blocker: {status['blocker'] if status['blocker'] else 'none'}",
            "",
            "## Cleanup",
            "```bash",
            "docker compose down -v",
            "```",
        ]
    )

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest")
    args = parser.parse_args()
    manifest_path = Path(args.manifest)
    readme_path = manifest_path.with_name("README.md")
    readme_path.write_text(render(manifest_path))
    print(f"Rendered {readme_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
