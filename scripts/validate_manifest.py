#!/usr/bin/env python3
import argparse
from pathlib import Path
from urllib.parse import urlparse

import yaml


REQUIRED_TOP = [
    "case_id",
    "split",
    "severity",
    "product",
    "sources",
    "fidelity",
    "runtime",
    "objective",
    "status",
]

ALLOWED_FIDELITY = {"faithful", "near-faithful", "cve-specific-emulated"}
ALLOWED_FIXED_CONTROL = {"present", "deferred", "not-required-for-train"}
ALLOWED_PROTOCOLS = {"http", "https", "tcp", "telnet", "udp", "ftp"}


def is_positive_int(value: object) -> bool:
    return isinstance(value, int) and value > 0


def validate_manifest(path: Path) -> list[str]:
    errors: list[str] = []
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return [f"{path}: manifest is not a mapping"]

    for key in REQUIRED_TOP:
        if key not in data:
            errors.append(f"{path}: missing top-level key '{key}'")

    if data.get("split") not in {"train", "test"}:
        errors.append(f"{path}: split must be train|test")

    if data.get("severity") not in {"critical", "high", "medium", "low"}:
        errors.append(f"{path}: severity must be critical|high|medium|low")

    status = data.get("status", {}) if isinstance(data.get("status"), dict) else {}
    allowed_states = {
        "pending-rebuild",
        "draft",
        "runnable",
        "retired",
        "blocked-metadata-mismatch",
        "blocked-external-dependency",
        "blocked-unavailable-upstream",
        "blocked-research-unavailable",
        "unbuildable",
    }
    if status.get("lab_state") not in allowed_states:
        errors.append(
            f"{path}: status.lab_state must be one of {sorted(allowed_states)}"
        )

    fidelity = data.get("fidelity", {}) if isinstance(data.get("fidelity"), dict) else {}
    if fidelity.get("level") not in ALLOWED_FIDELITY:
        errors.append(f"{path}: fidelity.level must be one of {sorted(ALLOWED_FIDELITY)}")
    if fidelity.get("level") != "faithful" and not fidelity.get("limitations"):
        errors.append(f"{path}: fidelity.limitations is required for non-faithful cases")

    if status.get("fixed_control") not in ALLOWED_FIXED_CONTROL:
        errors.append(f"{path}: status.fixed_control must be one of {sorted(ALLOWED_FIXED_CONTROL)}")

    product = data.get("product", {}) if isinstance(data.get("product"), dict) else {}
    if "fixed_control" in product and product.get("fixed_control") not in ALLOWED_FIXED_CONTROL:
        errors.append(f"{path}: product.fixed_control must be one of {sorted(ALLOWED_FIXED_CONTROL)}")

    runtime = data.get("runtime", {}) if isinstance(data.get("runtime"), dict) else {}
    required_runtime = [
        "compose_file",
        "host_bind",
        "target_port",
        "evaluator_port",
        "required_services",
        "optional_services",
        "protocol",
        "target_url",
        "container_target_port",
    ]
    for key in required_runtime:
        if key not in runtime:
            errors.append(f"{path}: runtime.{key} is required")
    if "target_port_container" in runtime:
        errors.append(f"{path}: runtime.target_port_container is deprecated; use runtime.container_target_port")
    if runtime.get("protocol") not in ALLOWED_PROTOCOLS:
        errors.append(f"{path}: runtime.protocol must be one of {sorted(ALLOWED_PROTOCOLS)}")
    for key in ["target_port", "evaluator_port", "container_target_port"]:
        if key in runtime and not is_positive_int(runtime.get(key)):
            errors.append(f"{path}: runtime.{key} must be a positive integer")
    if runtime.get("host_bind") != "127.0.0.1":
        errors.append(f"{path}: runtime.host_bind must be 127.0.0.1")
    if runtime.get("target_url"):
        parsed = urlparse(str(runtime["target_url"]))
        if parsed.scheme != runtime.get("protocol"):
            errors.append(f"{path}: runtime.target_url scheme does not match runtime.protocol")
        if parsed.hostname != runtime.get("host_bind"):
            errors.append(f"{path}: runtime.target_url host does not match runtime.host_bind")
        if parsed.port != runtime.get("target_port"):
            errors.append(f"{path}: runtime.target_url port does not match runtime.target_port")
    if status.get("fixed_control") == "present" and not isinstance(runtime.get("fixed_control"), dict):
        errors.append(f"{path}: runtime.fixed_control is required when status.fixed_control is present")

    visibility = data.get("visibility", {})
    if visibility and "agent_can_read" not in visibility:
        errors.append(f"{path}: visibility.agent_can_read is required when visibility is set")

    public_task_path = path.parent / "public_task.yml"
    if public_task_path.exists():
        public_task = yaml.safe_load(public_task_path.read_text(encoding="utf-8"))
        if not isinstance(public_task, dict):
            errors.append(f"{public_task_path}: public task is not a mapping")
        else:
            if public_task.get("case_id") != data.get("case_id"):
                errors.append(f"{public_task_path}: case_id does not match manifest")
            target = public_task.get("target", {}) if isinstance(public_task.get("target"), dict) else {}
            scope = public_task.get("scope", {}) if isinstance(public_task.get("scope"), dict) else {}
            if not target.get("url"):
                errors.append(f"{public_task_path}: target.url is required")
            if target.get("protocol") != runtime.get("protocol"):
                errors.append(f"{public_task_path}: target.protocol does not match runtime.protocol")
            if target.get("url") != runtime.get("target_url"):
                errors.append(f"{public_task_path}: target.url does not match runtime.target_url")
            allowed_hosts = scope.get("allowed_hosts", []) if isinstance(scope, dict) else []
            allowed_ports = scope.get("allowed_ports", []) if isinstance(scope, dict) else []
            if runtime.get("host_bind") not in allowed_hosts:
                errors.append(f"{public_task_path}: runtime host is outside scope.allowed_hosts")
            if runtime.get("target_port") not in allowed_ports:
                errors.append(f"{public_task_path}: runtime target_port is outside scope.allowed_ports")
    else:
        errors.append(f"{path}: missing sibling public_task.yml")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default="splits")
    args = parser.parse_args()

    root = Path(args.root)
    manifests = sorted(root.glob("**/manifest.yml"))
    if not manifests:
        print("No manifests found; skeleton dataset has no rebuilt cases yet")
        return 0

    errors: list[str] = []
    for manifest in manifests:
        errors.extend(validate_manifest(manifest))

    is_test_root = "splits/test" in str(root).replace("\\", "/") or root.name == "test"
    if is_test_root:
        loaded = [yaml.safe_load(path.read_text(encoding="utf-8")) for path in manifests]
        upgraded = sum(1 for item in loaded if item.get("fidelity", {}).get("level") in {"faithful", "near-faithful"})
        fixed = sum(1 for item in loaded if item.get("status", {}).get("fixed_control") == "present")
        if upgraded < 6:
            errors.append(f"{root}: expected at least 6 faithful/near-faithful test cases, found {upgraded}")
        if fixed < 6:
            errors.append(f"{root}: expected at least 6 fixed controls, found {fixed}")

    if errors:
        print("Manifest validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    print(f"Validated {len(manifests)} manifest(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
