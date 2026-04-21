#!/usr/bin/env python3
import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = REPO_ROOT / "docs"
SRC_DIR = REPO_ROOT / "src"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_cve_order() -> list[str]:
    cve_ids = []
    for line in (DOCS_DIR / "CVE_list.txt").read_text(encoding="utf-8").splitlines():
        match = re.search(r"(CVE-\d{4}-\d+)", line)
        if match:
            cve_ids.append(match.group(1))
    return cve_ids


def load_manifests() -> dict[str, Path]:
    manifests = {}
    for path in SRC_DIR.glob("**/manifest.yml"):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        manifests[data["cve_id"]] = path
    return manifests


def truncate(text: str, limit: int = 12000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...[truncated]..."


def relative(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def run_cmd(cmd: list[str], cwd: Path, timeout: int) -> dict:
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    return {
        "cmd": subprocess.list2cmdline(cmd),
        "rc": proc.returncode,
        "stdout": truncate(proc.stdout.strip()),
        "stderr": truncate(proc.stderr.strip()),
    }


def find_python_files(lab_dir: Path) -> list[Path]:
    python_files = []
    for subdir in ("solution", "target", "auxiliary"):
        candidate_dir = lab_dir / subdir
        if candidate_dir.exists():
            python_files.extend(sorted(candidate_dir.glob("*.py")))
    return python_files


def update_manifest(manifest_path: Path, timestamp: str, runtime_validation: str) -> None:
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    data.setdefault("status", {})
    data["status"]["last_validation_utc"] = timestamp
    data["status"]["runtime_validation"] = runtime_validation
    manifest_path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=False),
        encoding="utf-8",
    )


def build_runtime_artifact(
    cve_id: str,
    lab_dir: Path,
    completeness: str,
    started_utc: str,
    finished_utc: str,
    steps: list[dict],
    runtime_validation: str,
) -> dict:
    return {
        "cve_id": cve_id,
        "lab": relative(lab_dir),
        "started_utc": started_utc,
        "finished_utc": finished_utc,
        "runtime_validation": runtime_validation,
        "lab_mode": completeness,
        "comparison": {
            "performed": False,
            "reason": "No fixed control is defined in this lab."
            if completeness == "vuln-only"
            else "This rerun only validated the vulnerable-path lab topology.",
        },
        "steps": steps,
        "note": "Fresh batch rerun recorded by scripts/rerun_all_labs.py.",
    }


def rerun_lab(
    cve_id: str,
    manifest_path: Path,
    manifest_validation_step: dict,
    timeout: int,
) -> dict:
    lab_dir = manifest_path.parent
    compose_path = lab_dir / "compose.yml"
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    completeness = data["status"]["completeness"]

    started_utc = utc_now()
    steps = [manifest_validation_step]
    failed = manifest_validation_step["rc"] != 0

    python_files = find_python_files(lab_dir)
    if python_files:
        compile_step = run_cmd(
            ["python3", "-m", "py_compile", *[relative(path) for path in python_files]],
            cwd=REPO_ROOT,
            timeout=timeout,
        )
        steps.append(compile_step)
        failed = failed or compile_step["rc"] != 0

    compose_base = ["docker", "compose", "-f", relative(compose_path)]
    config_step = run_cmd([*compose_base, "config"], cwd=REPO_ROOT, timeout=timeout)
    steps.append(config_step)
    failed = failed or config_step["rc"] != 0

    pre_down_step = run_cmd([*compose_base, "down", "-v"], cwd=REPO_ROOT, timeout=timeout)
    steps.append(pre_down_step)

    if not failed:
        up_step = run_cmd([*compose_base, "up", "-d", "--build"], cwd=REPO_ROOT, timeout=timeout)
        steps.append(up_step)
        failed = failed or up_step["rc"] != 0

    if not failed:
        ps_step = run_cmd([*compose_base, "ps", "-a"], cwd=REPO_ROOT, timeout=timeout)
        steps.append(ps_step)
        failed = failed or ps_step["rc"] != 0

    if not failed:
        exploit_step = run_cmd(
            [*compose_base, "run", "--rm", "solution", "sh", "/work/exploit.sh"],
            cwd=REPO_ROOT,
            timeout=timeout,
        )
        steps.append(exploit_step)
        failed = failed or exploit_step["rc"] != 0

    post_down_step = run_cmd([*compose_base, "down", "-v"], cwd=REPO_ROOT, timeout=timeout)
    steps.append(post_down_step)

    finished_utc = utc_now()
    runtime_validation = "pass" if not failed else "fail"

    artifact = build_runtime_artifact(
        cve_id=cve_id,
        lab_dir=lab_dir,
        completeness=completeness,
        started_utc=started_utc,
        finished_utc=finished_utc,
        steps=steps,
        runtime_validation=runtime_validation,
    )
    artifact_path = lab_dir / "artifacts" / "runtime-validation.json"
    artifact_path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    update_manifest(manifest_path, finished_utc, runtime_validation)

    return {
        "cve_id": cve_id,
        "runtime_validation": runtime_validation,
        "manifest": relative(manifest_path),
        "artifact": relative(artifact_path),
        "last_validation_utc": finished_utc,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=int, default=1800, help="Per-command timeout in seconds")
    args = parser.parse_args()

    cve_order = read_cve_order()
    manifests = load_manifests()

    missing = [cve_id for cve_id in cve_order if cve_id not in manifests]
    if missing:
        raise SystemExit(f"Missing manifests for: {', '.join(missing)}")

    manifest_validation_step = run_cmd(
        ["python3", "scripts/validate_manifest.py", "src"],
        cwd=REPO_ROOT,
        timeout=args.timeout,
    )

    summary = []
    failed = []
    for cve_id in cve_order:
        result = rerun_lab(
            cve_id=cve_id,
            manifest_path=manifests[cve_id],
            manifest_validation_step=manifest_validation_step,
            timeout=args.timeout,
        )
        summary.append(result)
        if result["runtime_validation"] != "pass":
            failed.append(cve_id)
        print(f"{cve_id}: {result['runtime_validation']}", flush=True)

    (DOCS_DIR / "runtime_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"Completed {len(summary)} lab reruns")
    if failed:
        print(f"Failures: {', '.join(failed)}")
        return 1
    print("All lab reruns passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
