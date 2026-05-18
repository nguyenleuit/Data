#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import yaml


ROOT = Path(__file__).resolve().parents[1]
CASES_ROOT = ROOT / "splits" / "test" / "cases"
RESULTS_ROOT = ROOT / "splits" / "test" / "artifacts" / "smoke-results"
REPORT_PATH = ROOT / "splits" / "test" / "artifacts" / "test-readiness-report.md"

FINAL_STATUSES = {
    "test_ready",
    "starts_but_not_testable",
    "oracle_failed",
    "target_unreachable",
    "metadata_mismatch",
    "blocked",
}


@dataclass
class Case:
    case_id: str
    path: Path
    manifest: dict
    public_task: dict


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run(cmd: list[str], cwd: Path, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=timeout, check=False)


def load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def discover_cases(case_ids: set[str] | None = None) -> list[Case]:
    cases: list[Case] = []
    for manifest_path in sorted(CASES_ROOT.glob("*/*/manifest.yml")):
        manifest = load_yaml(manifest_path)
        case_id = manifest.get("case_id") or manifest.get("cve_id")
        if case_ids and case_id not in case_ids:
            continue
        case_dir = manifest_path.parent
        public_task_path = case_dir / "public_task.yml"
        public_task = load_yaml(public_task_path) if public_task_path.exists() else {}
        cases.append(Case(case_id=case_id, path=case_dir, manifest=manifest, public_task=public_task))
    return cases


def target_from_metadata(case: Case) -> dict:
    manifest = case.manifest
    public = case.public_task
    runtime = manifest.get("runtime", {}) if isinstance(manifest.get("runtime"), dict) else {}
    public_target = public.get("target", {}) if isinstance(public.get("target"), dict) else {}
    url = public_target.get("url") or runtime.get("target_url") or manifest.get("target_url")
    parsed = urlparse(url) if url else None
    protocol = public_target.get("protocol") or runtime.get("protocol") or manifest.get("protocol") or (parsed.scheme if parsed else "http")
    host = public_target.get("host") or runtime.get("host") or (parsed.hostname if parsed else "127.0.0.1")
    port = public_target.get("port") or runtime.get("target_port") or manifest.get("port") or (parsed.port if parsed else None)
    return {
        "url": url,
        "protocol": protocol,
        "host": host,
        "port": int(port) if port is not None else None,
    }


def metadata_check(case: Case, target: dict) -> tuple[bool, str | None]:
    manifest = case.manifest
    public = case.public_task
    if not case.case_id or case.case_id != public.get("case_id"):
        return False, "manifest/public_task case_id mismatch"
    if not target.get("protocol") or not target.get("host") or target.get("port") is None:
        return False, "target protocol/host/port is incomplete"
    scope = public.get("scope", {}) if isinstance(public.get("scope"), dict) else {}
    allowed_hosts = scope.get("allowed_hosts", [])
    allowed_ports = scope.get("allowed_ports", [])
    if target["host"] not in allowed_hosts:
        return False, "public target host is outside declared scope"
    if target["port"] not in allowed_ports:
        return False, "public target port is outside declared scope"
    text = (case.path / "public_task.yml").read_text(encoding="utf-8") if (case.path / "public_task.yml").exists() else ""
    secret_path = case.path / "target" / "config" / "case.json"
    if secret_path.exists():
        try:
            secret = json.loads(secret_path.read_text(encoding="utf-8")).get("lab_secret")
        except json.JSONDecodeError:
            secret = None
        if secret and secret in text:
            return False, "public_task leaks lab secret"
    for hidden_token in ["/impact", "expected_success_signal", "lab_secret"]:
        if hidden_token in text:
            return False, f"public_task leaks hidden token {hidden_token}"
    return True, None


def wait_for_target(target: dict, timeout_seconds: int = 60) -> dict:
    deadline = time.time() + timeout_seconds
    last_error = None
    attempts = 0
    while time.time() < deadline:
        attempts += 1
        result = probe_target(target)
        if result["reachable"]:
            result["attempts"] = attempts
            return result
        last_error = result.get("error_message")
        time.sleep(2)
    return {"reachable": False, "attempts": attempts, "error_message": last_error or "target did not become reachable"}


def wait_for_evaluator(case: Case, timeout_seconds: int = 60) -> dict:
    port = case.manifest.get("runtime", {}).get("evaluator_port")
    if port is None:
        return {"reachable": False, "error_message": "manifest runtime.evaluator_port is missing"}
    url = f"http://127.0.0.1:{int(port)}/health"
    deadline = time.time() + timeout_seconds
    attempts = 0
    last_error = None
    while time.time() < deadline:
        attempts += 1
        try:
            with urlopen(Request(url, method="GET"), timeout=5) as response:
                body = response.read(256).decode(errors="replace")
            return {"reachable": True, "attempts": attempts, "status_code": response.status, "sample": body[:120]}
        except Exception as exc:  # noqa: BLE001 - surfaced in smoke result.
            last_error = f"{type(exc).__name__}: {exc}"
            time.sleep(2)
    return {"reachable": False, "attempts": attempts, "error_message": last_error or "evaluator did not become reachable"}


def probe_target(target: dict) -> dict:
    protocol = target["protocol"]
    host = target["host"]
    port = target["port"]
    if protocol in {"telnet", "tcp"}:
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                sock.settimeout(5)
                banner = sock.recv(256).decode(errors="replace")
            return {"reachable": True, "interaction": "tcp-connect-read-banner", "status": "ok", "sample": banner[:120]}
        except Exception as exc:  # noqa: BLE001 - surfaced in smoke result.
            return {"reachable": False, "interaction": "tcp-connect-read-banner", "error_message": f"{type(exc).__name__}: {exc}"}
    if protocol == "udp":
        probes = [("udp-health", b"HEALTH")]
        url = f"http://{host}/benchmark-smoke-probe".encode("ascii") + b"\x00"
        body = b"\x00\x00\x00\x00" + url
        probes.append(("udp-icp-v2-query", struct.pack("!BBHIIII", 1, 2, 20 + len(body), 1, 0, 0, 0) + body))
        last_error = None
        for interaction, payload in probes:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(5)
                    sock.sendto(payload, (host, port))
                    data, _ = sock.recvfrom(512)
                sample = data.decode(errors="replace")
                return {"reachable": True, "interaction": interaction, "status": "ok", "sample": sample[:120]}
            except Exception as exc:  # noqa: BLE001 - surfaced in smoke result.
                last_error = f"{interaction}: {type(exc).__name__}: {exc}"
        return {"reachable": False, "interaction": "udp-send-receive", "error_message": last_error or "udp probe failed"}
    if protocol == "udp-health-only":
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(5)
                sock.sendto(b"HEALTH", (host, port))
                data, _ = sock.recvfrom(512)
            sample = data.decode(errors="replace")
            return {"reachable": True, "interaction": "udp-send-receive", "status": "ok", "sample": sample[:120]}
        except Exception as exc:  # noqa: BLE001 - surfaced in smoke result.
            return {"reachable": False, "interaction": "udp-send-receive", "error_message": f"{type(exc).__name__}: {exc}"}
    if protocol in {"http", "https"}:
        url = target.get("url") or f"{protocol}://{host}:{port}"
        try:
            req = Request(url, method="GET", headers={"User-Agent": "benchmark-smoke-runner/1.0"})
            with urlopen(req, timeout=5) as response:
                body = response.read(512).decode(errors="replace")
            return {"reachable": True, "interaction": "http-get-public-url", "status_code": response.status, "sample": body[:120]}
        except Exception as exc:  # noqa: BLE001 - surfaced in smoke result.
            return {"reachable": False, "interaction": "http-get-public-url", "error_message": f"{type(exc).__name__}: {exc}"}
    return {"reachable": False, "interaction": "unsupported-protocol", "error_message": f"unsupported protocol {protocol}"}


def classify_oracle(proc: subprocess.CompletedProcess, case_dir: Path) -> dict:
    observation_path = case_dir / "artifacts" / "observation.json"
    if not observation_path.exists():
        return {
            "classification": "invalid",
            "returncode": proc.returncode,
            "error_message": "oracle did not write artifacts/observation.json",
            "stdout_tail": proc.stdout[-2000:],
            "stderr_tail": proc.stderr[-2000:],
        }
    try:
        observation = json.loads(observation_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {
            "classification": "invalid",
            "returncode": proc.returncode,
            "error_message": f"observation is not valid JSON: {exc}",
            "stdout_tail": proc.stdout[-2000:],
            "stderr_tail": proc.stderr[-2000:],
        }
    if proc.returncode == 0 and observation.get("success") is True:
        classification = "success"
    elif proc.returncode != 0 and observation.get("success") is False:
        classification = "failure"
    elif observation.get("runtime_tested") is not True:
        classification = "inconclusive"
    else:
        classification = "invalid"
    return {
        "classification": classification,
        "returncode": proc.returncode,
        "observation_path": str(observation_path.relative_to(ROOT)),
        "score_path": str((case_dir / "artifacts" / "score.json").relative_to(ROOT)),
        "observation_success": observation.get("success"),
        "oracle_result": observation.get("oracle_result"),
        "stdout_tail": proc.stdout[-2000:],
        "stderr_tail": proc.stderr[-2000:],
    }


def cleanup(case_dir: Path) -> dict:
    proc = run(["docker", "compose", "down", "-v"], case_dir, timeout=120)
    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout_tail": proc.stdout[-1000:],
        "stderr_tail": proc.stderr[-1000:],
    }


def smoke_once(case: Case, attempt: int) -> dict:
    target = target_from_metadata(case)
    metadata_ok, metadata_error = metadata_check(case, target)
    result = {
        "attempt": attempt,
        "start_result": {"ok": False},
        "reachability_result": {"reachable": False},
        "minimal_interaction_result": None,
        "oracle_result": {"classification": "invalid"},
        "cleanup_result": {"ok": False},
        "attempt_status": "blocked",
        "error_message": None,
    }
    if not metadata_ok:
        result["attempt_status"] = "metadata_mismatch"
        result["error_message"] = metadata_error
        return result

    run(["docker", "compose", "down", "-v"], case.path, timeout=120)
    try:
        start = run(["docker", "compose", "up", "-d", "--build"], case.path, timeout=180)
        result["start_result"] = {
            "ok": start.returncode == 0,
            "returncode": start.returncode,
            "stdout_tail": start.stdout[-1000:],
            "stderr_tail": start.stderr[-1000:],
        }
        if start.returncode != 0:
            result["attempt_status"] = "blocked"
            result["error_message"] = "docker compose up failed"
            return result

        reachability = wait_for_target(target)
        result["reachability_result"] = reachability
        result["minimal_interaction_result"] = reachability
        if not reachability.get("reachable"):
            result["attempt_status"] = "target_unreachable"
            result["error_message"] = reachability.get("error_message")
            return result

        evaluator_reachability = wait_for_evaluator(case)
        result["evaluator_reachability_result"] = evaluator_reachability
        if not evaluator_reachability.get("reachable"):
            result["attempt_status"] = "starts_but_not_testable"
            result["error_message"] = evaluator_reachability.get("error_message")
            return result

        oracle = run([sys.executable, "oracle/verify.py"], case.path, timeout=90)
        oracle_result = classify_oracle(oracle, case.path)
        result["oracle_result"] = oracle_result
        if oracle_result["classification"] == "success":
            result["attempt_status"] = "test_ready"
        elif oracle_result["classification"] in {"failure", "invalid", "inconclusive"}:
            result["attempt_status"] = "oracle_failed"
            result["error_message"] = oracle_result.get("error_message") or f"oracle classified run as {oracle_result['classification']}"
        else:
            result["attempt_status"] = "starts_but_not_testable"
            result["error_message"] = "unknown oracle classification"
        return result
    finally:
        result["cleanup_result"] = cleanup(case.path)


def final_status(attempts: list[dict]) -> tuple[str, str | None, dict]:
    if not attempts:
        return "blocked", "no smoke attempts executed", {"stable": False}
    statuses = [attempt["attempt_status"] for attempt in attempts]
    oracle_classes = [attempt.get("oracle_result", {}).get("classification") for attempt in attempts]
    cleanup_ok = all(attempt.get("cleanup_result", {}).get("ok") for attempt in attempts)
    stable = len(set(statuses)) == 1 and len(set(oracle_classes)) == 1
    stability = {"stable": stable, "attempt_statuses": statuses, "oracle_classifications": oracle_classes}
    if all(status == "test_ready" for status in statuses) and stable and cleanup_ok:
        return "test_ready", None, stability
    first_non_ready = next((attempt for attempt in attempts if attempt["attempt_status"] != "test_ready"), attempts[-1])
    status = first_non_ready["attempt_status"]
    if status not in FINAL_STATUSES:
        status = "starts_but_not_testable"
    if not cleanup_ok:
        return "blocked", "cleanup failed after smoke run", stability
    if not stable:
        return "starts_but_not_testable", "smoke attempts were not stable", stability
    return status, first_non_ready.get("error_message"), stability


def smoke_case(case: Case, repeats: int) -> dict:
    target = target_from_metadata(case)
    attempts = [smoke_once(case, attempt + 1) for attempt in range(repeats)]
    status, error, stability = final_status(attempts)
    result = {
        "cve_id": case.case_id,
        "lab_path": str(case.path.relative_to(ROOT)),
        "lab_type": case.manifest.get("lab_type") or case.manifest.get("fidelity", {}).get("level", "unknown"),
        "protocol": target.get("protocol"),
        "target_url": target.get("url"),
        "host": target.get("host"),
        "port": target.get("port"),
        "start_result": attempts[-1].get("start_result") if attempts else {"ok": False},
        "reachability_result": attempts[-1].get("reachability_result") if attempts else {"reachable": False},
        "oracle_result": attempts[-1].get("oracle_result") if attempts else {"classification": "invalid"},
        "cleanup_result": attempts[-1].get("cleanup_result") if attempts else {"ok": False},
        "final_status": status,
        "error_message": error,
        "timestamp": utc_now(),
        "stability": stability,
        "attempts": attempts,
    }
    RESULTS_ROOT.mkdir(parents=True, exist_ok=True)
    (RESULTS_ROOT / f"{case.case_id}.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def write_report(results: list[dict], command: str) -> None:
    total = len(results)
    test_ready = sum(1 for item in results if item["final_status"] == "test_ready")
    blocked = sum(1 for item in results if item["final_status"] == "blocked")
    not_ready = total - test_ready
    lines = [
        "# Test Readiness Report",
        "",
        f"Updated: {utc_now()}",
        "",
        f"- Total labs checked: {total}",
        f"- test_ready: {test_ready}",
        f"- not_test_ready: {not_ready}",
        f"- blocked: {blocked}",
        "",
        "## Commands",
        "",
        "- `python3 scripts/build_test_labs.py validate`",
        "- `python3 scripts/validate_manifest.py splits/test`",
        "- `python3 scripts/validate_dataset.py --root .`",
        f"- `{command}`",
        "- `docker ps --format '{{.Names}}'`",
        "",
        "## Per-CVE Status",
        "",
        "| CVE | Path | Lab Type | Protocol | Target | Status | Oracle | Stable | Reason | Artifact |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for item in sorted(results, key=lambda r: r["cve_id"]):
        target = item.get("target_url") or f"{item.get('host')}:{item.get('port')}"
        oracle = item.get("oracle_result", {}).get("classification", "unknown")
        stable = item.get("stability", {}).get("stable")
        reason = item.get("error_message") or ""
        artifact = f"splits/test/artifacts/smoke-results/{item['cve_id']}.json"
        lines.append(
            f"| {item['cve_id']} | {item['lab_path']} | {item['lab_type']} | {item['protocol']} | {target} | {item['final_status']} | {oracle} | {stable} | {reason} | {artifact} |"
        )
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--case", action="append", dest="case_ids", help="CVE ID to smoke test; repeatable")
    group.add_argument("--all", action="store_true", help="Smoke test all test split labs")
    parser.add_argument("--repeats", type=int, default=2, help="Number of clean start/probe/oracle/cleanup attempts per lab")
    args = parser.parse_args()

    selected = set(args.case_ids) if args.case_ids else None
    cases = discover_cases(selected)
    if selected and len(cases) != len(selected):
        found = {case.case_id for case in cases}
        missing = sorted(selected - found)
        raise SystemExit(f"Missing case(s): {', '.join(missing)}")

    results = []
    for case in cases:
        print(f"smoke {case.case_id}")
        result = smoke_case(case, args.repeats)
        print(f"{case.case_id}: {result['final_status']} oracle={result['oracle_result'].get('classification')} stable={result['stability'].get('stable')}")
        results.append(result)

    command = "python3 scripts/smoke_test_labs.py " + ("--all" if args.all else " ".join(f"--case {case_id}" for case_id in args.case_ids or []))
    if args.repeats != 2:
        command += f" --repeats {args.repeats}"
    write_report(results, command)
    return 0 if all(result["final_status"] == "test_ready" for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
