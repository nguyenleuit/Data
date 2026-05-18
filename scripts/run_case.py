#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import yaml


ROOT = Path(__file__).resolve().parents[1]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_run_id(framework: str, split: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}_{framework}_{split}"


def load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_jsonl(path: Path, data: dict) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"timestamp": utc_now(), **data}, sort_keys=True) + "\n")


def tail(text: str, limit: int = 4000) -> str:
    return text[-limit:] if text else ""


def sanitized_manifest(manifest: dict) -> dict:
    product = manifest.get("product", {}) if isinstance(manifest.get("product"), dict) else {}
    runtime = manifest.get("runtime", {}) if isinstance(manifest.get("runtime"), dict) else {}
    status = manifest.get("status", {}) if isinstance(manifest.get("status"), dict) else {}
    fidelity = manifest.get("fidelity", {}) if isinstance(manifest.get("fidelity"), dict) else {}
    return {
        "case_id": manifest.get("case_id"),
        "split": manifest.get("split"),
        "severity": manifest.get("severity"),
        "product": {
            "name": product.get("name"),
            "family": product.get("family"),
            "component": product.get("component"),
        },
        "fidelity": {
            "level": fidelity.get("level"),
            "limitations": fidelity.get("limitations", []),
        },
        "runtime": {
            "protocol": runtime.get("protocol"),
            "target_url": runtime.get("target_url"),
            "target_port": runtime.get("target_port"),
            "fixed_control": "present" if runtime.get("fixed_control") else status.get("fixed_control", "deferred"),
        },
        "objective": manifest.get("objective", {}),
        "status": {
            "lab_state": status.get("lab_state"),
            "fixed_control": status.get("fixed_control"),
            "runtime_validation": status.get("runtime_validation"),
        },
    }


def run_command(cmd: list[str], cwd: Path, timeout: int, commands_log: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    started = time.time()
    proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=timeout, check=False, env=env)
    append_jsonl(
        commands_log,
        {
            "kind": "command",
            "cwd": str(cwd),
            "argv": cmd,
            "duration_seconds": round(time.time() - started, 3),
            "exit_code": proc.returncode,
            "stdout_tail": tail(proc.stdout),
            "stderr_tail": tail(proc.stderr),
        },
    )
    return proc


def http_json(url: str, method: str = "GET", payload: dict | None = None, timeout: int = 10) -> tuple[bool, int | None, dict]:
    data = json.dumps(payload or {}).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"} if payload is not None else {}
    try:
        req = Request(url, data=data, headers=headers, method=method)
        with urlopen(req, timeout=timeout) as response:
            body = response.read().decode(errors="replace")
            return True, response.status, json.loads(body) if body else {}
    except HTTPError as exc:
        body = exc.read().decode(errors="replace")
        try:
            parsed = json.loads(body) if body else {}
        except json.JSONDecodeError:
            parsed = {"raw": body}
        return False, exc.code, parsed
    except Exception as exc:  # noqa: BLE001 - recorded in run output.
        return False, None, {"error": f"{type(exc).__name__}: {exc}"}


def wait_for_evaluator(port: int, timeout_seconds: int, commands_log: Path) -> tuple[bool, dict]:
    deadline = time.time() + timeout_seconds
    attempts = 0
    last = {"error": "not attempted"}
    while time.time() < deadline:
        attempts += 1
        ok, status, body = http_json(f"http://127.0.0.1:{port}/health", timeout=5)
        last = {"ok": ok, "status": status, "body": body, "attempts": attempts}
        if ok:
            append_jsonl(commands_log, {"kind": "http", "method": "GET", "url": f"http://127.0.0.1:{port}/health", "status": status, "ok": ok})
            return True, last
        time.sleep(2)
    return False, last


def manual_adapter(public_task: dict, target: dict, transcript_log: Path) -> dict:
    append_jsonl(
        transcript_log,
        {
            "role": "system",
            "content": "manual adapter baseline: no framework actions executed",
            "visible_case_id": public_task.get("case_id"),
            "target": target,
        },
    )
    append_jsonl(
        transcript_log,
        {
            "role": "assistant",
            "content": "No-op baseline completed without submitting proof.",
        },
    )
    return {"adapter": "manual", "actions": 0, "proof_uploaded": False}


def evaluator_done(evaluator_port: int, commands_log: Path) -> dict:
    url = f"http://127.0.0.1:{evaluator_port}/done"
    ok, status, body = http_json(url, method="POST", payload={})
    append_jsonl(commands_log, {"kind": "http", "method": "POST", "url": url, "status": status, "ok": ok, "body": body})
    return {"ok": ok, "status": status, "body": body}


def score_from_observation(case_id: str, framework: str, observation: dict) -> dict:
    success = bool(observation.get("success"))
    classification = "success" if success else "failure"
    if observation.get("runtime_tested") is not True:
        classification = "not_run"
    return {
        "case_id": case_id,
        "framework": framework,
        "success": success,
        "score": 1.0 if success else 0.0,
        "oracle_classification": classification,
        "observation": observation,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("case_dir")
    parser.add_argument("--framework", default="manual")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--split", choices=["train", "test"])
    parser.add_argument("--run-id")
    parser.add_argument("--results-root", default="results/runs")
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--keep-containers", action="store_true")
    args = parser.parse_args()

    case_dir = Path(args.case_dir).resolve()
    manifest_path = case_dir / "manifest.yml"
    public_task_path = case_dir / "public_task.yml"
    if not manifest_path.exists():
        raise SystemExit(f"Missing manifest: {manifest_path}")
    if not public_task_path.exists():
        raise SystemExit(f"Missing public task: {public_task_path}")

    manifest = load_yaml(manifest_path)
    public_task = load_yaml(public_task_path)
    split = args.split or manifest.get("split", "test")
    case_id = manifest["case_id"]
    run_id = args.run_id or default_run_id(args.framework, split)
    results_root = Path(args.results_root)
    if not results_root.is_absolute():
        results_root = ROOT / results_root
    run_root = results_root / run_id
    out_dir = run_root / case_id
    out_dir.mkdir(parents=True, exist_ok=True)

    transcript_log = out_dir / "transcript.jsonl"
    commands_log = out_dir / "commands.jsonl"
    transcript_log.write_text("", encoding="utf-8")
    commands_log.write_text("", encoding="utf-8")
    shutil.copyfile(public_task_path, out_dir / "public_task.yml")
    write_json(out_dir / "manifest_summary.json", sanitized_manifest(manifest))

    started = utc_now()
    errors: list[str] = []
    status = "dry-run" if args.dry_run else "running"
    observation = {
        "case_id": case_id,
        "success": False,
        "runtime_tested": False,
        "objective_type": manifest.get("objective", {}).get("type", "unknown"),
        "evidence": {"mode": "dry-run" if args.dry_run else "manual-no-op"},
        "comparison": {"performed": False, "reason": "framework adapter did not submit a proof"},
        "oracle_result": "not_run",
    }

    runtime = manifest.get("runtime", {}) if isinstance(manifest.get("runtime"), dict) else {}
    target = public_task.get("target", {}) if isinstance(public_task.get("target"), dict) else {}
    evaluator_port = int(runtime.get("evaluator_port", 0) or 0)
    env = os.environ.copy()
    env["EVALUATOR_STATE_HOST_DIR"] = str(out_dir / "evaluator-state")

    try:
        adapter_result = manual_adapter(public_task, target, transcript_log)
        if args.framework != "manual":
            append_jsonl(
                transcript_log,
                {
                    "role": "system",
                    "content": f"framework adapter '{args.framework}' is not integrated; manual no-op contract used",
                },
            )
        if not args.dry_run:
            down = run_command(["docker", "compose", "down", "-v"], case_dir, args.timeout_seconds, commands_log, env=env)
            if down.returncode != 0:
                errors.append("pre-run docker compose down failed")
            up = run_command(["docker", "compose", "up", "-d", "--build"], case_dir, args.timeout_seconds, commands_log, env=env)
            if up.returncode != 0:
                errors.append("docker compose up failed")
                status = "infra_error"
            else:
                evaluator_ok, evaluator_health = wait_for_evaluator(evaluator_port, min(args.timeout_seconds, 90), commands_log)
                if not evaluator_ok:
                    errors.append(f"evaluator did not become reachable: {evaluator_health}")
                    status = "infra_error"
                else:
                    done = evaluator_done(evaluator_port, commands_log)
                    observation = done["body"] if isinstance(done.get("body"), dict) else observation
                    status = "completed"
    except subprocess.TimeoutExpired as exc:
        errors.append(f"timeout running command: {exc.cmd}")
        status = "timeout"
    finally:
        if not args.dry_run and not args.keep_containers:
            cleanup = run_command(["docker", "compose", "down", "-v"], case_dir, args.timeout_seconds, commands_log, env=env)
            if cleanup.returncode != 0:
                errors.append("cleanup docker compose down failed")

    score = score_from_observation(case_id, args.framework, observation)
    write_json(out_dir / "observation.json", observation)
    write_json(out_dir / "score.json", score)
    run = {
        "case_id": case_id,
        "split": split,
        "framework": args.framework,
        "run_id": run_id,
        "started_utc": started,
        "finished_utc": utc_now(),
        "status": "failed" if errors and status == "completed" else status,
        "dry_run": args.dry_run,
        "timeout_seconds": args.timeout_seconds,
        "score": score["score"],
        "success": score["success"],
        "errors": errors,
        "result_files": {
            "public_task": "public_task.yml",
            "manifest_summary": "manifest_summary.json",
            "transcript": "transcript.jsonl",
            "commands": "commands.jsonl",
            "observation": "observation.json",
            "score": "score.json",
            "run": "run.json",
        },
        "adapter": adapter_result,
    }
    write_json(out_dir / "run.json", run)
    print(out_dir)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
