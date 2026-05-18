import json
import os
from pathlib import Path


def state_dir() -> Path:
    path = Path(os.environ.get("EVALUATOR_STATE_DIR", "/state"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_json(name: str, data: dict) -> Path:
    path = state_dir() / name
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def read_json(name: str, default: dict | None = None) -> dict:
    path = state_dir() / name
    if not path.exists():
        return default or {}
    return json.loads(path.read_text(encoding="utf-8"))
