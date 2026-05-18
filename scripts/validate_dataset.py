#!/usr/bin/env python3
import argparse
import re
from pathlib import Path


REQUIRED_DIRS = [
    "splits/train/cases/critical",
    "splits/train/cases/high",
    "splits/train/cases/medium",
    "splits/test/cases/critical",
    "splits/test/cases/high",
    "splits/test/cases/medium",
    "common/docker",
    "common/evaluator/app",
    "common/secrets",
    "schemas",
    "scripts",
    "adapters/hacksynth",
    "adapters/pentestgpt",
    "adapters/vulnbot",
    "adapters/pentestagent",
    "results/runs",
    "docs",
]

REQUIRED_FILES = [
    "README.md",
    "dataset.yml",
    "splits/test/CVE_test.md",
    "docs/SplitPolicy.md",
    "docs/BuildPolicy.md",
    "docs/EvaluationPolicy.md",
    "schemas/manifest.schema.yml",
    "schemas/public_task.schema.yml",
    "schemas/eval.schema.yml",
    "schemas/observation.schema.yml",
    "schemas/score.schema.yml",
]


def count_cves(cve_test: Path) -> int:
    text = cve_test.read_text(encoding="utf-8")
    return len(set(re.findall(r"CVE-\d{4}-\d+", text)))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--expected-test-cves", type=int, default=27)
    args = parser.parse_args()

    root = Path(args.root)
    errors: list[str] = []

    for rel in REQUIRED_DIRS:
        if not (root / rel).is_dir():
            errors.append(f"missing directory: {rel}")

    for rel in REQUIRED_FILES:
        if not (root / rel).is_file():
            errors.append(f"missing file: {rel}")

    if (root / "src").exists():
        errors.append("legacy Data/src still exists")

    cve_test = root / "splits/test/CVE_test.md"
    if cve_test.exists():
        cve_count = count_cves(cve_test)
        if cve_count != args.expected_test_cves:
            errors.append(
                f"CVE_test.md has {cve_count} unique CVEs; expected {args.expected_test_cves}"
            )

    if errors:
        print("Dataset validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    print("Dataset structure validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
