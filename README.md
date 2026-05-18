# Auto Pentest CVE Dataset

This repository contains controlled local CVE labs for developing and evaluating autonomous penetration-testing frameworks.

- `dataset.yml`: dataset metadata, split definitions, framework list, and visibility policy.
- `splits/train`: 40 runnable development/training cases rebuilt from `splits/train/CVE_train.md`.
- `splits/test`: 27 held-out evaluation cases rebuilt from `splits/test/CVE_test.md`.
- `adapters/`: public-only exporters for HackSynth, PentestGPT, PentestAgent, and VulnBot.
- `common/`: shared Docker, evaluator, schema, and secret-template material.
- `results/runs`: benchmark output from `scripts/run_case.py` and `scripts/run_split.py`.

Current dataset status:

| Split | Cases | Severity Mix | Fidelity Mix | Fixed Controls |
| --- | ---: | --- | --- | --- |
| Train | 40/40 runnable | 23 critical, 14 high, 3 medium | 4 faithful, 17 near-faithful, 19 CVE-specific emulated | Not required for train |
| Test | 27/27 runnable | 10 critical, 12 high, 5 medium | 8 faithful, 15 near-faithful, 4 CVE-specific emulated | 27 present |

## Quickstart

Validate structure and manifests:

```bash
python3 scripts/validate_dataset.py
python3 scripts/validate_manifest.py splits/test
python3 scripts/validate_train_dataset.py
```

Run a manual dry-run over the test split:

```bash
python3 scripts/run_split.py test --framework manual --dry-run
```

Inspect results under `results/runs/<run_id>/summary.json` and per-case `run.json`, `transcript.jsonl`, and `score.json`.

Run smoke tests for the local Docker labs:

```bash
python3 scripts/smoke_test_labs.py --all
```

Evaluated frameworks must only receive public task material. Hidden oracle, evaluator, artifact, fixed-control, and solution material must not be exposed during benchmark runs.
