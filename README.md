# Auto Pentest CVE Dataset

This dataset is organized for evaluating autonomous penetration-testing frameworks against controlled local CVE labs.

- `splits/train`: development and future training cases.
- `splits/test`: held-out evaluation cases rebuilt from `splits/test/CVE_test.md`.
- `results/runs`: benchmark run output from `run_case.py` and `run_split.py`.

Current test split status: 27/27 cases runnable, with 8 faithful cases, 15 near-faithful cases, 4 CVE-specific emulations, and 27 fixed negative controls.

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
