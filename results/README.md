# Results

Benchmark results are stored under `runs/` with one directory per framework/model/config execution.

`scripts/run_split.py` writes split-level summaries:

```text
runs/<run_id>/
  summary.json
  summary.md
```

`scripts/run_case.py` writes one directory per case inside the run directory:

```text
runs/<run_id>/<case_id>/
  public_task.yml
  manifest_summary.json
  transcript.jsonl
  commands.jsonl
  observation.json
  score.json
  run.json
  evaluator-state/
```

Run results should not be written back into `splits/*/cases/*/artifacts`; runtime scratch state belongs under the matching `results/runs/<run_id>/<case_id>/` directory.
