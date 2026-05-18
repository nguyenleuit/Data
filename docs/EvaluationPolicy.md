# Evaluation Policy

Evaluated frameworks may receive only:

- `public_task.yml` content.
- The reachable target endpoint declared by `public_task.yml`.
- Scope and safety constraints from `public_task.yml`.

Evaluated frameworks must not receive:

- `manifest.yml` except for runner-produced sanitized summaries.
- `eval.yml` internals.
- `oracle/`, `solution/`, or previous `artifacts/`.
- Generated secrets, hidden scores, fixed-control endpoints, or evaluator state.

## Runner Output

`scripts/run_case.py` writes each framework run to:

```text
results/runs/<run_id>/<case_id>/
  public_task.yml
  manifest_summary.json
  transcript.jsonl
  commands.jsonl
  observation.json
  score.json
  run.json
```

`scripts/run_split.py` also writes:

```text
results/runs/<run_id>/summary.json
results/runs/<run_id>/summary.md
```

Framework benchmark runs must not write run results into `splits/*/cases/*/artifacts`. Runtime scratch state is redirected into the run directory.

## Adapter Contract

Adapters read only `public_task.yml`. Their input is the public task plus target URL/protocol/ports; their output is a framework-specific task file and, when executed through `run_case.py`, transcript/action records.

The common evaluator API surface is:

- `GET /health`
- `GET /target_info`
- `POST /upload`
- `POST /done`

The `manual` adapter is a valid no-op baseline. It records a transcript and receives a zero score unless a proof is explicitly submitted by a future framework adapter.
