# Adapter Contract

Adapters must read only public benchmark material:

- `public_task.yml`
- the target endpoint declared inside `public_task.yml`

Adapters must not read `manifest.yml`, `eval.yml`, `oracle/`, `solution/`, or existing `artifacts/`.

The common output contract is:

- framework-visible task text or JSON
- target URL/protocol/ports from the public task
- scope constraints from the public task
- optional transcript/action log written by `scripts/run_case.py`
