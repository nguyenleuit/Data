# Adapter Contract

Adapters export framework-specific task/target files from public benchmark material only:

- `public_task.yml`
- the target endpoint declared inside `public_task.yml`

Adapters must not read `manifest.yml`, `eval.yml`, `oracle/`, `solution/`, or existing `artifacts/`.

Current exporter scripts:

- `hacksynth/build_targets.py`: writes a HackSynth-style `targets.json`.
- `pentestgpt/build_tasks.py`: writes PentestGPT task prompts.
- `pentestagent/build_tasks.py`: writes PentestAgent task definitions.
- `vulnbot/build_tasks.py`: writes VulnBot target descriptions.

Full framework execution remains outside the dataset runner; `manual` is the runner's no-op baseline.

The common output contract is:

- framework-visible task text or JSON
- target URL/protocol/ports from the public task
- scope constraints from the public task
- optional transcript/action log written by `scripts/run_case.py`
