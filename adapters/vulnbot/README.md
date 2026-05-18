# VulnBot Adapter

This adapter exports dataset cases into VulnBot target descriptions and runtime config using only `public_task.yml`.

Exporter:

```bash
python3 adapters/vulnbot/build_tasks.py splits/test/cases results/adapters/vulnbot-targets.json
```

VulnBot runtime Kali/SSH/database execution is not wired into `scripts/run_case.py` yet.
