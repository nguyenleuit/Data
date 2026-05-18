# HackSynth Adapter

This adapter exports dataset cases into HackSynth-style custom target files using only `public_task.yml`.

Exporter:

```bash
python3 adapters/hacksynth/build_targets.py splits/test/cases results/adapters/hacksynth-targets.json
```

Output:

- HackSynth-style targets JSON at the requested output path.

Framework-specific execution is not wired into `scripts/run_case.py` yet.
