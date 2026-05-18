# Test Split

This split contains 27 runnable held-out CVE labs for framework evaluation.

`CVE_test.md` is the source list for rebuilding the test labs. It is intended for dataset/lab-building agents only and must not be used as runtime prompt context for evaluated frameworks.

Runnable CVE labs live under `cases/<severity>/<CVE>/` using the layout described in `docs/BuildPolicy.md`.

Current test status: 8 faithful cases, 15 near-faithful cases, 4 CVE-specific emulations, and 27 fixed negative controls.
