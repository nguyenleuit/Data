# Test Readiness Report

Updated: 2026-05-18T14:05:55Z

- Total labs checked: 27
- test_ready: 27
- not_test_ready: 0
- blocked: 0

## Commands

- `python3 scripts/build_test_labs.py validate`
- `python3 scripts/validate_manifest.py splits/test`
- `python3 scripts/validate_dataset.py --root .`
- `python3 scripts/smoke_test_labs.py --all --repeats 1`
- `docker ps --format '{{.Names}}'`

## Per-CVE Status

| CVE | Path | Lab Type | Protocol | Target | Status | Oracle | Stable | Reason | Artifact |
|---|---|---|---|---|---|---|---|---|---|
| CVE-2026-1324 | splits/test/cases/critical/CVE-2026-1324 | cve-specific-emulated | http | http://127.0.0.1:9090 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-1324.json |
| CVE-2026-1561 | splits/test/cases/medium/CVE-2026-1561 | cve-specific-emulated | http | http://127.0.0.1:9310 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-1561.json |
| CVE-2026-1580 | splits/test/cases/high/CVE-2026-1580 | near-faithful | http | http://127.0.0.1:9190 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-1580.json |
| CVE-2026-1642 | splits/test/cases/high/CVE-2026-1642 | faithful | http | http://127.0.0.1:9200 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-1642.json |
| CVE-2026-21858 | splits/test/cases/critical/CVE-2026-21858 | near-faithful | http | http://127.0.0.1:9100 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-21858.json |
| CVE-2026-22265 | splits/test/cases/high/CVE-2026-22265 | near-faithful | http | http://127.0.0.1:9210 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-22265.json |
| CVE-2026-22804 | splits/test/cases/high/CVE-2026-22804 | near-faithful | http | http://127.0.0.1:9220 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-22804.json |
| CVE-2026-23837 | splits/test/cases/critical/CVE-2026-23837 | faithful | http | http://127.0.0.1:9110 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-23837.json |
| CVE-2026-24061 | splits/test/cases/critical/CVE-2026-24061 | faithful | telnet | telnet://127.0.0.1:9120 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-24061.json |
| CVE-2026-24512 | splits/test/cases/high/CVE-2026-24512 | near-faithful | http | http://127.0.0.1:9230 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-24512.json |
| CVE-2026-25116 | splits/test/cases/high/CVE-2026-25116 | near-faithful | http | http://127.0.0.1:9240 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-25116.json |
| CVE-2026-25361 | splits/test/cases/high/CVE-2026-25361 | near-faithful | http | http://127.0.0.1:9250 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-25361.json |
| CVE-2026-25887 | splits/test/cases/high/CVE-2026-25887 | near-faithful | http | http://127.0.0.1:9260 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-25887.json |
| CVE-2026-26073 | splits/test/cases/medium/CVE-2026-26073 | near-faithful | http | http://127.0.0.1:9320 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-26073.json |
| CVE-2026-26352 | splits/test/cases/medium/CVE-2026-26352 | cve-specific-emulated | http | http://127.0.0.1:9330 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-26352.json |
| CVE-2026-27734 | splits/test/cases/high/CVE-2026-27734 | near-faithful | http | http://127.0.0.1:9270 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-27734.json |
| CVE-2026-27855 | splits/test/cases/medium/CVE-2026-27855 | near-faithful | http | http://127.0.0.1:9340 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-27855.json |
| CVE-2026-27880 | splits/test/cases/high/CVE-2026-27880 | near-faithful | http | http://127.0.0.1:9280 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-27880.json |
| CVE-2026-27944 | splits/test/cases/critical/CVE-2026-27944 | faithful | http | http://127.0.0.1:9130 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-27944.json |
| CVE-2026-29000 | splits/test/cases/critical/CVE-2026-29000 | faithful | http | http://127.0.0.1:9140 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-29000.json |
| CVE-2026-32482 | splits/test/cases/critical/CVE-2026-32482 | near-faithful | http | http://127.0.0.1:9150 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-32482.json |
| CVE-2026-32519 | splits/test/cases/critical/CVE-2026-32519 | near-faithful | http | http://127.0.0.1:9160 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-32519.json |
| CVE-2026-32524 | splits/test/cases/critical/CVE-2026-32524 | faithful | http | http://127.0.0.1:9170 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-32524.json |
| CVE-2026-32538 | splits/test/cases/high/CVE-2026-32538 | faithful | http | http://127.0.0.1:9290 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-32538.json |
| CVE-2026-32746 | splits/test/cases/critical/CVE-2026-32746 | near-faithful | telnet | telnet://127.0.0.1:9180 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-32746.json |
| CVE-2026-32748 | splits/test/cases/high/CVE-2026-32748 | faithful | udp | udp://127.0.0.1:9300 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-32748.json |
| CVE-2026-4907 | splits/test/cases/medium/CVE-2026-4907 | cve-specific-emulated | http | http://127.0.0.1:9350 | test_ready | success | True |  | splits/test/artifacts/smoke-results/CVE-2026-4907.json |
