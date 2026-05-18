# Common Evaluator

The evaluator exposes a small HTTP API used by runners after a framework attempts a case.

Endpoints:

- `GET /health`
- `GET /target_info`
- `POST /upload`
- `POST /done`

Case-specific logic should live in each case's `oracle/` directory and be wired into the evaluator during the lab rebuild phase.
