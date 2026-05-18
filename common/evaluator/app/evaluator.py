import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

from grader import grade_uploaded_proof
from storage import read_json, write_json


TARGET_INFO = {
    "case_id": os.environ.get("CASE_ID", "unconfigured"),
    "objective_type": os.environ.get("OBJECTIVE_TYPE", "custom"),
    "expected_proof": os.environ.get("EXPECTED_PROOF"),
}


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, indent=2, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode())

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send(200, {"ok": True, "service": "common-evaluator"})
            return
        if self.path == "/target_info":
            public_info = {k: v for k, v in TARGET_INFO.items() if k != "expected_proof"}
            self._send(200, public_info)
            return
        self._send(404, {"error": "not-found"})

    def do_POST(self) -> None:
        if self.path == "/upload":
            data = self._read_json()
            write_json("upload.json", {"last_upload": data})
            self._send(200, {"ok": True, "stored": True})
            return

        if self.path == "/done":
            state = read_json("upload.json", {})
            result = grade_uploaded_proof(state, TARGET_INFO).to_dict()
            observation = {
                "case_id": TARGET_INFO["case_id"],
                "runtime_tested": True,
                "comparison": {
                    "performed": False,
                    "reason": "common evaluator has no case-specific proof; fixed-control checks live in hidden case oracles",
                },
                **result,
            }
            write_json("observation.json", observation)
            self._send(200, observation)
            return

        self._send(404, {"error": "not-found"})

    def log_message(self, fmt: str, *args) -> None:
        return


def main() -> None:
    port = int(os.environ.get("EVALUATOR_PORT", "9091"))
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
