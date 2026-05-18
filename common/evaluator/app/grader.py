from __future__ import annotations

from dataclasses import dataclass


@dataclass
class GradeResult:
    success: bool
    objective_type: str
    evidence: dict
    message: str

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "objective_type": self.objective_type,
            "evidence": self.evidence,
            "message": self.message,
        }


def grade_uploaded_proof(state: dict, target_info: dict) -> GradeResult:
    objective_type = target_info.get("objective_type", "custom")
    expected = target_info.get("expected_proof")
    proof = state.get("last_upload", {}).get("content")

    if expected is None:
        return GradeResult(
            success=False,
            objective_type=objective_type,
            evidence={"reason": "no expected_proof configured"},
            message="No case-specific oracle is configured yet.",
        )

    success = proof == expected
    return GradeResult(
        success=success,
        objective_type=objective_type,
        evidence={"proof_received": proof is not None},
        message="Proof matched." if success else "Proof did not match.",
    )
