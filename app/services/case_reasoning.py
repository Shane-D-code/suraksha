"""
Case-Based Reasoning Engine — Document Similarity Search.

Stores and retrieves past document analysis cases for precedent-based
decision support. Uses feature vector similarity to find the most
comparable historical cases and their outcomes.
"""
import structlog
from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime

logger = structlog.get_logger(__name__)


@dataclass
class DocumentCase:
    case_id: str
    timestamp: str
    bank_name: Optional[str]
    risk_score: int
    decision: str
    override_reason: Optional[str]
    features: dict
    findings_summary: List[str]
    outcome: str


class CaseReasoningEngine:
    """In-memory case store with similarity search.
    
    In production this would use a vector database (FAISS, pgvector).
    Current implementation uses simple feature-vector cosine similarity.
    """

    def __init__(self):
        self.cases: List[DocumentCase] = []

    def store_case(self, case: DocumentCase) -> None:
        self.cases.append(case)
        logger.info("CASE_STORED", case_id=case.case_id, decision=case.decision)

    def find_similar(self, features: dict, top_k: int = 3) -> List[dict]:
        """Find top-k most similar past cases by feature overlap."""
        if not self.cases:
            return []

        query_vec = self._vectorise(features)
        scored = []
        for case in self.cases:
            case_vec = self._vectorise(case.features)
            sim = self._cosine_similarity(query_vec, case_vec)
            scored.append((sim, case))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [
            {
                "similarity_pct": round(sim * 100, 1),
                "case_id": case.case_id,
                "decision": case.decision,
                "outcome": case.outcome,
                "risk_score": case.risk_score,
                "bank_name": case.bank_name,
                "timestamp": case.timestamp,
                "findings": case.findings_summary[:3],
            }
            for sim, case in scored[:top_k]
            if sim > 0.3
        ]

    def _vectorise(self, features: dict) -> List[float]:
        """Convert feature dict to a flat numeric vector."""
        vec = []
        vec.append(float(features.get("risk_score", 0)))
        vec.append(float(features.get("num_findings", 0)))
        vec.append(float(features.get("num_critical", 0)))
        vec.append(float(features.get("num_high", 0)))
        vec.append(float(features.get("has_template", 0)))
        vec.append(float(features.get("has_balance_mismatch", 0)))
        vec.append(float(features.get("has_txn_mismatch", 0)))
        vec.append(float(features.get("has_currency_mismatch", 0)))
        vec.append(float(features.get("has_account_missing", 0)))
        vec.append(float(features.get("has_ifsc_missing", 0)))
        return vec

    @staticmethod
    def _cosine_similarity(a: List[float], b: List[float]) -> float:
        if len(a) != len(b):
            return 0.0
        dot = sum(x * y for x, y in zip(a, b))
        na = sum(x * x for x in a) ** 0.5
        nb = sum(y * y for y in b) ** 0.5
        if na == 0 or nb == 0:
            return 0.0
        return dot / (na * nb)


_case_store = CaseReasoningEngine()


def get_case_store() -> CaseReasoningEngine:
    return _case_store


def build_case_features(banking_result: dict) -> dict:
    findings = banking_result.get("findings", [])
    return {
        "risk_score": banking_result.get("authenticity_score", 50),
        "num_findings": len(findings),
        "num_critical": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
        "num_high": sum(1 for f in findings if f.get("severity") == "HIGH"),
        "has_template": int(any(f.get("field") == "document_authenticity" for f in findings)),
        "has_balance_mismatch": int(any(
            "balance" in f.get("finding", "").lower() and "reconciliation" in f.get("finding", "").lower()
            for f in findings
        )),
        "has_txn_mismatch": int(any(
            "transaction total mismatch" in f.get("finding", "").lower()
            for f in findings
        )),
        "has_currency_mismatch": int(any(
            f.get("field") == "currency_consistency" for f in findings
        )),
        "has_account_missing": int(any(
            "missing account number" in f.get("finding", "").lower()
            for f in findings
        )),
        "has_ifsc_missing": int(any(
            "missing ifsc" in f.get("finding", "").lower()
            for f in findings
        )),
    }
