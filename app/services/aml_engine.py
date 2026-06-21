"""
Dedicated AML Engine — Transaction-Risk Intelligence.

Consolidates all AML detection:
- Pending KYC status
- Large cash deposits (>₹5L)
- Multiple large deposits (2+)
- Offshore jurisdiction transfers
- Large wire / international transfers (>₹10L)
- Rapid movement of funds

Each finding contributes to a cumulative risk score (0–100) mapped to
severity bands aligned with PMLA 2002 and FATF guidelines.
"""
import re
from typing import List, Dict, Optional, Tuple


__all__ = ["AMLResult", "analyze", "CASH_THRESHOLD", "WIRE_THRESHOLD"]


# ── Thresholds ────────────────────────────────────────────────────────

CASH_THRESHOLD = 500000
WIRE_THRESHOLD = 1000000


# ── Risk Configuration ────────────────────────────────────────────────

RISK_WEIGHTS = {
    "pending_kyc": 30,
    "large_cash_deposit": 30,
    "multiple_large_deposits": 20,
    "offshore_transfer": 40,
    "large_wire_transfer": 40,
    "rapid_movement": 20,
}

RISK_BANDS = [
    (0, 20, "LOW"),
    (21, 50, "MEDIUM"),
    (51, 80, "HIGH"),
    (81, 100, "CRITICAL"),
]


# ── High-Risk Jurisdictions ───────────────────────────────────────────

HIGH_RISK_JURISDICTIONS = [
    "CAYMAN ISLANDS",
    "PANAMA",
    "SEYCHELLES",
    "BELIZE",
    "BRITISH VIRGIN ISLANDS",
    "VANUATU",
]


# ── Compiled Regex Patterns ──────────────────────────────────────────

KYC_PENDING_RE = re.compile(r"KYC\s*STATUS\s*:\s*PENDING", re.IGNORECASE)

CASH_DEPOSIT_RE = re.compile(
    r"(?:cash\s*deposit|cash\s*dep|cash\s*credited|by\s*cash)",
    re.IGNORECASE,
)

WIRE_TRANSFER_RE = re.compile(
    r"(?:wire\s*transfer|international\s*transfer|rtgs|neft|imps|telegraphic)",
    re.IGNORECASE,
)

RAPID_MOVEMENT_RE = re.compile(
    r"(?:large\s*credit|large\s*deposit|rapid\s*movement|funds\s*moved)",
    re.IGNORECASE,
)

AMOUNT_RE = re.compile(r"(?:[₹$€£]\s*)?([\d,]+(?:\.\d{1,2})?)")


# ── AML Result ────────────────────────────────────────────────────────

class AMLResult:
    """Structured result from the AML analysis pipeline."""

    def __init__(
        self,
        risk_score: float = 0.0,
        severity: str = "LOW",
        findings: Optional[List[Dict]] = None,
        flags: Optional[Dict[str, bool]] = None,
    ):
        self.risk_score = round(min(risk_score, 100.0), 1)
        self.severity = severity
        self.findings = findings or []
        self.flags = flags or {}

    def to_dict(self) -> Dict:
        return {
            "risk_score": self.risk_score,
            "severity": self.severity,
            "findings": self.findings,
            "flags": self.flags,
        }


# ── Helpers ───────────────────────────────────────────────────────────

def _classify_risk(score: float) -> str:
    """Map a risk score to its severity band."""
    for lo, hi, label in RISK_BANDS:
        if lo <= score <= hi:
            return label
    return "CRITICAL"


def _extract_amounts(text: str) -> List[float]:
    """Extract all monetary amounts from text."""
    amounts = []
    for m in AMOUNT_RE.finditer(text):
        raw = m.group(1).replace(",", "")
        if not raw.replace(".", "").isdigit():
            continue
        amounts.append(float(raw))
    return amounts


def _find_context(line: str, keyword_re: re.Pattern) -> bool:
    """Check if a line matches the given pattern."""
    return bool(keyword_re.search(line))


# ── Detection Functions ───────────────────────────────────────────────

def detect_pending_kyc(ocr_text: str) -> bool:
    """Check if OCR text contains a pending KYC status."""
    return bool(KYC_PENDING_RE.search(ocr_text)) if ocr_text else False


def detect_offshore_jurisdiction(ocr_text: str) -> Optional[str]:
    """Return the first matched high-risk jurisdiction, or None."""
    if not ocr_text:
        return None
    lower = ocr_text.lower()
    for j in HIGH_RISK_JURISDICTIONS:
        if j.lower() in lower:
            return j
    return None


def extract_cash_deposit_amounts(ocr_text: str) -> List[float]:
    """Extract amounts from lines tagged as cash deposits."""
    amounts = []
    if not ocr_text:
        return amounts
    for line in ocr_text.splitlines():
        if CASH_DEPOSIT_RE.search(line):
            amounts.extend(_extract_amounts(line))
    return amounts


def extract_wire_transfer_amounts(ocr_text: str) -> List[float]:
    """Extract amounts from lines tagged as wire / electronic transfers."""
    amounts = []
    if not ocr_text:
        return amounts
    for line in ocr_text.splitlines():
        if WIRE_TRANSFER_RE.search(line):
            amounts.extend(_extract_amounts(line))
    return amounts


def detect_rapid_movement(ocr_text: str) -> bool:
    """Detect keywords suggesting rapid account movement."""
    if not ocr_text:
        return False
    return bool(RAPID_MOVEMENT_RE.search(ocr_text))


# ── Public API ────────────────────────────────────────────────────────

def analyze(ocr_text: str) -> AMLResult:
    """Run all AML checks against OCR-extracted text.

    Returns an AMLResult with cumulative risk score, severity band,
    per-finding details, and boolean flags for each detection type.
    """
    risk = 0
    findings: List[Dict] = []
    flags: Dict[str, bool] = {}

    # 1. Pending KYC
    flags["pending_kyc"] = detect_pending_kyc(ocr_text)
    if flags["pending_kyc"]:
        risk += RISK_WEIGHTS["pending_kyc"]
        findings.append({
            "finding": "KYC verification incomplete",
            "severity": "HIGH",
            "risk_points": RISK_WEIGHTS["pending_kyc"],
            "field": "kyc_status",
            "evidence": "KYC Status: Pending detected in OCR text",
        })

    # 2. Offshore jurisdiction
    offshore = detect_offshore_jurisdiction(ocr_text)
    flags["offshore_transfer"] = offshore is not None
    if offshore:
        risk += RISK_WEIGHTS["offshore_transfer"]
        findings.append({
            "finding": f"Transfer to offshore jurisdiction — {offshore}",
            "severity": "CRITICAL",
            "risk_points": RISK_WEIGHTS["offshore_transfer"],
            "field": "aml",
            "evidence": f"High-risk jurisdiction '{offshore}' referenced in document",
        })

    # 3. Large cash deposits
    cash_amounts = extract_cash_deposit_amounts(ocr_text)
    large_cash = [a for a in cash_amounts if a > CASH_THRESHOLD]
    flags["large_cash_deposit"] = len(large_cash) > 0
    if large_cash:
        risk += RISK_WEIGHTS["large_cash_deposit"]
        evidence = f"Cash deposit(s) exceeding ₹{CASH_THRESHOLD:,}: {', '.join(f'₹{a:,.2f}' for a in large_cash)}"
        findings.append({
            "finding": "Large cash deposit detected",
            "severity": "HIGH",
            "risk_points": RISK_WEIGHTS["large_cash_deposit"],
            "field": "aml",
            "evidence": evidence,
        })

    # 4. Multiple large deposits (2+)
    flags["multiple_large_deposits"] = len(large_cash) >= 2
    if len(large_cash) >= 2:
        risk += RISK_WEIGHTS["multiple_large_deposits"]
        findings.append({
            "finding": "Multiple large cash deposits detected",
            "severity": "CRITICAL",
            "risk_points": RISK_WEIGHTS["multiple_large_deposits"],
            "field": "aml",
            "evidence": f"{len(large_cash)} cash deposits each exceeding ₹{CASH_THRESHOLD:,}",
        })

    # 5. Large wire / international transfers
    wire_amounts = extract_wire_transfer_amounts(ocr_text)
    large_wires = [a for a in wire_amounts if a > WIRE_THRESHOLD]
    flags["large_wire_transfer"] = len(large_wires) > 0
    if large_wires:
        risk += RISK_WEIGHTS["large_wire_transfer"]
        evidence = f"Wire transfer(s) exceeding ₹{WIRE_THRESHOLD:,}: {', '.join(f'₹{a:,.2f}' for a in large_wires)}"
        findings.append({
            "finding": "Large international wire transfer detected",
            "severity": "CRITICAL",
            "risk_points": RISK_WEIGHTS["large_wire_transfer"],
            "field": "aml",
            "evidence": evidence,
        })

    # 6. Rapid movement of funds
    flags["rapid_movement"] = detect_rapid_movement(ocr_text)
    if flags["rapid_movement"]:
        risk += RISK_WEIGHTS["rapid_movement"]
        findings.append({
            "finding": "Rapid movement of funds detected",
            "severity": "MEDIUM",
            "risk_points": RISK_WEIGHTS["rapid_movement"],
            "field": "aml",
            "evidence": "Keywords suggesting rapid account movement found in OCR text",
        })

    risk = min(risk, 100)
    severity = _classify_risk(risk)

    return AMLResult(
        risk_score=risk,
        severity=severity,
        findings=findings,
        flags=flags,
    )
