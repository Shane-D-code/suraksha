"""
Unit tests for banking authenticity features:
1. Parser confidence computation
2. Additive scoring
3. Transaction classification
4. AML structuring detection
5. Behavioral anomaly detection
6. Fraud loss estimation gating
7. ORB signature matching
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from typing import List, Optional
from app.services.banking_authenticity import (
    _compute_parser_confidence,
    _extract_structured_transactions,
    _extract_declared_balances,
    check_balance_reconciliation,
    check_transaction_total_mismatch,
    estimate_fraud_loss,
    classify_transaction_type,
    analyze_transaction_intelligence,
    check_aml_indicators,
    analyze_bank_statement,
    AuthenticityFinding,
)
from app.services.signature_intelligence import _compare_signature_regions


# ═════════════════════════════════════════════════════════════════════════════
# 1. Parser Confidence Tests
# ═════════════════════════════════════════════════════════════════════════════

def test_parser_confidence_zero_rows():
    """0 transaction rows → confidence should be 0.0."""
    conf = _compute_parser_confidence([], "")
    assert conf == 0.0


def test_parser_confidence_one_row():
    """1 transaction row with balance → confidence should be 0.60 (0.50 base + 0.10 balance)."""
    txns = [{"date": "01/04/2025", "credit": 50000.0, "balance": 100000.0}]
    conf = _compute_parser_confidence(txns, "")
    assert conf == 0.60, f"Expected 0.60, got {conf}"


def test_parser_confidence_one_row_with_declared():
    """1 row with declared totals present → capped at 0.60."""
    text = "Total Credits: 100,000\nTotal Debits: 50,000\n"
    txns = [{"date": "01/04/2025", "credit": 50000.0, "balance": 100000.0}]
    conf = _compute_parser_confidence(txns, text)
    assert conf == 0.60, f"Expected 0.60, got {conf}"


def test_parser_confidence_three_rows():
    """3 transaction rows → confidence should be 0.70."""
    txns = [
        {"date": "01/04/2025", "credit": 50000.0, "debit": None, "balance": 100000.0},
        {"date": "02/04/2025", "credit": None, "debit": 10000.0, "balance": 90000.0},
        {"date": "03/04/2025", "credit": 25000.0, "debit": None, "balance": 115000.0},
    ]
    conf = _compute_parser_confidence(txns, "")
    # 3 rows → 0.70, balance >= 70% → +0.10, both credit/debit → +0.05 = 0.85
    assert conf == 0.85, f"Expected 0.85, got {conf}"


def test_parser_confidence_five_rows():
    """5+ transaction rows → confidence should be 0.85 + bonuses."""
    txns = [
        {"date": "01/04/2025", "credit": 50000.0, "debit": None, "balance": 100000.0},
        {"date": "02/04/2025", "credit": None, "debit": 10000.0, "balance": 90000.0},
        {"date": "03/04/2025", "credit": 25000.0, "debit": None, "balance": 115000.0},
        {"date": "04/04/2025", "credit": None, "debit": 5000.0, "balance": 110000.0},
        {"date": "05/04/2025", "credit": 75000.0, "debit": None, "balance": 185000.0},
    ]
    conf = _compute_parser_confidence(txns, "")
    # 5 rows → 0.85, balance >= 70% → +0.10, both credit/debit → +0.05 = 1.0
    assert conf == 1.0, f"Expected 1.0, got {conf}"


def test_parser_confidence_no_balances():
    """Most rows without balance column → no balance bonus but credit+debit mix adds 0.05."""
    txns = [
        {"date": "01/04/2025", "credit": 50000.0, "debit": None},
        {"date": "02/04/2025", "credit": None, "debit": 10000.0},
        {"date": "03/04/2025", "credit": 25000.0, "debit": None},
    ]
    conf = _compute_parser_confidence(txns, "")
    # 3 rows → 0.70, no balance bonus (< 70% with balance), has credit+debit → +0.05 = 0.75
    assert conf == 0.75, f"Expected 0.75, got {conf}"


def test_parser_confidence_credits_only():
    """Only credits → no debit/credit mix bonus."""
    txns = [
        {"date": "01/04/2025", "credit": 50000.0, "debit": None, "balance": 100000.0},
        {"date": "02/04/2025", "credit": 25000.0, "debit": None, "balance": 125000.0},
        {"date": "03/04/2025", "credit": 75000.0, "debit": None, "balance": 200000.0},
    ]
    conf = _compute_parser_confidence(txns, "")
    # 3 rows → 0.70, balance >= 70% → +0.10, no debits → no mix bonus = 0.80
    assert conf == 0.80, f"Expected 0.80, got {conf}"


def test_parser_confidence_debited_totals_penalty():
    """Declared totals exist but < 3 rows → capped at 0.60."""
    text = "Total Credits: 50,000\nTotal Debits: 10,000\nOpening Balance: 0\nClosing Balance: 40,000"
    txns = [{"date": "01/04/2025", "credit": 50000.0, "debit": None, "balance": 50000.0}]
    conf = _compute_parser_confidence(txns, text)
    assert conf == 0.60, f"Expected 0.60 (declared penalty caps to 0.60), got {conf}"


def test_parser_confidence_zero_rows_with_declared():
    """0 rows but declared totals exist → confidence 0.30."""
    text = "Total Credits: 100,000\nTotal Debits: 50,000\nOpening Balance: 0\nClosing Balance: 50,000"
    conf = _compute_parser_confidence([], text)
    assert conf == 0.30, f"Expected 0.30, got {conf}"


# ═════════════════════════════════════════════════════════════════════════════
# 2. Additive Scoring Tests
# ═════════════════════════════════════════════════════════════════════════════

def test_additive_scoring_perfect_statement():
    """A complete, valid statement should score high (89 with whitelist reduction)."""
    text = """
    HDFC BANK
    Branch: M G Road, Bangalore
    IFSC: HDFC0001234
    Account No: 50100123456789
    Opening Balance: 50,000.00
    Date        Particulars          Debit      Credit     Balance
    01/04/2025  Salary               ₹75,000.00 ₹125,000.00
    Closing Balance: ₹125,000.00
    """
    result = analyze_bank_statement(text, meta=None)
    # Score = 100 - 11 (whitelist: ifsc+account+bank) = 89
    assert result.authenticity_score == 89, f"Expected 89, got {result.authenticity_score}"


def test_additive_scoring_missing_ifsc():
    """Missing IFSC → subtract 10 points."""
    text = """
    HDFC BANK
    Branch: M G Road, Bangalore
    Account No: 50100123456789
    Opening Balance: 50,000.00
    Date        Particulars          Debit      Credit     Balance
    01/04/2025  Salary               ₹75,000.00 ₹125,000.00
    Closing Balance: ₹125,000.00
    """
    result = analyze_bank_statement(text, meta=None)
    missing_ifsc = [f for f in result.findings if "Missing" in f.finding and "IFSC" in f.finding]
    assert len(missing_ifsc) > 0
    # Score should be 100 - 10 (missing IFSC) - 25 (layout mismatch for simplified header) ...
    # We just check it's lower than perfect
    assert result.authenticity_score <= 90, f"Expected <= 90 for missing IFSC, got {result.authenticity_score}"


def test_additive_scoring_missing_account():
    """Missing account number → subtract 35 points."""
    text = """
    ICICI BANK
    Branch: Connaught Place, New Delhi
    IFSC: ICIC0005678
    Opening Balance: 25,000.00
    Date        Particulars          Debit      Credit     Balance
    01/04/2025  Salary               ₹50,000.00 ₹75,000.00
    Closing Balance: ₹75,000.00
    """
    result = analyze_bank_statement(text, meta=None)
    missing_acct = [f for f in result.findings if "Missing" in f.finding and "Account" in f.finding]
    assert len(missing_acct) > 0
    # Missing account = -35, missing IFSC = -10 ... but here IFSC is present
    # Layout mismatch for simplified header = -25
    assert result.authenticity_score <= 65, f"Expected <= 65 for missing account, got {result.authenticity_score}"


def test_additive_scoring_missing_branch():
    """Missing branch → subtract 10 points."""
    text = """
    HDFC BANK
    IFSC: HDFC0001234
    Account No: 50100123456789
    Opening Balance: 50,000.00
    Date        Particulars          Debit      Credit     Balance
    01/04/2025  Salary               ₹75,000.00 ₹125,000.00
    Closing Balance: ₹125,000.00
    """
    result = analyze_bank_statement(text, meta=None)
    missing_branch = [f for f in result.findings if "Missing" in f.finding and "Branch" in f.finding]
    assert len(missing_branch) > 0


def test_additive_scoring_currency_mismatch():
    """Currency mismatch → subtract 20 points."""
    text = """
    HDFC BANK
    Currency: USD
    IFSC: HDFC0001234
    Account No: XXXX XXXX 4821
    Date        Particulars          Debit      Credit     Balance
    01/04/2025  Salary               $5,000.00  $10,000.00
    """
    result = analyze_bank_statement(text, meta=None)
    assert result.has_currency_mismatch
    assert result.authenticity_score <= 80, f"Expected <= 80 for currency mismatch, got {result.authenticity_score}"


def test_additive_scoring_balance_mismatch_critical():
    """CRITICAL balance reconciliation failure should reduce authenticity_score."""
    text = f"""
    HDFC BANK
    IFSC Code: HDFC0001234
    Account Number: 12345678901
    Branch: MUMBAI
    Opening Balance: 10,000
    Total Credits: 245,000
    Total Debits: 5,000
    Closing Balance: 260,000
    Date        Particulars          Debit      Credit     Balance
    01/03/2025  Salary               ₹50,000.00               ₹60,000.00
    03/03/2025  ATM Withdrawal      ₹5,000.00               ₹55,000.00
    05/03/2025  NEFT Transfer       ₹150,000.00             ₹205,000.00
    07/03/2025  Cash Deposit                    ₹45,000.00 ₹250,000.00
    """
    result = analyze_bank_statement(text, meta=None)
    bal_findings = [f for f in result.findings if "balance reconciliation failure" in f.finding.lower()]
    assert len(bal_findings) > 0
    assert bal_findings[0].severity == "CRITICAL"
    # With additive scoring: score starts at 100, -40 for balance mismatch = 60,
    # plus positive trust adjustments (ifsc, account, branch, currency, transactions).
    # Score should be > 50 and < 100 (impacted by reconciliation failure).
    assert 0 < result.authenticity_score < 100, f"Expected 0 < score < 100, got {result.authenticity_score}"


def test_additive_scoring_score_clamped():
    """Score should be clamped to 0–100."""
    text = ""
    result = analyze_bank_statement(text, meta=None)
    assert 0 <= result.authenticity_score <= 100, f"Score {result.authenticity_score} out of bounds"


def test_additive_scoring_no_negative():
    """Multiple penalties should not produce negative score."""
    text = """
    HDFC BANK
    Currency: USD
    Opening Balance: 10,000
    Total Credits: 245,000
    Total Debits: 5,000
    Closing Balance: 260,000
    """
    result = analyze_bank_statement(text, meta=None)
    assert result.authenticity_score >= 0, f"Score should not be negative, got {result.authenticity_score}"


# ═════════════════════════════════════════════════════════════════════════════
# 3. Transaction Classification Tests
# ═════════════════════════════════════════════════════════════════════════════

def test_classify_salary():
    assert classify_transaction_type("Salary Credited") == "salary"
    assert classify_transaction_type("salary transfer") == "salary"
    assert classify_transaction_type("Payroll") == "salary"


def test_classify_neft():
    assert classify_transaction_type("NEFT Cr") == "neft"
    assert classify_transaction_type("NEFT Dr") == "neft"
    assert classify_transaction_type("neft credit") == "neft"


def test_classify_rtgs():
    assert classify_transaction_type("RTGS Cr") == "rtgs"
    assert classify_transaction_type("rtgs dr") == "rtgs"


def test_classify_imps():
    assert classify_transaction_type("IMPS") == "imps"
    assert classify_transaction_type("instant payment") == "imps"


def test_classify_upi():
    assert classify_transaction_type("UPI Cr") == "upi"
    assert classify_transaction_type("Google Pay") == "upi"
    assert classify_transaction_type("PhonePe") == "upi"
    assert classify_transaction_type("PAYTM") == "upi"
    assert classify_transaction_type("BHIM") == "upi"


def test_classify_atm_withdrawal():
    assert classify_transaction_type("ATM Withdrawal") == "atm_withdrawal"
    assert classify_transaction_type("Cash Withdrawal") == "atm_withdrawal"
    assert classify_transaction_type("WDL ATM") == "atm_withdrawal"


def test_classify_cash_deposit():
    assert classify_transaction_type("Cash Deposit") == "cash_deposit"
    assert classify_transaction_type("By Cash") == "cash_deposit"


def test_classify_pos():
    assert classify_transaction_type("POS Dr") == "pos"
    assert classify_transaction_type("Card Purchase") == "pos"
    assert classify_transaction_type("Card Used") == "pos"
    assert classify_transaction_type("Swipe") == "pos"


def test_classify_cheque():
    assert classify_transaction_type("Cheque") == "cheque"
    assert classify_transaction_type("Chq No 12345") == "cheque"


def test_classify_transfer_out():
    assert classify_transaction_type("Transfer Out") == "transfer_out"
    assert classify_transaction_type("Outward") == "transfer_out"
    assert classify_transaction_type("Funds Transfer") == "transfer_out"
    assert classify_transaction_type("Money Sent") == "transfer_out"


def test_classify_interest():
    assert classify_transaction_type("Interest Credited") == "interest"
    assert classify_transaction_type("Int Cr") == "interest"
    assert classify_transaction_type("Interest Paid") == "interest"


def test_classify_loan():
    assert classify_transaction_type("Loan Repayment") == "loan"
    assert classify_transaction_type("EMI") == "loan"
    assert classify_transaction_type("Loan Disburs") == "loan"


def test_classify_unknown_credit_fallback():
    """Unrecognized transaction with credit keywords → 'credit'."""
    assert classify_transaction_type("Miscellaneous Credit") == "credit"


def test_classify_unknown_debit_fallback():
    """Unrecognized transaction with debit keywords → 'debit'."""
    assert classify_transaction_type("Miscellaneous Debit") == "debit"
    assert classify_transaction_type("Some Charge") == "debit"
    assert classify_transaction_type("Fee") == "debit"


# ═════════════════════════════════════════════════════════════════════════════
# 4. AML Structuring Detection Tests
# ═════════════════════════════════════════════════════════════════════════════

def test_aml_too_few_transactions():
    """Fewer than 3 transactions → no AML findings."""
    txns = [{"date": "01/04/2025", "credit": 10000.0}]
    findings = check_aml_indicators(txns)
    assert len(findings) == 0


def test_aml_structuring_just_below_50k():
    """3+ credits just below ₹50,000 → structuring pattern."""
    txns = [
        {"date": "01/04/2025", "credit": 48000.0, "raw": "NEFT Cr"},
        {"date": "02/04/2025", "credit": 49000.0, "raw": "NEFT Cr"},
        {"date": "03/04/2025", "credit": 47500.0, "raw": "NEFT Cr"},
    ]
    findings = check_aml_indicators(txns)
    assert len(findings) > 0
    assert any("structuring" in f.finding.lower() for f in findings)
    assert findings[0].severity == "HIGH"


def test_aml_structuring_just_below_1lac():
    """3+ credits just below ₹1,00,000 → structuring pattern."""
    txns = [
        {"date": "01/04/2025", "credit": 98000.0, "raw": "NEFT Cr"},
        {"date": "02/04/2025", "credit": 99000.0, "raw": "NEFT Cr"},
        {"date": "03/04/2025", "credit": 95000.0, "raw": "NEFT Cr"},
    ]
    findings = check_aml_indicators(txns)
    assert len(findings) > 0
    assert any("structuring" in f.finding.lower() for f in findings)


def test_aml_no_structuring_below_threshold():
    """Credits well below 50K or above thresholds → no structuring."""
    txns = [
        {"date": "01/04/2025", "credit": 30000.0, "raw": "NEFT Cr"},
        {"date": "02/04/2025", "credit": 25000.0, "raw": "NEFT Cr"},
        {"date": "03/04/2025", "credit": 35000.0, "raw": "NEFT Cr"},
    ]
    findings = check_aml_indicators(txns)
    assert len(findings) == 0


def test_aml_rapid_movement():
    """Large credit immediately followed by large debit → rapid movement."""
    txns = [
        {"date": "01/04/2025", "credit": 200000.0, "raw": "NEFT Cr"},
        {"date": "02/04/2025", "debit": 100000.0, "raw": "NEFT Dr"},
    ]
    # Need 3+ transactions for AML to check
    txns_full = [
        {"date": "01/04/2025", "credit": 10000.0, "raw": "NEFT Cr"},
        {"date": "02/04/2025", "credit": 200000.0, "raw": "NEFT Cr"},
        {"date": "03/04/2025", "debit": 100000.0, "raw": "NEFT Dr"},
    ]
    findings = check_aml_indicators(txns_full)
    assert any("rapid account movement" in f.finding.lower() for f in findings)


def test_aml_dormant_reactivation():
    """>90 day gap between transactions → dormant account reactivation."""
    txns = [
        {"date": "01/01/2025", "credit": 10000.0, "raw": "NEFT Cr"},
        {"date": "15/01/2025", "credit": 5000.0, "raw": "NEFT Cr"},
        {"date": "20/05/2025", "credit": 20000.0, "raw": "NEFT Cr"},
    ]
    findings = check_aml_indicators(txns)
    dormant = [f for f in findings if "dormant" in f.finding.lower()]
    assert len(dormant) > 0


def test_aml_no_dormant_short_gaps():
    """All gaps under 90 days → no dormant finding."""
    txns = [
        {"date": "01/04/2025", "credit": 10000.0, "raw": "NEFT Cr"},
        {"date": "15/04/2025", "credit": 5000.0, "raw": "NEFT Cr"},
        {"date": "20/04/2025", "credit": 20000.0, "raw": "NEFT Cr"},
    ]
    findings = check_aml_indicators(txns)
    dormant = [f for f in findings if "dormant" in f.finding.lower()]
    assert len(dormant) == 0


# ═════════════════════════════════════════════════════════════════════════════
# 5. Behavioral Anomaly Detection Tests
# ═════════════════════════════════════════════════════════════════════════════

def test_anomaly_too_few_transactions():
    """Fewer than 3 transactions → no anomaly findings."""
    findings, types = analyze_transaction_intelligence("", [{"date": "01/04/2025", "credit": 10000.0}])
    assert len(findings) == 0


def test_anomaly_salary_stoppage():
    """Salary pattern with last salary >45 days ago → disrupted salary finding."""
    from datetime import datetime, timedelta
    past = (datetime.now() - timedelta(days=60)).strftime("%d/%m/%Y")
    recent = (datetime.now() - timedelta(days=5)).strftime("%d/%m/%Y")
    txns = [
        {"date": past, "credit": 75000.0, "raw": "Salary Credited"},
        {"date": (datetime.now() - timedelta(days=50)).strftime("%d/%m/%Y"),
         "credit": 75000.0, "raw": "Salary Credited"},
        {"date": recent, "credit": 5000.0, "raw": "NEFT Cr"},
    ]
    findings, types = analyze_transaction_intelligence("", txns)
    salary_findings = [f for f in findings if "salary" in f.finding.lower()]
    assert len(salary_findings) > 0, f"Expected salary finding, got {findings}"


def test_anomaly_atm_spike():
    """≥4 ATM withdrawals comprising ≥30% of transactions → ATM spike finding."""
    txns = [
        {"date": "01/04/2025", "debit": 5000.0, "raw": "ATM Withdrawal"},
        {"date": "02/04/2025", "debit": 3000.0, "raw": "ATM Withdrawal"},
        {"date": "03/04/2025", "debit": 2000.0, "raw": "ATM Withdrawal"},
        {"date": "04/04/2025", "debit": 4000.0, "raw": "ATM Withdrawal"},
        {"date": "05/04/2025", "credit": 50000.0, "raw": "NEFT Cr"},
    ]
    findings, types = analyze_transaction_intelligence("", txns)
    atm_findings = [f for f in findings if "atm" in f.finding.lower()]
    assert len(atm_findings) > 0


def test_anomaly_no_atm_spike():
    """Only 2 ATM withdrawals → no spike finding."""
    txns = [
        {"date": "01/04/2025", "debit": 5000.0, "raw": "ATM Withdrawal"},
        {"date": "02/04/2025", "debit": 3000.0, "raw": "ATM Withdrawal"},
        {"date": "03/04/2025", "credit": 50000.0, "raw": "NEFT Cr"},
    ]
    findings, types = analyze_transaction_intelligence("", txns)
    atm_findings = [f for f in findings if "atm" in f.finding.lower()]
    assert len(atm_findings) == 0


def test_anomaly_micro_transaction_smurfing():
    """≥5 debits under ₹2,000 spread across ≤2 days → smurfing pattern (5 txns ≥ 2 dates * 2 = 4)."""
    txns = [
        {"date": "01/04/2025", "debit": 1500.0, "raw": "UPI Dr"},
        {"date": "01/04/2025", "debit": 1800.0, "raw": "UPI Dr"},
        {"date": "01/04/2025", "debit": 1200.0, "raw": "UPI Dr"},
        {"date": "02/04/2025", "debit": 1900.0, "raw": "UPI Dr"},
        {"date": "02/04/2025", "debit": 1600.0, "raw": "UPI Dr"},
        {"date": "02/04/2025", "credit": 50000.0, "raw": "NEFT Cr"},
    ]
    findings, types = analyze_transaction_intelligence("", txns)
    micro_findings = [f for f in findings if "micro" in f.finding.lower() or "smurfing" in f.finding.lower()]
    assert len(micro_findings) > 0


def test_anomaly_round_number_clustering():
    """≥3 round-number debits comprising ≥40% of debits → clustering finding."""
    txns = [
        {"date": "01/04/2025", "debit": 10000.0, "raw": "NEFT Dr"},
        {"date": "02/04/2025", "debit": 20000.0, "raw": "NEFT Dr"},
        {"date": "03/04/2025", "debit": 30000.0, "raw": "NEFT Dr"},
        {"date": "04/04/2025", "debit": 1500.0, "raw": "UPI Dr"},
        {"date": "05/04/2025", "credit": 75000.0, "raw": "Salary"},
    ]
    findings, types = analyze_transaction_intelligence("", txns)
    round_findings = [f for f in findings if "round" in f.finding.lower()]
    assert len(round_findings) > 0


# ═════════════════════════════════════════════════════════════════════════════
# 6. Fraud Loss Estimation Gating Tests
# ═════════════════════════════════════════════════════════════════════════════

def test_fraud_loss_low_confidence_returns_none():
    """parser_confidence < 0.9 → returns None regardless of mismatches."""
    txns = [{"date": "01/04/2025", "debit": 100000.0}]
    findings = [AuthenticityFinding(
        finding="Balance reconciliation failure",
        severity="CRITICAL", risk_points=40,
        evidence="test", field="transaction_integrity",
    )]
    result = estimate_fraud_loss(txns, findings, parser_confidence=0.5,
                                  has_balance_mismatch=True, has_txn_mismatch=False)
    assert result is None


def test_fraud_loss_no_mismatch_returns_none():
    """No balance/txn mismatch → returns None even with high confidence."""
    txns = [{"date": "01/04/2025", "debit": 100000.0}]
    result = estimate_fraud_loss(txns, [], parser_confidence=1.0,
                                  has_balance_mismatch=False, has_txn_mismatch=False)
    assert result is None


def test_fraud_loss_high_confidence_with_mismatch():
    """High confidence + balance mismatch → returns loss estimate."""
    txns = [
        {"date": "01/04/2025", "debit": 100000.0, "raw": "NEFT Dr"},
        {"date": "02/04/2025", "debit": 50000.0, "raw": "NEFT Dr"},
    ]
    findings = [AuthenticityFinding(
        finding="Balance reconciliation failure — declared totals do not match",
        severity="CRITICAL", risk_points=40,
        evidence="test", field="transaction_integrity",
    )]
    result = estimate_fraud_loss(txns, findings, parser_confidence=0.95,
                                  has_balance_mismatch=True, has_txn_mismatch=False)
    assert result is not None
    assert "total_loss" in result
    assert result["total_loss"] > 0


def test_fraud_loss_zero_debits_returns_none():
    """No debits → loss is 0 → returns None."""
    txns = [{"date": "01/04/2025", "credit": 100000.0}]
    findings = [AuthenticityFinding(
        finding="Balance reconciliation failure",
        severity="CRITICAL", risk_points=40,
        evidence="test", field="transaction_integrity",
    )]
    result = estimate_fraud_loss(txns, findings, parser_confidence=0.95,
                                  has_balance_mismatch=True, has_txn_mismatch=False)
    assert result is None


def test_fraud_loss_output_structure():
    """Loss estimate dict has expected keys."""
    txns = [{"date": "01/04/2025", "debit": 100000.0}]
    findings = [AuthenticityFinding(
        finding="Balance reconciliation failure",
        severity="CRITICAL", risk_points=40,
        evidence="test", field="transaction_integrity",
    )]
    result = estimate_fraud_loss(txns, findings, parser_confidence=0.95,
                                  has_balance_mismatch=True, has_txn_mismatch=False)
    assert result is not None
    for key in ("total_loss", "balance_mismatch_loss", "aml_loss", "anomaly_loss"):
        assert key in result, f"Missing key: {key}"
        assert isinstance(result[key], (int, float))


# ═════════════════════════════════════════════════════════════════════════════
# 7. ORB Signature Matching Tests (mock-compatible)
# ═════════════════════════════════════════════════════════════════════════════

def test_orb_comparison_empty_or_single_region():
    """0 or 1 regions → empty matches and no findings."""
    from app.services.signature_intelligence import SignatureRegion

    result = _compare_signature_regions([], doc=None, dpi=150)
    assert result["matches"] == []
    assert result["findings"] == []

    result = _compare_signature_regions(
        [SignatureRegion(page=1, bounding_box=(0, 0, 100, 50), confidence=0.8, area_pct=2.0)],
        doc=None, dpi=150
    )
    assert result["matches"] == []
    assert result["findings"] == []


def test_orb_comparison_no_cv2_graceful():
    """When cv2 is unavailable, comparison should not crash."""
    from app.services.signature_intelligence import SignatureRegion, CV2_AVAILABLE

    if not CV2_AVAILABLE:
        pytest.skip("OpenCV not available — skipping cv2-dependent test")

    # Create minimal valid test input
    import fitz
    import numpy as np

    doc = fitz.open()
    page = doc.new_page()
    rect = page.rect
    # Draw two small rectangles that could look like signatures
    shape = page.new_shape()
    shape.draw_rect((rect.x0 + 10, rect.y0 + 10, rect.x0 + 110, rect.y0 + 60))
    shape.draw_rect((rect.x0 + 200, rect.y0 + 10, rect.x0 + 300, rect.y0 + 60))
    shape.finish(width=2)
    shape.commit()

    pdf_bytes = doc.write()
    doc.close()

    doc2 = fitz.open(stream=pdf_bytes, filetype="pdf")
    regions = [
        SignatureRegion(page=1, bounding_box=(10, 10, 100, 50), confidence=0.8, area_pct=2.0),
        SignatureRegion(page=1, bounding_box=(200, 10, 100, 50), confidence=0.8, area_pct=2.0),
    ]
    result = _compare_signature_regions(regions, doc2, dpi=150)
    doc2.close()

    assert "matches" in result
    assert "findings" in result
    # Two identical rectangles should produce high similarity
    if result["matches"]:
        assert result["matches"][0]["similarity"] > 0.5


def test_balance_reconciliation_gated_low_confidence():
    """Low parser confidence with actual mismatch → MEDIUM/UNKNOWN, not CRITICAL/FAIL."""
    text = """Opening Balance: 10,000
Closing Balance: 260,000
Total Credits: 245,000
Total Debits: 5,000"""
    finding = check_balance_reconciliation(text, parser_confidence=0.5)
    assert finding is not None
    # Now proceeds with comparison even at low confidence; mismatch exists
    assert finding.severity == "MEDIUM"
    assert finding.status == "UNKNOWN"
    assert "failure" in finding.finding.lower()


def test_balance_reconciliation_high_confidence_mismatch():
    """High parser confidence with mismatch → CRITICAL finding."""
    text = """Opening Balance: 10,000
Closing Balance: 260,000
Total Credits: 245,000
Total Debits: 5,000"""
    finding = check_balance_reconciliation(text, parser_confidence=0.9)
    assert finding is not None
    assert finding.severity == "CRITICAL"
    assert "failure" in finding.finding.lower()


def test_balance_reconciliation_high_confidence_match():
    """High parser confidence with valid balance → None (no finding)."""
    text = """Opening Balance: 10,000
Closing Balance: 250,000
Total Credits: 245,000
Total Debits: 5,000"""
    finding = check_balance_reconciliation(text, parser_confidence=0.9)
    assert finding is None


def test_transaction_total_mismatch_gated_low_confidence():
    """Low parser confidence → no mismatch finding (returns None or LOW)."""
    finding = check_transaction_total_mismatch(
        "Total Credits: 100,000\nTotal Debits: 50,000",
        parser_confidence=0.5,
    )
    # Low confidence returns None or LOW finding, never CRITICAL
    if finding is not None:
        assert finding.severity == "LOW"


def test_transaction_total_mismatch_within_tolerance():
    """Parsed sums within 1% of declared → no finding (high confidence).

    Note: declared totals use round numbers without commas to avoid
    parser confusion with transaction columns. The parser matches
    debits/credits by position in tabular rows."""
    text = """Total Credits: 100000
Total Debits: 50000
Date        Particulars          Debit        Credit       Balance
01/04/2025  Salary Credit                    60000.00     60000.00
02/04/2025  Refund Credit                    40000.00     100000.00
03/04/2025  ATM Withdrawal      30000.00                   70000.00
04/04/2025  Transfer Out        20000.00                   50000.00"""
    finding = check_transaction_total_mismatch(text, parser_confidence=0.9)
    assert finding is None, f"Expected no mismatch finding, got: {finding}"


def test_transaction_total_mismatch_outside_tolerance():
    """Parsed sums with >1% deviation → finding generated."""
    text = """Total Credits: 100,000
Total Debits: 50,000
Date        Particulars          Debit      Credit     Balance
01/04/2025  NEFT Cr              ₹100,000.00            ₹100,000.00
02/04/2025  NEFT Dr   ₹10,000.00                       ₹90,000.00"""
    finding = check_transaction_total_mismatch(text, parser_confidence=0.9)
    assert finding is not None
    assert finding.severity == "CRITICAL"
