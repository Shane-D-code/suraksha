"""
Synthetic Fraud Lab — Generate realistic bank statements for testing.

Generates both genuine and fraudulent bank statement text with controlled
mutations to validate detection accuracy.

Usage:
    python tests/synthetic_fraud_lab.py              # quick smoke test
    python tests/synthetic_fraud_lab.py --count 100  # generate 100 docs
"""
import argparse
import random
import sys
from datetime import datetime, timedelta

BANKS = {
    "hdfc": {"ifsc_prefix": "HDFC", "name": "HDFC BANK"},
    "icici": {"ifsc_prefix": "ICIC", "name": "ICICI BANK"},
    "sbi": {"ifsc_prefix": "SBIN", "name": "STATE BANK OF INDIA"},
    "axis": {"ifsc_prefix": "UTIB", "name": "AXIS BANK"},
}

BRANCHES = [
    "M G Road, Bangalore", "Connaught Place, New Delhi",
    "Andheri East, Mumbai", "Koramangala, Bangalore",
    "Salt Lake, Kolkata", "Jubilee Hills, Hyderabad",
    "Civil Lines, Pune", "Banjara Hills, Hyderabad",
]

TRANSACTION_TYPES = [
    ("Salary", 25000, 80000, 0.9),
    ("NEFT Transfer", 5000, 50000, 0.7),
    ("UPI Payment", 500, 5000, 0.6),
    ("ATM Withdrawal", 2000, 15000, 0.5),
    ("POS Purchase", 200, 3000, 0.4),
    ("Interest Credited", 500, 5000, 0.1),
    ("Cheque Deposit", 10000, 100000, 0.3),
    ("Bill Payment", 1000, 10000, 0.3),
]

FRAUD_MUTATIONS = [
    "missing_ifsc",
    "missing_account",
    "missing_branch",
    "balance_mismatch",
    "transaction_mismatch",
    "template_watermark",
    "currency_mismatch",
    "future_dates",
    "duplicate_transactions",
    "bank_identity_conflict",
]


def random_date(start_year=2024, end_year=2025):
    start = datetime(start_year, 1, 1)
    end = datetime(end_year, 12, 31)
    delta = end - start
    return start + timedelta(days=random.randint(0, delta.days))


def generate_statement(bank_key: str, num_txns: int = 8, fraud_type: str = None) -> str:
    """Generate a synthetic bank statement text, optionally with fraud mutations."""
    bank = BANKS[bank_key]
    ifsc = f"{bank['ifsc_prefix']}0{random.randint(100000, 999999)}"
    account = str(random.randint(10000000000, 99999999999))
    branch = random.choice(BRANCHES)
    opening_bal = random.randint(50000, 500000)
    lines = []

    # Header
    lines.append(f"{bank['name']}")
    lines.append(f"Branch: {branch}")
    lines.append(f"IFSC: {ifsc}")
    lines.append(f"Account No: {account}")
    if random.random() > 0.5:
        cust_id = f"CIF{random.randint(100000, 999999)}"
        lines.append(f"Customer ID: {cust_id}")
    lines.append("")
    lines.append(f"{'Date':<14} {'Particulars':<25} {'Debit':<14} {'Credit':<14} {'Balance':<14}")
    lines.append("-" * 80)

    # Transactions
    running_bal = opening_bal
    total_credits = 0.0
    total_debits = 0.0

    for i in range(num_txns):
        txn_date = random_date()
        date_str = txn_date.strftime("%d/%m/%Y")
        txn_type, min_amt, max_amt, _ = random.choice(TRANSACTION_TYPES)

        if fraud_type == "future_dates":
            date_str = (datetime.now() + timedelta(days=random.randint(1, 60))).strftime("%d/%m/%Y")

        is_credit = txn_type in ("Salary", "Interest Credited", "Cheque Deposit", "NEFT Transfer")
        amount = round(random.uniform(min_amt, max_amt), 2)

        if fraud_type == "duplicate_transactions" and i > 3 and random.random() > 0.5:
            prev_amt = amount
            amount = prev_amt

        if is_credit:
            running_bal += amount
            total_credits += amount
            lines.append(f"{date_str:<14} {txn_type:<25} {'':<14} ₹{amount:<10,.2f} ₹{running_bal:<,.2f}")
        else:
            if amount > running_bal:
                amount = running_bal * 0.5
            running_bal -= amount
            total_debits += amount
            lines.append(f"{date_str:<14} {txn_type:<25} ₹{amount:<10,.2f} {'':<14} ₹{running_bal:<,.2f}")

    # Summary
    lines.append("-" * 80)
    lines.append(f"{'Opening Balance':<40} ₹{opening_bal:>10,.2f}")
    lines.append(f"{'Total Credits':<40} ₹{total_credits:>10,.2f}")
    lines.append(f"{'Total Debits':<40} ₹{total_debits:>10,.2f}")
    closing_bal = opening_bal + total_credits - total_debits

    if fraud_type == "balance_mismatch":
        closing_bal += random.randint(10000, 100000) * random.choice([-1, 1])

    lines.append(f"{'Closing Balance':<40} ₹{closing_bal:>10,.2f}")

    text = "\n".join(lines)

    # Fraud mutations on the full text
    if fraud_type == "missing_ifsc":
        text = text.replace(f"IFSC: {ifsc}", "")
    elif fraud_type == "missing_account":
        text = text.replace(f"Account No: {account}", "")
    elif fraud_type == "missing_branch":
        text = text.replace(f"Branch: {branch}", "")
    elif fraud_type == "template_watermark":
        text += "\n\nGenerated from www.template.net — sample statement"
    elif fraud_type == "currency_mismatch":
        text = text.replace("INR", "USD")
        text += "\nCurrency: USD"
    elif fraud_type == "bank_identity_conflict":
        other_bank = random.choice([b for b in BANKS if b != bank_key])
        text += f"\n{random.choice(BANKS[other_bank]['name'])}"
    elif fraud_type == "transaction_mismatch":
        text = text.replace(f"Total Credits", f"Total Credits (adjusted)")
        text += f"\nTotal Credits: ₹{total_credits * random.uniform(0.5, 1.5):,.2f}"

    return text


def generate_genuine(bank_key: str = None) -> str:
    bank = bank_key or random.choice(list(BANKS.keys()))
    return generate_statement(bank, num_txns=random.randint(5, 12))


def generate_fraud(fraud_type: str = None) -> tuple:
    bank = random.choice(list(BANKS.keys()))
    ft = fraud_type or random.choice(FRAUD_MUTATIONS)
    text = generate_statement(bank, num_txns=random.randint(5, 12), fraud_type=ft)
    return text, ft


def run_smoke_test():
    """Quick test: generate both genuine and fraud docs, check detection."""
    from app.services.banking_authenticity import analyze_bank_statement

    print("=" * 60)
    print("SYNTHETIC FRAUD LAB — SMOKE TEST")
    print("=" * 60)

    # Test genuine statements
    print("\n--- GENUINE STATEMENTS ---")
    for bank in BANKS:
        text = generate_genuine(bank)
        result = analyze_bank_statement(text)
        status = "OK" if result.authenticity_score >= 70 else "LOW"
        print(f"  {bank.upper():6s} score={result.authenticity_score:3.0f} txn={result.transaction_count} [{status}]")

    # Test fraud statements
    print("\n--- FRAUD STATEMENTS ---")
    results = {}
    for ft in FRAUD_MUTATIONS:
        text, ftype = generate_fraud(ft)
        result = analyze_bank_statement(text)
        score = result.authenticity_score
        results[ft] = score
        # Score < 85 is anomalous (genuine statements score 95-100)
        status = "DETECTED" if score <= 80 else "MISSED"
        print(f"  {ft:30s} score={score:3.0f} [{status}]")

    # Summary
    print(f"\nSummary:")
    detected = sum(1 for s in results.values() if s <= 80)
    print(f"  Detected: {detected}/{len(FRAUD_MUTATIONS)}")
    print(f"  Detection rate: {detected/len(FRAUD_MUTATIONS)*100:.0f}%")
    print("=" * 60)


def run_batch(count: int = 100):
    """Generate batch of statements and run them through the engine."""
    from app.services.banking_authenticity import analyze_bank_statement

    genuine_scores = []
    fraud_results = {}

    for _ in range(count // 2):
        text = generate_genuine()
        result = analyze_bank_statement(text)
        genuine_scores.append(result.authenticity_score)

    for ft in FRAUD_MUTATIONS:
        fraud_results[ft] = []
        for _ in range(count // (2 * len(FRAUD_MUTATIONS))):
            text, _ = generate_fraud(ft)
            result = analyze_bank_statement(text)
            fraud_results[ft].append(result.authenticity_score)

    print(f"Genuine: avg_score={sum(genuine_scores)/len(genuine_scores):.0f} min={min(genuine_scores)} max={max(genuine_scores)}")
    for ft, scores in fraud_results.items():
        if scores:
            avg = sum(scores) / len(scores)
            print(f"Fraud [{ft:30s}]: avg_score={avg:.0f} min={min(scores)} max={max(scores)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Synthetic Fraud Lab")
    parser.add_argument("--count", type=int, default=0, help="Batch size (0 = smoke test)")
    args = parser.parse_args()

    if args.count > 0:
        run_batch(args.count)
    else:
        run_smoke_test()
