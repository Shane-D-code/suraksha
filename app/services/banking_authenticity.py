"""
Banking Document Authenticity & Transaction Intelligence Engine.

Validates bank statements against banking-specific rules:
- Template/sample detection
- Bank identity extraction (IFSC, account number, branch)
- Currency consistency (INR vs foreign currency)
- Running balance validation
- Transaction pattern analysis
- Per-bank rule enforcement

Returns structured findings with concrete evidence snippets.
"""
import re
import structlog
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Tuple

from app.services.bank_rules import run_bank_rules, reconstruct_transaction_flow

logger = structlog.get_logger(__name__)


class ValidationStatus(Enum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"


# ── Bank Definitions ─────────────────────────────────────────────────

BANK_IDENTIFIERS = {
    "canara": {
        "aliases": ["canara bank", "canara"],
        "ifsc_prefix": "CNRB",
        "required_fields": ["ifsc", "account number", "branch", "customer id"],
    },
    "sbi": {
        "aliases": ["state bank of india", "sbi", "state bank"],
        "ifsc_prefix": "SBIN",
        "required_fields": ["ifsc", "account number", "branch", "customer id"],
    },
    "hdfc": {
        "aliases": ["hdfc bank", "hdfc"],
        "ifsc_prefix": "HDFC",
        "required_fields": ["ifsc", "account number", "branch"],
    },
    "icici": {
        "aliases": ["icici bank", "icici"],
        "ifsc_prefix": "ICIC",
        "required_fields": ["ifsc", "account number", "branch"],
    },
    "indian": {
        "aliases": ["indian bank", "indian"],
        "ifsc_prefix": "IDIB",
        "required_fields": ["ifsc", "account number", "branch"],
    },
    "baroda": {
        "aliases": ["bank of baroda", "baroda"],
        "ifsc_prefix": "BARB",
        "required_fields": ["ifsc", "account number", "branch"],
    },
    "pnb": {
        "aliases": ["punjab national bank", "pnb"],
        "ifsc_prefix": "PUNB",
        "required_fields": ["ifsc", "account number", "branch"],
    },
    "union": {
        "aliases": ["union bank of india", "union bank"],
        "ifsc_prefix": "UBIN",
        "required_fields": ["ifsc", "account number", "branch"],
    },
    "boi": {
        "aliases": ["bank of india", "boi"],
        "ifsc_prefix": "BKID",
        "required_fields": ["ifsc", "account number", "branch"],
    },
}

TEMPLATE_KEYWORDS = [
    "template.net", "www.template.net", "sample", "specimen", "demo", "example",
    "templatenet", "template", "mock statement", "for illustration",
    "sample only", "demo only", "not a real statement",
    "canva", "freepik", "adobe stock", "powered by canva",
    "sample statement", "demo statement",
    "templatelab", "adobe express", "wix", "squarespace",
    "wordpress", "strikingly", "weebly", "godaddy", "shopify",
]

INVOICE_KEYWORDS = [
    "subtotal", "sub-total", "discount", "tax", "qty", "quantity",
    "pricing summary", "invoice", "unit price", "total amount due",
    "payment terms", "due date",
]

PUBLIC_TEMPLATE_INDICATORS = [
    "template.net", "canva", "freepik", "adobe stock",
    "templatelab", "adobe express", "wix", "shopify",
]

FOREIGN_CURRENCY_SYMBOLS = ["$", "€", "£", "¥"]
FOREIGN_CURRENCY_CODES = ["usd", "eur", "gbp", "jpy", "cny", "aud", "cad"]
INR_SYMBOLS = ["₹", "inr", "rs.", "rs "]

MONTH_NAMES = [
    "january", "february", "march", "april", "may", "june",
    "july", "august", "september", "october", "november", "december",
    "jan", "feb", "mar", "apr", "may", "jun",
    "jul", "aug", "sep", "oct", "nov", "dec",
]


# ── Document Type Constants ──────────────────────────────────────────

DOCUMENT_BANK_STATEMENT = "bank_statement"
DOCUMENT_INVOICE = "invoice"
DOCUMENT_SALARY = "salary_slip"
DOCUMENT_UNKNOWN = "unknown"


@dataclass
class AuthenticityFinding:
    finding: str
    severity: str  # LOW / MEDIUM / HIGH / CRITICAL
    risk_points: int  # raw risk contribution (0-100)
    evidence: str
    field: str = ""
    confidence: float = 1.0
    status: str = "FAIL"  # PASS / FAIL / UNKNOWN
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat()


@dataclass
class BankingAuthenticityResult:
    bank_name: Optional[str] = None
    authenticity_score: float = 0.0
    confidence: float = 1.0
    findings: List[AuthenticityFinding] = field(default_factory=list)
    transaction_count: int = 0
    balance_valid: Optional[bool] = None
    has_template_indicators: bool = False
    has_currency_mismatch: bool = False
    has_running_balance_issue: bool = False
    has_balance_reconciliation_issue: bool = False
    has_transaction_total_mismatch: bool = False
    has_invoice_layout: bool = False
    has_public_template_indicator: bool = False
    has_metadata_missing: bool = False
    has_aml_structuring: bool = False
    has_fraud_loss_estimate: bool = False
    estimated_fraud_loss: float = 0.0
    transaction_types: dict = field(default_factory=dict)
    timeline_events: List[dict] = field(default_factory=list)
    whitelist_signals: List[dict] = field(default_factory=list)
    document_type: str = DOCUMENT_UNKNOWN
    bank_confidence: float = 0.0
    extraction_quality: float = 1.0  # 0-1: how complete the financial extraction was
    transaction_reconstruction: Optional[dict] = None  # display-ready flow reconstruction


# ── Helper Functions ─────────────────────────────────────────────────

def _normalise(text: str) -> str:
    return re.sub(r'\s+', ' ', text.strip().lower())


def _extract_ifsc(text: str) -> Optional[str]:
    """Extract IFSC code: 4 letters + 0 + 6 alphanumeric."""
    m = re.search(r'\b[A-Z]{4}0[A-Z0-9]{6}\b', text)
    return m.group(0) if m else None


def _extract_account_numbers(text: str) -> List[str]:
    """Extract bank account numbers — full or masked (e.g. XXXX XXXX 4821)."""
    nums = re.findall(r'\b\d{9,18}\b', text)
    masks = re.findall(r'(?:[Xx*]{4}\s?){2}\d{4}', text)
    joined = [m.replace(' ', '') for m in masks]
    return nums + joined


WEIGHTS = {
    "template_watermark": 80,
    "public_template_source": 30,
    "currency_mismatch": 60,
    "bank_identity_mismatch": 25,
    "missing_account_number": 50,
    "missing_ifsc": 25,
    "missing_branch": 5,
    "missing_customer_id": 5,
    "metadata_missing": 20,
    "metadata_author_missing": 1,
}

FIELD_PATTERNS = {
    "ifsc": [r'\b[A-Z]{4}0[A-Z0-9]{6}\b',
             r'ifsc\s*(?:code|no|number)?\s*[:\-]?\s*[A-Z0-9]+'],
    "account number": [r'account\s*(?:no|number|#|\.?)\s*[:\-]?\s*(?:\d{6,18}|[Xx*]{4}\s*[Xx*\d]{4,})',
                       r'a[/\\]?c\s*(?:no|number|#)?\s*[:\-]?\s*(?:\d{6,18}|[Xx*]{4}\s*[Xx*\d]{4,})',
                       r'(?:[Xx*]{4}\s?){2}\d{4}',
                       r'\b\d{9,18}\b',
                       r'masked\s*account'],
    "branch": [r'branch\s*(?:address|name|code|no|number)?\s*[:\-]\s*\w+',
               r'branch\s*:\s*\w+',
               r'\b(?:koramangala|indiranagar|whitefield|mg\s*road|bannerghatta'
               r'|jayanagar|rajajinagar|malleshwaram|basavanagudi|sadashivanagar'
               r'|jayanagar|btm\s*layout|hsr\s*layout|electronic\s*city'
               r'|marathahalli|bellandur|sarjapur|hebbal|yelahanka)',
               r'\b(?:bengaluru|bangalore|mumbai|delhi|pune|kolkata|chennai'
               r'|hyderabad|ahmedabad|jaipur|kochi|surat|lucknow|noida|gurgaon'
               r'|ghaziabad|faridabad|chandigarh|indore|bhopal|nagpur'
               r'|thane|navi\s*mumbai|goa|panaji|siliguri|guwahati|patna'
               r'|ranchi|raipur|bhubaneswar|vijayawada|visakhapatnam'
               r'|coimbatore|madurai|trivandrum|kozhikode|mangalore'
               r'|mysore|hubli|belgaum|davangere|shimoga|udupi)'],
    "customer id": [r'customer\s*(?:id|no|number|#)?\s*[:\-]\s*\w+',
                    r'cust\s*(?:id|no|number|#)?\s*[:\-]\s*\w+',
                    r'c/id\s*[:\-]\s*\w+',
                    r'cif\s*(?:number|no|#)?\s*[:\-]\s*\w+',
                    r'customer\s*(?:number|relationship\s*number)\s*[:\-]\s*\w+',
                    r'user\s*id\s*[:\-]\s*\w+'],
}


def _field_present(field_name: str, text: str) -> bool:
    """Check whether a required field appears in text.

    Uses dedicated extractors for IFSC and account numbers (content-validated).
    For branch/customer-id, uses per-line regex matching with mandatory
    separator to prevent matching empty labels like 'Customer ID:' alone.
    """
    if field_name == "ifsc":
        return _extract_ifsc(text) is not None
    if field_name == "account number":
        return len(_extract_account_numbers(text)) > 0
    patterns = FIELD_PATTERNS.get(field_name, [re.escape(field_name)])
    return any(re.search(p, line, re.I) for line in text.split('\n') for p in patterns)


def _extract_amounts(text: str) -> List[float]:
    """Extract monetary amounts from a line of text.
    Uses word boundary to avoid matching digits embedded in alphanumeric ref codes.
    Only numbers with exactly 2 decimal places (or preceded by ₹) are accepted as
    transaction amounts — reference/UTR numbers are never extracted.
    """
    date_spans = set()
    for dm in re.finditer(r'\b\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b', text):
        for pos in range(dm.start(), dm.end()):
            date_spans.add(pos)

    amounts = []
    NON_FINANCIAL_KEYWORDS = ['care', 'phone', 'tel:', 'fax', 'contact',
                              'toll-free', 'toll free', 'helpline',
                              'customer care', 'customer.support',
                              'email', 'website', 'www', 'http',
                              'pincode', 'pin code', 'pin:', 'zip',
                              'page', 'date', 'print', 'digitally']

    for m in re.finditer(r'(?:[₹$€£]\s*)?\b([\d,]+(?:\.\d{1,2})?)\b', text):
        raw = m.group(1).replace(',', '')
        if not raw.replace('.', '').isdigit():
            continue
        val = float(raw)

        # Skip amounts that are part of a date string
        if any(pos in date_spans for pos in range(m.start(1), m.end(1))):
            continue

        has_currency_prefix = m.group(0).startswith(('₹', '$', '€', '£'))
        has_exactly_two_decimals = '.' in raw and len(raw.split('.')[1]) == 2

        # Numbers with currency prefix always pass
        if has_currency_prefix:
            amounts.append(val)
            continue

        ctx_start = max(0, m.start() - 30)
        ctx_end = min(len(text), m.end() + 30)
        context = text[ctx_start:ctx_end].lower()

        if any(kw in context for kw in NON_FINANCIAL_KEYWORDS):
            continue

        # Indian pincode filter
        if 100000 <= val <= 999999 and re.search(r'\b[1-9]\d{5}\b', raw):
            addr_kw = ['pin', 'zip', 'code', 'ka ', 'karnataka', 'bengaluru',
                       'bangalore', 'mumbai', 'delhi', 'chennai', 'kolkata',
                       'hyderabad', 'pune', 'ahmedabad', 'jaipur']
            txn_kw = ['deposited', 'credited', 'debited', 'withdrawal',
                      'withdrawn', 'paid', 'received', 'transfer', 'amount',
                      'rs', 'inr', 'balance', 'total', 'charge', 'fee',
                      'refund', 'payment', 'salary', 'interest']
            if any(kw in context for kw in addr_kw) and not any(kw in context for kw in txn_kw):
                continue

        # Only numbers with exactly 2 decimal places are valid transaction amounts
        # (unless they have a currency prefix, handled above)
        if not has_exactly_two_decimals:
            continue

        # Reject unreasonably large amounts (>100 crore) — likely UTR/ref numbers
        if val > 1_000_000_000:
            continue

        amounts.append(val)

    return amounts


@dataclass
class TransactionRow:
    date: Optional[str] = None
    description: str = ""
    debit: Optional[float] = None
    credit: Optional[float] = None
    balance: Optional[float] = None


TRANSACTION_DESCRIPTION_KEYWORDS = [
    'atm', 'withdrawal', 'withdrawl', 'deposit', 'credited', 'debited',
    'transfer', 'neft', 'rtgs', 'imps', 'upi', 'pos', 'purchas',
    'salary', 'interest', 'cheque', 'chq', 'payment', 'received',
    'paid', 'charge', 'fee', 'refund', 'bill', 'by cash', 'loan', 'emi',
    'tax', 'insurance', 'dividend', 'commission', 'brokerage',
    'swipe', 'card', 'online', 'wallet', 'paytm', 'google pay',
    'phonepe', 'bhim', 'imps', 'inward', 'outward', 'fund',
    'mint', 'credit card', 'repayment',
]


_TXN_DATE_PATTERN = re.compile(
    r'\d{2}[/-]\d{2}[/-]\d{2,4}'           # DD/MM/YYYY or DD-MM-YYYY
    r'|\d{2}[/-][A-Za-z]{3}[/-]\d{2,4}'    # DD-Mon-YYYY
    r'|\d{2}\s+[A-Za-z]{3}\s+\d{2,4}'      # DD Mon YYYY
)


def looks_like_transaction(line: str) -> bool:
    """Check if a line looks like a genuine bank transaction entry.
    Must contain a date AND at least one valid monetary amount AND
    descriptive alphabetic text (not just codes/numbers).
    """
    if not _TXN_DATE_PATTERN.search(line):
        return False

    amounts = _extract_amounts(line)
    if not amounts:
        return False

    # Remove date patterns and numeric values to check for descriptive text
    cleaned = _TXN_DATE_PATTERN.sub(' ', line)
    cleaned = re.sub(r'[\d,.\s]+', ' ', cleaned)
    alpha = re.sub(r'[^a-zA-Z]', ' ', cleaned).strip()
    alpha_words = [w for w in alpha.split() if len(w) > 1]

    if len(alpha_words) >= 2:
        return True

    if len(alpha_words) == 1 and len(alpha_words[0]) >= 4:
        return True

    return False


def _extract_structured_transactions(text: str) -> List[dict]:
    """
    Parse transaction rows from bank statement OCR text.
    Only extracts from lines with date patterns, excluding header/totals/footer sections.
    Assigns running balance to 'balance' field so it is never included in credit/debit sums.
    """
    transactions = []
    lines = text.split('\n')
    date_pattern = re.compile(
        r'(\d{2}[/-]\d{2}[/-]\d{2,4})'              # DD/MM/YYYY or DD-MM-YYYY
        r'|(\d{2}[/-][A-Za-z]{3}[/-]\d{2,4})'        # DD-Mon-YYYY
        r'|(\d{2}\s+[A-Za-z]{3}\s+\d{2,4})'          # DD Mon YYYY
    )

    # Keywords that indicate a line is NOT a transaction row
    SKIP_LINE_KEYWORDS = [
        'opening', 'closing', 'open balance', 'close balance',
        'total credit', 'total debit', 'total cr', 'total dr',
        'statement', 'summary', 'account no', 'ifsc', 'branch',
        'customer', 'page', 'print', 'digitally', 'generated',
        'reference', 'narration', 'particulars', 'date',
    ]

    for line in lines:
        line = line.strip()
        if not line:
            continue

        line_lower = line.lower()
        # Skip header/summary lines even if they contain dates
        if any(kw in line_lower for kw in SKIP_LINE_KEYWORDS):
            continue

        # Skip lines that are purely header/footer (short, no transaction amounts)
        if len(line) < 20:
            continue

        date_match = date_pattern.search(line)
        if not date_match:
            continue

        # Transaction validation gate: skip lines that don't look like transactions
        if not looks_like_transaction(line):
            logger.info("TRANSACTION_SKIP_NON_TXN", line=line[:120])
            continue

        amounts = _extract_amounts(line)
        date_str = next(g for g in date_match.groups() if g is not None)

        if len(amounts) == 0:
            continue

        if len(amounts) == 1:
            line_lower = line.lower()
            is_debit = any(kw in line_lower for kw in
                           ['withdrawal', 'withdrawl', 'debit', 'debited',
                            'paid', 'payment', 'charge', 'fee', 'deducted',
                            'transfer-out', 'transfer out', 'outward',
                            'atm', 'pos ', 'purchas', 'ref no'])
            entry = {
                "date": date_str,
                "debit": amounts[0] if is_debit else None,
                "credit": amounts[0] if not is_debit else None,
                "balance": None,
                "raw": line[:120],
            }
            logger.info("TRANSACTION_ROW",
                        date=date_str, debit=entry["debit"], credit=entry["credit"],
                        balance=None, description=line[:60])
            transactions.append(entry)
            continue

        # Last amount is always the running balance
        balance = amounts[-1]
        debit_credit = amounts[:-1]

        line_lower = line.lower()
        is_debit_line = any(kw in line_lower for kw in
                            ['withdrawal', 'withdrawl', 'debit', 'debited',
                             'paid', 'payment', 'charge', 'fee', 'deducted',
                             'transfer-out', 'transfer out', 'outward',
                             'atm', 'pos ', 'purchas', 'ref no'])
        debit = None
        credit = None

        if len(debit_credit) == 1:
            credit = None if is_debit_line else debit_credit[0]
            debit = debit_credit[0] if is_debit_line else None
        elif len(debit_credit) >= 2:
            credit = debit_credit[0]
            debit = debit_credit[1]

        entry = {
            "date": date_str,
            "debit": debit,
            "credit": credit,
            "balance": balance,
            "raw": line[:120],
        }
        logger.info("TRANSACTION_ROW",
                    date=date_str, debit=debit, credit=credit,
                    balance=balance, description=line[:60])
        transactions.append(entry)

    # Fallback: if date-based parsing found nothing and we have declared totals
    if not transactions:
        declared = _extract_declared_balances(text)
        logger.info("FALLBACK_NO_TRANSACTIONS", declared_keys=list(declared.keys()))

    logger.info("TRANSACTION_PARSE_RESULT",
                rows_found=len(transactions),
                credit_sum=sum(t.get("credit", 0) or 0 for t in transactions),
                debit_sum=sum(t.get("debit", 0) or 0 for t in transactions))
    return transactions


TRANSACTION_TYPE_PATTERNS = {
    "salary": [r'salary', r'salary\s*credited', r'payroll', r'wages', r'salary\s*transfer'],
    "neft": [r'neft', r'neft\s*cr', r'neft\s*dr', r'neft\s*credit', r'neft\s*debit'],
    "rtgs": [r'rtgs', r'rtgs\s*cr', r'rtgs\s*dr'],
    "imps": [r'imps', r'imps\s*cr', r'imps\s*dr', r'instant\s*payment'],
    "upi": [r'upi', r'upi\s*cr', r'upi\s*dr', r'upi\s*transfer', r'google\s*pay', r'phonepe', r'paytm', r'bhim'],
    "atm_withdrawal": [r'atm\s*withdrawal', r'atm\s*wdl', r'cash\s*withdrawal', r'withdrawal\s*atm', r'wdl\s*atm'],
    "cash_deposit": [r'cash\s*deposit', r'cash\s*dep', r'cash\s*credited', r'by\s*cash'],
    "pos": [r'pos\s*dr', r'pos\s*purchas', r'point\s*of\s*sale', r'card\s*purchas', r'swipe', r'card\s*used'],
    "transfer_out": [r'transfer\s*out', r'outward', r'funds\s*transfer', r'money\s*sent', r'electronic\s*transfer'],
    "interest": [r'interest\s*credited', r'int\s*cr', r'interest\s*paid', r'int\.?\s*paid'],
    "cheque": [r'cheque', r'chq', r'ch\.?\s*no', r'check'],
    "loan": [r'loan', r'emi', r'loan\s*repayment', r'loan\s*disburs'],
}


def classify_transaction_type(raw_text: str) -> str:
    """Classify a transaction by its description text into a category."""
    lower = raw_text.lower()
    for txn_type, patterns in TRANSACTION_TYPE_PATTERNS.items():
        for p in patterns:
            if re.search(p, lower):
                return txn_type
    # Fallback: check if it looks like a debit or credit
    is_debit = any(kw in lower for kw in ['debit', 'debited', 'withdrawal', 'withdrawl', 'paid', 'payment', 'charge', 'fee', 'deducted'])
    return "debit" if is_debit else "credit"


def analyze_transaction_intelligence(text: str, transactions: List[dict]) -> Tuple[List[AuthenticityFinding], dict]:
    """Analyze transaction patterns for behavioral anomalies and type-based intelligence.
    
    Returns (findings, transaction_type_counts) tuple.
    Findings include:
    - Salary pattern disruption (sudden stop)
    - ATM/cash withdrawal spikes
    - Unusual transaction types
    - Repeated micro-transactions
    """
    findings = []
    type_counts_result: dict = {}
    if len(transactions) < 3:
        return findings, type_counts_result

    # Classify each transaction
    classified = []
    for i, txn in enumerate(transactions):
        tx_type = classify_transaction_type(txn.get("raw", ""))
        classified.append({**txn, "tx_type": tx_type, "index": i})

    # Count by type
    type_counts: dict = {}
    type_amounts: dict = {}
    for t in classified:
        tp = t["tx_type"]
        type_counts[tp] = type_counts.get(tp, 0) + 1
        amt = t.get("debit") or t.get("credit") or 0
        type_amounts.setdefault(tp, []).append(amt)

    type_counts_result = {k: {"count": v, "total_amount": sum(type_amounts.get(k, []))} for k, v in type_counts.items()}

    # 1. Salary pattern check
    salary_txns = [t for t in classified if t["tx_type"] == "salary"]
    if len(salary_txns) >= 2:
        # Check if salary appears in last 2 months — if not, it may have stopped
        from datetime import datetime, timedelta
        now = datetime.now()
        salary_dates = []
        for s in salary_txns:
            date_str = s.get("date")
            if not date_str:
                continue
            parsed = _parse_date(date_str)
            if parsed:
                y, m, d = parsed
                try:
                    salary_dates.append(datetime(y, m, d))
                except ValueError:
                    pass
        if salary_dates:
            latest = max(salary_dates)
            if (now - latest) > timedelta(days=45):
                findings.append(AuthenticityFinding(
                    finding="Salary credit pattern disrupted — no salary deposited in 45+ days",
                    severity="MEDIUM",
                    risk_points=20,
                    evidence=f"Last salary credit: {latest.date().isoformat()}, analysis date: {now.date().isoformat()}",
                    field="transaction_integrity",
                ))

    # 2. ATM withdrawal spike
    atm_txns = [t for t in classified if t["tx_type"] == "atm_withdrawal"]
    if len(atm_txns) >= 4:
        atm_amounts = [(t.get("debit") or 0) for t in atm_txns]
        avg_atm = sum(atm_amounts) / len(atm_amounts) if atm_amounts else 0
        # Check for high-frequency ATM usage
        if len(atm_txns) >= len(classified) * 0.3:
            findings.append(AuthenticityFinding(
                finding="ATM withdrawal frequency anomaly — disproportionate ATM usage",
                severity="MEDIUM",
                risk_points=15,
                evidence=f"{len(atm_txns)} of {len(classified)} transactions are ATM withdrawals (avg ₹{avg_atm:,.2f})",
                field="transaction_integrity",
            ))

    # 3. Repeated micro-transactions (potential smurfing)
    micro_txns = [t for t in classified if (t.get("debit") or 0) < 2000 and t.get("debit") is not None]
    if len(micro_txns) >= 5:
        unique_dates = set(t.get("date", "") for t in micro_txns if t.get("date"))
        if len(micro_txns) >= len(unique_dates) * 2:
            findings.append(AuthenticityFinding(
                finding="Repeated micro-transactions detected — possible smurfing pattern",
                severity="MEDIUM",
                risk_points=20,
                evidence=f"{len(micro_txns)} transactions under ₹2,000 across {len(unique_dates)} days",
                field="transaction_integrity",
            ))

    # 4. Round-number transaction clustering
    round_txns = [t for t in classified if t.get("debit") and t["debit"] % 1000 == 0 and t["debit"] > 0]
    if len(round_txns) >= 3 and len(round_txns) >= len([t for t in classified if t.get("debit")]) * 0.4:
        findings.append(AuthenticityFinding(
            finding="Round-number transaction clustering — possible structuring indicator",
            severity="LOW",
            risk_points=10,
            evidence=f"{len(round_txns)} debit transactions are exact multiples of ₹1,000",
            field="transaction_integrity",
        ))

    return findings, type_counts_result


def check_aml_indicators(transactions: List[dict]) -> List[AuthenticityFinding]:
    """Detect AML-related patterns: structuring, rapid movement, dormant activation."""
    findings = []
    if len(transactions) < 3:
        return findings

    classified = []
    for txn in transactions:
        tx_type = classify_transaction_type(txn.get("raw", ""))
        classified.append({**txn, "tx_type": tx_type})

    # 1. Structuring: round-number credits just below reporting thresholds (₹50,000, ₹1,00,000, ₹10,00,000)
    structuring_thresholds = [50000, 100000, 1000000]
    for threshold in structuring_thresholds:
        band_min = threshold * 0.95
        credits = [t for t in classified if t.get("credit") and band_min <= t["credit"] < threshold]
        if len(credits) >= 3:
            total = sum(t["credit"] for t in credits)
            findings.append(AuthenticityFinding(
                finding=f"AML structuring pattern detected — {len(credits)} credits just below ₹{threshold:,}",
                severity="HIGH",
                risk_points=35,
                evidence=f"{len(credits)} credit transactions totaling ₹{total:,.2f} in range ₹{band_min:,.0f}–₹{threshold:,.0f}",
                field="aml",
            ))

    # 2. Rapid account movement: large credit followed quickly by debit
    for i in range(len(classified) - 1):
        curr = classified[i]
        nxt = classified[i + 1]
        if curr.get("credit") and curr["credit"] >= 100000 and nxt.get("debit") and nxt["debit"] >= 50000:
            findings.append(AuthenticityFinding(
                finding="Rapid account movement — large credit immediately followed by large debit",
                severity="HIGH",
                risk_points=30,
                evidence=f"Credit ₹{curr['credit']:,.2f} followed by debit ₹{nxt['debit']:,.2f} in consecutive transactions",
                field="aml",
            ))

    # 3. Dormant account activity
    dates_with_txns = []
    for t in classified:
        date_str = t.get("date")
        if not date_str:
            continue
        parsed = _parse_date(date_str)
        if parsed:
            dates_with_txns.append(parsed)

    if len(dates_with_txns) >= 3:
        dates_with_txns.sort()
        gaps = []
        for i in range(1, len(dates_with_txns)):
            from datetime import date as dt_date
            prev = dt_date(dates_with_txns[i - 1][0], dates_with_txns[i - 1][1], dates_with_txns[i - 1][2])
            curr = dt_date(dates_with_txns[i][0], dates_with_txns[i][1], dates_with_txns[i][2])
            gap = (curr - prev).days
            if gap > 0:
                gaps.append(gap)
        if gaps and max(gaps) > 90:
            max_gap = max(gaps)
            idx = gaps.index(max_gap)
            findings.append(AuthenticityFinding(
                finding=f"Dormant account reactivation — {max_gap}-day gap in transaction activity",
                severity="MEDIUM",
                risk_points=20,
                evidence=f"Gap of {max_gap} days between transactions {idx + 1} and {idx + 2} (indexed by date order)",
                field="aml",
            ))

    return findings


def estimate_fraud_loss(transactions: List[dict], findings: List[AuthenticityFinding],
                        parser_confidence: float = 1.0,
                        has_balance_mismatch: bool = False,
                        has_txn_mismatch: bool = False) -> Optional[dict]:
    """Estimate potential fraud loss.
    Only generates an estimate when BOTH:
    - parser_confidence > 0.9
    - A real balance mismatch or transaction mismatch exists
    Returns None (no estimate) when conditions are not met.
    """
    if parser_confidence < 0.9:
        return None
    if not has_balance_mismatch and not has_txn_mismatch:
        return None

    total_debits = sum(t.get("debit", 0) or 0 for t in transactions)
    total_credits = sum(t.get("credit", 0) or 0 for t in transactions)

    balance_mismatch_risk = 0.0
    for f in findings:
        if f.field == "transaction_integrity" and ("balance" in f.finding.lower() or "reconciliation" in f.finding.lower()):
            balance_mismatch_risk += f.risk_points / 100.0

    loss = round(balance_mismatch_risk * total_debits * 0.3, 2) if total_debits > 0 else 0.0
    if loss <= 0:
        return None

    return {
        "total_loss": loss,
        "balance_mismatch_loss": loss,
        "aml_loss": 0.0,
        "anomaly_loss": 0.0,
    }


def cross_validate_documents(documents: List[dict]) -> dict:
    """Compare common fields across multiple documents for consistency.
    
    Returns a dict with consistency score, mismatches, and verified fields.
    Stub ready for multi-document upload pipeline.
    """
    if not documents or len(documents) < 2:
        return {"score": 100.0, "mismatches": [], "verified_fields": []}

    fields_to_check = ["bank_name", "account_number", "customer_name", "ifsc"]
    mismatches = []
    verified_fields = []

    for field in fields_to_check:
        values = [d.get(field) for d in documents if d.get(field)]
        if len(values) >= 2:
            if len(set(str(v).strip().lower() for v in values)) == 1:
                verified_fields.append(field)
            else:
                mismatches.append({"field": field, "values": values})

    score = max(0.0, 100.0 - (len(mismatches) * 25.0))
    return {"score": score, "mismatches": mismatches, "verified_fields": verified_fields}


def _parse_date(date_str) -> Optional[Tuple[int, int, int]]:
    """Parse DD/MM/YYYY or DD-MM-YYYY into (year, month, day)."""
    if not date_str:
        return None
    if not isinstance(date_str, str):
        date_str = str(date_str)
    m = re.match(r'(\d{2})[/-](\d{2})[/-](\d{2,4})', date_str.strip())
    if not m:
        return None
    day, month, year = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if year < 100:
        year += 2000
    if month < 1 or month > 12 or day < 1 or day > 31:
        return None
    return year, month, day


# ── Check Functions ──────────────────────────────────────────────────

def check_template_document(text: str) -> Optional[AuthenticityFinding]:
    text_lower = text.lower()
    for kw in TEMPLATE_KEYWORDS:
        if kw in text_lower:
            context_start = max(0, text_lower.index(kw) - 30)
            context_end = min(len(text_lower), text_lower.index(kw) + len(kw) + 30)
            snippet = text[context_start:context_end].strip()
            return AuthenticityFinding(
                finding=f"Template watermark detected: '{kw}'",
                severity="CRITICAL",
                risk_points=WEIGHTS["template_watermark"],
                evidence=f"Text contains template indicator: '{snippet}'",
                field="document_authenticity",
            )
    return None


def _score_bank_names(text: str) -> dict:
    lines = text.split("\n")
    scores = {}
    for line in lines[:20]:
        for bank_key, bank_def in BANK_IDENTIFIERS.items():
            for alias in bank_def["aliases"]:
                if alias in line.lower():
                    scores[bank_key] = scores.get(bank_key, 0) + 10
    for line in lines[20:]:
        for bank_key, bank_def in BANK_IDENTIFIERS.items():
            for alias in bank_def["aliases"]:
                if alias in line.lower():
                    scores[bank_key] = scores.get(bank_key, 0) + 1
    return scores


def check_bank_identity(text: str) -> Tuple[Optional[str], float, List[AuthenticityFinding]]:
    text_lower = text.lower()
    findings = []

    ifsc = _extract_ifsc(text)
    detected_bank = None
    bank_confidence = 0.0

    # Phase 1: IFSC-based detection (high confidence)
    if ifsc:
        for bank_key, bank_def in BANK_IDENTIFIERS.items():
            if ifsc.startswith(bank_def["ifsc_prefix"]):
                detected_bank = bank_key
                bank_confidence = 0.95
                break

    # Phase 2: Text alias scoring (medium confidence, fallback)
    scores = _score_bank_names(text)
    total_score = sum(scores.values()) if scores else 0

    if not detected_bank and scores:
        detected_bank = max(scores, key=scores.get)
        best_score = scores[detected_bank]
        bank_confidence = round(best_score / total_score, 2) if total_score > 0 else 0
        # Discount confidence when total matches are very low
        if total_score < 5:
            bank_confidence = max(bank_confidence, 0.3)

    if not detected_bank:
        return None, 0.0, findings

    # IFSC vs detected-bank validation
    if ifsc:
        expected_prefix = BANK_IDENTIFIERS[detected_bank]["ifsc_prefix"]
        if not ifsc.startswith(expected_prefix):
            # The IFSC belongs to a different bank than what text suggests
            # Find the actual bank from IFSC
            ifsc_bank = None
            for bk, bd in BANK_IDENTIFIERS.items():
                if ifsc.startswith(bd["ifsc_prefix"]):
                    ifsc_bank = bk
                    break
            ifsc_label = BANK_IDENTIFIERS[ifsc_bank]["aliases"][0].title() if ifsc_bank else ifsc
            findings.append(AuthenticityFinding(
                finding=f"IFSC code {ifsc} ({ifsc_label}) does not match detected bank '{BANK_IDENTIFIERS[detected_bank]['aliases'][0].title()}'",
                severity="HIGH",
                risk_points=WEIGHTS["bank_identity_mismatch"],
                confidence=0.95,
                evidence=f"Found IFSC: {ifsc} → {ifsc_label}, text suggests: {detected_bank.title()}",
                field="bank_identity",
            ))

    # Bank identity conflict from multiple text references
    if scores and total_score > 0 and detected_bank in scores:
        best_score = scores[detected_bank]
        conflicting = [(k, v / total_score) for k, v in scores.items()
                       if k != detected_bank and v / total_score > 0.1]
        if conflicting and bank_confidence > 0.6:
            for other_bank, other_conf in conflicting:
                bank_label = BANK_IDENTIFIERS[detected_bank]["aliases"][0]
                other_label = BANK_IDENTIFIERS[other_bank]["aliases"][0]
                findings.append(AuthenticityFinding(
                    finding=f"Bank identity conflict — expected '{bank_label.title()}' but found references to '{other_label.title()}'",
                    severity="HIGH",
                    risk_points=WEIGHTS["bank_identity_mismatch"],
                    confidence=round(0.5 + bank_confidence * 0.4, 2),
                    evidence=f"Document identifies as '{bank_label.title()}' (confidence: {bank_confidence:.0%}) but also references '{other_label.title()}' (confidence: {other_conf:.0%})",
                    field="bank_identity",
                ))

    required = BANK_IDENTIFIERS[detected_bank]["required_fields"]
    field_risk_map = {
        "ifsc": WEIGHTS["missing_ifsc"],
        "account number": WEIGHTS["missing_account_number"],
        "branch": WEIGHTS["missing_branch"],
        "customer id": WEIGHTS["missing_customer_id"],
    }
    for field_name in required:
        if not _field_present(field_name, text):
            label = field_name.title()
            if field_name == "ifsc":
                label = "IFSC Code"
            elif field_name == "customer id":
                label = "Customer ID / CIF Number"
            findings.append(AuthenticityFinding(
                finding=f"Missing {label}",
                severity="MEDIUM",
                risk_points=field_risk_map.get(field_name, 5),
                confidence=0.9,
                evidence=f"Document does not contain '{field_name}' in its text",
                field="bank_identity",
            ))

    return detected_bank, bank_confidence, findings


def check_currency_consistency(text: str, bank_name: Optional[str] = None) -> Optional[AuthenticityFinding]:
    text_lower = text.lower()
    has_inr = any(sym in text for sym in INR_SYMBOLS)
    has_inr = has_inr or "rupee" in text_lower

    has_foreign_symbol = any(sym in text for sym in FOREIGN_CURRENCY_SYMBOLS)
    has_foreign_code = any(code in text_lower for code in FOREIGN_CURRENCY_CODES)

    if has_foreign_symbol or has_foreign_code:
        foreign_present = []
        for sym in FOREIGN_CURRENCY_SYMBOLS:
            if sym in text:
                foreign_present.append(sym)
        for code in FOREIGN_CURRENCY_CODES:
            if code in text_lower:
                foreign_present.append(code.upper())
        if foreign_present:
            institution = (bank_name or "Indian bank").title()
            evidence = (
                f"Institution: {institution} | "
                f"Expected currency: INR (₹) | "
                f"Detected: {', '.join(foreign_present)}"
            )
            return AuthenticityFinding(
                finding=f"Institution Consistency Failure — {institution} detected with non-INR currency ({', '.join(foreign_present)})",
                severity="CRITICAL",
                risk_points=WEIGHTS["currency_mismatch"],
                evidence=evidence,
                field="currency_consistency",
            )
    return None


def check_running_balance(text: str) -> Optional[AuthenticityFinding]:
    """Validate running balance integrity. +40 risk on mismatch."""
    transactions = _extract_structured_transactions(text)
    if len(transactions) < 3:
        return None

    for i in range(1, len(transactions)):
        prev = transactions[i - 1]
        curr = transactions[i]
        prev_bal = prev.get("balance")
        curr_bal = curr.get("balance")
        debit = curr.get("debit")
        credit = curr.get("credit")

        if prev_bal is not None and curr_bal is not None:
            expected = prev_bal
            if debit:
                expected -= debit
            if credit:
                expected += credit

            if abs(expected - curr_bal) > 0.01:
                return AuthenticityFinding(
                    finding="Running balance inconsistency detected",
                    severity="HIGH",
                    risk_points=40,
                    confidence=0.8,
                    evidence=(
                        f"Transaction {i}: expected balance ₹{expected:,.2f} "
                        f"but found ₹{curr_bal:,.2f} "
                        f"(prev: ₹{prev_bal:,.2f}, "
                        f"debit: {'₹' + f'{debit:,.2f}' if debit else 'N/A'}, "
                        f"credit: {'₹' + f'{credit:,.2f}' if credit else 'N/A'})"
                    ),
                    field="transaction_integrity",
                )
    return None


def check_transaction_patterns(text: str) -> List[AuthenticityFinding]:
    """Check for duplicate transactions, date order errors, future dates, negative balances."""
    findings = []
    transactions = _extract_structured_transactions(text)
    if len(transactions) < 2:
        return findings

    dates_seen = {}
    for i, txn in enumerate(transactions):
        date_str = txn.get("date") or ""
        parsed = _parse_date(date_str)
        if not parsed:
            continue

        year, month, day = parsed

        from datetime import date
        if (year, month, day) > (date.today().year, date.today().month, date.today().day):
            findings.append(AuthenticityFinding(
                finding=f"Future transaction date detected: {date_str}",
                severity="MEDIUM",
                risk_points=15,
                confidence=0.7,
                evidence=f"Transaction {i + 1} has date {date_str} which is in the future",
                field="transaction_integrity",
            ))

        amount_key = f"{txn.get('debit')}-{txn.get('credit')}"
        date_amount_key = f"{date_str}:{amount_key}"
        if date_amount_key in dates_seen:
            findings.append(AuthenticityFinding(
                finding=f"Possible duplicate transaction on {date_str}",
                severity="MEDIUM",
                risk_points=20,
                confidence=0.7,
                evidence=f"Same date and amount combination found at transactions {dates_seen[date_amount_key] + 1} and {i + 1}",
                field="transaction_integrity",
            ))
        dates_seen[date_amount_key] = i

    for i in range(1, len(transactions)):
        prev = _parse_date(transactions[i - 1].get("date") or "")
        curr = _parse_date(transactions[i].get("date") or "")
        if prev and curr:
            if (curr[0], curr[1], curr[2]) < (prev[0], prev[1], prev[2]):
                findings.append(AuthenticityFinding(
                    finding=f"Date order error: {transactions[i]['date']} follows {transactions[i - 1]['date']}",
                    severity="MEDIUM",
                    risk_points=15,
                    evidence=f"Transaction {i + 1} dated {transactions[i]['date']} appears after transaction {i} dated {transactions[i - 1]['date']}",
                    field="transaction_integrity",
                ))

    for i, txn in enumerate(transactions):
        bal = txn.get("balance")
        if bal is not None and bal < 0:
            findings.append(AuthenticityFinding(
                finding="Negative balance detected",
                severity="LOW",
                risk_points=5,
                evidence=f"Transaction {i + 1} shows negative balance of ₹{abs(bal):,.2f}",
                field="transaction_integrity",
            ))

    return findings


# ── Balance Reconciliation & Transaction Total Validation ───────────


def _extract_declared_balances(text: str) -> dict:
    """Extract declared opening/closing balances and totals from text."""
    result = {}

    # Preserve line structure — only normalize spaces within each line
    lines = text.split('\n')

    # Currency prefix: optional ₹ or Rs. (with optional dot and space)
    CURR = r'(?:Rs\.?\s*|₹\s*)?'

    PATTERNS: dict[str, list[str]] = {
        "opening_balance": [
            rf'(?:Opening|Open)(?:\s+Balance)?\s*[:\-=]?\s*{CURR}([\d,]+(?:\.\d{{2}})?)',
        ],
        "closing_balance": [
            rf'(?:Closing|Close|Cl)(?:\s+Balance)?\s*[:\-=]?\s*{CURR}([\d,]+(?:\.\d{{2}})?)',
        ],
        "total_credits": [
            rf'(?:Total|Tot)(?:\s+Credit|Cr)\w*\s*[:\-=]?\s*{CURR}([\d,]+(?:\.\d{{2}})?)',
        ],
        "total_debits": [
            rf'(?:Total|Tot)(?:\s+Debit|Dr)\w*\s*[:\-=]?\s*{CURR}([\d,]+(?:\.\d{{2}})?)',
        ],
    }

    for key, patterns in PATTERNS.items():
        for p in patterns:
            m = re.search(p, text, re.IGNORECASE)
            if m:
                val = float(m.group(1).replace(',', ''))
                result[key] = val
                logger.warning("MATCH_%s", key.upper(), value=val)
                break

    # ── Log everything extracted ──
    logger.warning("EXTRACTED_BALANCES_FULL",
                   opening=result.get("opening_balance"),
                   credits=result.get("total_credits"),
                   debits=result.get("total_debits"),
                   closing=result.get("closing_balance"),
                   keys=list(result.keys()))
    return result


def _sum_transaction_totals(text: str) -> dict:
    """Sum credits and debits from individual transactions."""
    transactions = _extract_structured_transactions(text)
    total_credits = sum(t.get("credit", 0) or 0 for t in transactions)
    total_debits = sum(t.get("debit", 0) or 0 for t in transactions)
    return {"total_credits": total_credits, "total_debits": total_debits}


def _compute_parser_confidence(transactions: List[dict], text: str) -> float:
    """Rate transaction extraction reliability on 0-1 scale."""
    n = len(transactions)
    declared = _extract_declared_balances(text)
    if n == 0:
        if declared:
            return 0.30
        return 0.0

    # Base confidence from row count
    if n >= 5:
        conf = 0.85
    elif n >= 3:
        conf = 0.70
    else:
        conf = 0.50

    # Check if most rows have a balance (indicates good tabular extraction)
    with_balance = sum(1 for t in transactions if t.get("balance") is not None)
    if with_balance >= n * 0.7:
        conf = min(1.0, conf + 0.10)

    # Check if both credits and debits exist (plausible transaction mix)
    has_credits = any(t.get("credit") for t in transactions)
    has_debits = any(t.get("debit") for t in transactions)
    if has_credits and has_debits:
        conf = min(1.0, conf + 0.05)

    # Penalize if declared totals exist but fewer than 3 rows were parsed
    if declared and n < 3:
        conf = min(conf, 0.60)

    return round(min(1.0, max(0.0, conf)), 2)


def check_balance_reconciliation(
    text: str, parser_confidence: float = 1.0, transaction_coverage: float = 1.0,
) -> Optional[AuthenticityFinding]:
    """Validate opening + credits - debits == closing balance.
    Uses ValidationStatus semantics:
      PASS    → no finding (None)
      UNKNOWN → low confidence / missing data
      FAIL    → actual mismatch
    """
    declared = _extract_declared_balances(text)
    logger.info("BALANCE_RECONCILIATION",
                opening=declared.get("opening_balance"),
                credits=declared.get("total_credits"),
                debits=declared.get("total_debits"),
                closing=declared.get("closing_balance"))

    if not all(k in declared for k in ("opening_balance", "closing_balance", "total_credits", "total_debits")):
        logger.info("BALANCE_RECONCILIATION_SKIP",
                    reason="Missing one or more required fields",
                    declared_keys=list(declared.keys()))
        return None

    expected = declared["opening_balance"] + declared["total_credits"] - declared["total_debits"]
    actual = declared["closing_balance"]

    is_match = abs(expected - actual) <= 1

    # Low parser confidence or low coverage → downgrade status still do comparison
    if parser_confidence < 0.8 or transaction_coverage < 0.7:
        if is_match:
            logger.info("BALANCE_RECONCILIATION_OK_LOW_CONF",
                        expected=expected, actual=actual, parser_confidence=parser_confidence)
            return None
        return AuthenticityFinding(
            finding=f"Balance reconciliation failure (expected ₹{expected:,.2f}, found ₹{actual:,.2f})",
            severity="MEDIUM",
            risk_points=30,
            status="UNKNOWN",
            confidence=parser_confidence,
            evidence=f"Opening: ₹{declared['opening_balance']:,.2f}, Credits: ₹{declared['total_credits']:,.2f}, Debits: ₹{declared['total_debits']:,.2f}, Expected Closing: ₹{expected:,.2f}, Actual Closing: ₹{actual:,.2f}. Low extraction confidence ({parser_confidence:.2f}) — manual verification recommended.",
            field="transaction_integrity",
        )

    if not is_match:
        finding = AuthenticityFinding(
            finding=f"Balance reconciliation failure (expected ₹{expected:,.2f}, found ₹{actual:,.2f})",
            severity="CRITICAL",
            risk_points=60,
            status="FAIL",
            confidence=min(1.0, parser_confidence + 0.1),
            evidence=(
                f"Opening: ₹{declared['opening_balance']:,.2f}, "
                f"Credits: ₹{declared['total_credits']:,.2f}, "
                f"Debits: ₹{declared['total_debits']:,.2f}, "
                f"Expected Closing: ₹{expected:,.2f}, "
                f"Actual Closing: ₹{actual:,.2f}"
            ),
            field="transaction_integrity",
        )
        logger.info("BALANCE_RECONCILIATION_FAIL",
                    expected=expected, actual=actual, diff=abs(expected - actual))
        return finding

    logger.info("BALANCE_RECONCILIATION_OK", expected=expected, actual=actual)
    return None


def check_transaction_total_mismatch(
    text: str, parser_confidence: float = 1.0, transaction_coverage: float = 1.0,
) -> Optional[AuthenticityFinding]:
    """Compare declared totals against individual transaction sums using 1% tolerance.
    Uses ValidationStatus semantics.
    """
    declared = _extract_declared_balances(text)
    transaction_totals = _sum_transaction_totals(text)

    logger.info("TRANSACTION_TOTAL_CHECK",
                declared_credits=declared.get("total_credits"),
                declared_debits=declared.get("total_debits"),
                summed_credits=transaction_totals["total_credits"],
                summed_debits=transaction_totals["total_debits"],
                parser_confidence=parser_confidence,
                coverage=transaction_coverage)

    has_declared_totals = "total_credits" in declared or "total_debits" in declared
    if not has_declared_totals:
        return None

    # Compute comparison once for both low and normal confidence paths
    mismatches = []
    TOLERANCE = 0.01  # 1%
    has_both_sides = False
    has_any_parsed = False

    for side_key, declared_key in [("total_credits", "credit"), ("total_debits", "debit")]:
        if side_key in declared:
            declared_val = declared[side_key]
            parsed_val = transaction_totals[side_key]
            if parsed_val > 0:
                has_any_parsed = True
                has_both_sides = True
                ratio = abs(declared_val - parsed_val) / max(declared_val, parsed_val)
                if ratio > TOLERANCE:
                    mismatches.append(
                        f"{declared_key.title()}s: declared ₹{declared_val:,.2f}, "
                        f"summed ₹{parsed_val:,.2f} (diff: {ratio:.1%})"
                    )
            elif declared_val > 0:
                mismatches.append(
                    f"{declared_key.title()}s: declared ₹{declared_val:,.2f} "
                    f"but no individual {declared_key} transactions found"
                )

    # Low confidence/coverage path — downgrade to UNKNOWN status
    if parser_confidence < 0.8 or transaction_coverage < 0.7:
        if not mismatches and has_any_parsed:
            return None
        if mismatches and has_any_parsed:
            return AuthenticityFinding(
                finding="Transaction total mismatch — " + "; ".join(mismatches),
                severity="MEDIUM",
                risk_points=15,
                status="UNKNOWN",
                evidence=f"Parser confidence {parser_confidence:.2f}, coverage {transaction_coverage:.0%}. Low confidence — manual verification recommended.",
                field="transaction_integrity",
            )
        # No parsed rows at all — UNKNOWN, not FAIL
        return AuthenticityFinding(
            finding="Unable to verify transaction totals — no transaction rows extracted",
            severity="LOW",
            risk_points=0,
            status="UNKNOWN",
            evidence=f"Parser confidence {parser_confidence:.2f}, coverage {transaction_coverage:.0%}. Declared totals present but 0 transaction rows parsed.",
            field="transaction_integrity",
        )

    if not mismatches:
        logger.info("TRANSACTION_TOTAL_OK",
                    declared_credits=declared.get("total_credits"),
                    parsed_credits=transaction_totals["total_credits"])
        return None

    # Tiered scoring based on error percentage
    max_error_pct = 0.0
    for side_key, _ in [("total_credits", "credit"), ("total_debits", "debit")]:
        if side_key in declared:
            declared_val = declared[side_key]
            parsed_val = transaction_totals[side_key]
            if max(declared_val, parsed_val) > 0:
                error_pct = abs(declared_val - parsed_val) / max(declared_val, parsed_val)
                max_error_pct = max(max_error_pct, error_pct)

    if max_error_pct < 0.02:
        risk_points = 5
        severity = "LOW"
    elif max_error_pct < 0.10:
        risk_points = 15
        severity = "MEDIUM"
    elif max_error_pct < 0.30:
        risk_points = 25
        severity = "HIGH"
    else:
        risk_points = 40
        severity = "CRITICAL"

    return AuthenticityFinding(
        finding="Transaction total mismatch — declared totals do not match individual transactions",
        severity=severity,
        risk_points=risk_points,
        confidence=parser_confidence,
        evidence="; ".join(mismatches),
        field="transaction_integrity",
    )


def check_metadata_timeline(meta: dict) -> List[AuthenticityFinding]:
    """Analyze PDF metadata for suspicious timestamps. +15 for modified after creation."""
    findings = []
    pdf_meta = meta.get("pdf_metadata", {})

    creation = pdf_meta.get("creationDate") or pdf_meta.get("creation_date")
    modification = pdf_meta.get("modDate") or pdf_meta.get("mod_date")

    if creation and modification and creation != modification:
        findings.append(AuthenticityFinding(
            finding="Document modified after creation — timeline inconsistency",
            severity="MEDIUM",
            risk_points=15,
            evidence=f"Created: {creation}, Modified: {modification}",
            field="metadata_forensics",
        ))

    producer = (pdf_meta.get("producer") or "").lower()
    suspicious_producers = [
        "unknown", "random pdf", "online tool", "free pdf",
        "pdf generator", "pdf converter", "pdf creator",
        "canva", "google docs", "google doc", "microsoft word", "word",
        "wps office", "wps pdf", "foxit phantom", "foxit reader",
        "libreoffice draw", "libreoffice", "openoffice",
        "photoshop", "adobe photoshop", "illustrator", "adobe illustrator",
        "gimp", "inkscape", "coreldraw", "paint", "mspaint",
        "pdf filler", "pdf escape", "ilovepdf", "pdf candy",
        "smallpdf", "pdf24", "sejda", "pdfsam", "pdf architect",
        "nitro pdf", "foxit phantompdf", "pdfelement",
        "pdf filler", "pdfzen", "pdf converter pro",
        "pdf to image", "image to pdf", "jpg to pdf",
        "html to pdf", "web to pdf", "print to pdf",
    ]
    if producer:
        for sp in suspicious_producers:
            if sp in producer:
                findings.append(AuthenticityFinding(
                    finding=f"Suspicious PDF producer: '{producer}'",
                    severity="MEDIUM",
                    risk_points=10,
                    evidence=f"Document produced by '{producer}' which may indicate non-banking origin",
                    field="metadata_forensics",
                ))
                break

    return findings


def check_invoice_layout(text: str) -> Optional[AuthenticityFinding]:
    """Detect invoice-style terminology in what claims to be a bank statement. +25 risk."""
    text_lower = text.lower()
    matches = [kw for kw in INVOICE_KEYWORDS if kw in text_lower]
    if matches:
        return AuthenticityFinding(
            finding=f"Invoice-style layout detected — bank statement contains invoice terminology ({', '.join(matches[:3])})",
            severity="HIGH",
            risk_points=25,
            evidence=f"Found invoice keywords in bank statement: {', '.join(matches)}",
            field="document_authenticity",
        )
    return None


def check_public_template_source(text: str) -> Optional[AuthenticityFinding]:
    text_lower = text.lower()
    for kw in PUBLIC_TEMPLATE_INDICATORS:
        if kw in text_lower:
            return AuthenticityFinding(
                finding=f"Public template source detected: '{kw}' — document likely from template marketplace",
                severity="CRITICAL",
                risk_points=WEIGHTS["public_template_source"],
                evidence=f"Document contains '{kw}', a known public template source",
                field="document_authenticity",
            )
    return None


# ── Bank Layout Fingerprints ────────────────────────────────────────

BANK_EXPECTED_SECTIONS = {
    "canara": ["account summary", "transaction details", "branch", "ifsc", "customer id"],
    "sbi": ["account summary", "transaction details", "branch", "ifsc"],
    "hdfc": ["account summary", "transaction details", "branch", "ifsc"],
    "icici": ["account summary", "transaction details", "branch", "ifsc"],
}


def check_layout_similarity(text: str, bank_name: Optional[str] = None) -> Optional[AuthenticityFinding]:
    """Compare extracted structure against expected bank layout. Minor signal only."""
    if not bank_name:
        return None

    expected = BANK_EXPECTED_SECTIONS.get(bank_name.lower())
    if not expected:
        return None

    text_lower = text.lower()
    matched = sum(1 for section in expected if section in text_lower)
    similarity = matched / len(expected) if expected else 0

    if similarity < 0.25:
        return AuthenticityFinding(
            finding=f"Layout structure mismatch for {bank_name.title()} — expected {len(expected)} sections, matched {matched}",
            severity="MEDIUM",
            risk_points=5,
            confidence=0.6,
            evidence=f"Expected sections: {', '.join(expected)} | Matched: {matched}/{len(expected)} (similarity: {similarity:.0%})",
            field="document_authenticity",
        )
    return None


# ── Risk Override Layer (Incremental, not hard jumps) ──────────────

# Banks hate hard-coded jumps.  Each rule adds a fixed penalty rather
# than setting an absolute score.  The final_score = min(score, 100).

# Penalties for findings NOT already deducted inline in analyze_bank_statement.
# Items like template, balance_mismatch, running_balance, txn_total_mismatch
# are already deducted in the main scoring loop — adding them here would double-count.
RISK_PENALTIES = [
    ("has_currency_mismatch", 20, "Non-INR currency detected — Indian bank statement should use INR"),
    ("has_public_template_indicator", 15, "Public template source detected"),
]


def apply_incremental_penalties(result: BankingAuthenticityResult, current_score: float) -> tuple[float, list[str]]:
    """Add incremental penalties instead of hard score overrides.
    Returns (adjusted_score, reasons)."""
    reasons = []
    for attr, penalty, reason in RISK_PENALTIES:
        if getattr(result, attr, False):
            current_score -= penalty
            reasons.append(reason)
    current_score = max(0.0, current_score)
    if reasons:
        logger.info("INCREMENTAL_PENALTIES_APPLIED", penalties=reasons,
                    final_score=current_score)
    return current_score, reasons


# ── Document Type Detection ──────────────────────────────────────────

def detect_document_type(text: str) -> str:
    text_lower = text.lower()
    invoice_kws = ["subtotal", "sub-total", "discount", "tax", "qty", "quantity", "unit price", "invoice", "total amount due"]
    bank_kws = ["statement", "account statement", "bank statement", "transaction", "withdrawal", "deposit", "balance", "branch", "ifsc", "opening balance", "closing balance"]
    salary_kws = ["salary", "pay slip", "payslip", "earnings", "deductions", "take home", "net pay", "allowance", "hra", "pf"]

    invoice_score = sum(2 for kw in invoice_kws if kw in text_lower)
    bank_score = sum(1 for kw in bank_kws if kw in text_lower)
    salary_score = sum(2 for kw in salary_kws if kw in text_lower)

    if invoice_score >= bank_score and invoice_score >= salary_score and invoice_score >= 4:
        return DOCUMENT_INVOICE
    if salary_score >= bank_score and salary_score >= invoice_score and salary_score >= 4:
        return DOCUMENT_SALARY
    if bank_score >= 3:
        return DOCUMENT_BANK_STATEMENT
    return DOCUMENT_UNKNOWN


# ── Whitelist / Good Signals ─────────────────────────────────────────

WHITELIST_SIGNALS = {
    "ifsc_present": {"label": "IFSC Code Present", "risk_reduction": 3},
    "account_present": {"label": "Account Number Present", "risk_reduction": 3},
    "bank_name_consistent": {"label": "Consistent Bank Name", "risk_reduction": 5},
    "digitally_signed": {"label": "Digitally Signed PDF", "risk_reduction": 5},
    "bank_logo_detected": {"label": "Bank Logo Detected", "risk_reduction": 5},
}


def compute_whitelist_signals(text: str, bank_name: Optional[str] = None, meta: Optional[dict] = None) -> list:
    signals = []
    ifsc = _extract_ifsc(text)
    if ifsc:
        signals.append({"signal": "ifsc_present", "detail": f"IFSC: {ifsc}", "reduction": WHITELIST_SIGNALS["ifsc_present"]["risk_reduction"]})

    accounts = _extract_account_numbers(text)
    if accounts:
        signals.append({"signal": "account_present", "detail": f"Account: {accounts[0]}", "reduction": WHITELIST_SIGNALS["account_present"]["risk_reduction"]})

    if bank_name:
        scores = _score_bank_names(text)
        if scores:
            total = sum(scores.values())
            best = max(scores.values())
            if total > 0 and best / total > 0.8:
                signals.append({"signal": "bank_name_consistent", "detail": f"Bank: {bank_name.title()}", "reduction": WHITELIST_SIGNALS["bank_name_consistent"]["risk_reduction"]})

    if meta:
        pdf_meta = meta.get("pdf_metadata", {}) if isinstance(meta, dict) else {}
        sigs = (pdf_meta.get("signature") or pdf_meta.get("permissions") or "")
        if sigs:
            signals.append({"signal": "digitally_signed", "detail": "PDF contains digital signature/permissions", "reduction": WHITELIST_SIGNALS["digitally_signed"]["risk_reduction"]})

    return signals


# ── Main Entry Point ─────────────────────────────────────────────────

# ── Bank-Specific Validators ─────────────────────────────────────────

def validate_bank_template(text: str, bank_name: Optional[str] = None) -> List[AuthenticityFinding]:
    """Check document matches per-bank rule definitions.

    Delegates to app.services.bank_rules.run_bank_rules() which provides
    per-bank required fields, sections, known phrases, and layout rules.
    """
    findings: List[AuthenticityFinding] = []
    if not bank_name:
        return findings

    raw_findings = run_bank_rules(text, bank_name)
    for rf in raw_findings:
        findings.append(AuthenticityFinding(
            finding=rf["finding"],
            severity=rf["severity"],
            risk_points=rf["risk_points"],
            status="FAIL",
            confidence=0.85,
            evidence=f"Bank rule: {rf.get('field', 'document_authenticity')}",
            field=rf.get("field", "document_authenticity"),
        ))

    return findings


def analyze_bank_statement(
    text: str,
    meta: Optional[dict] = None,
    ocr_reliability: Optional[float] = None,
) -> BankingAuthenticityResult:
    """Run all banking authenticity checks and return consolidated result.
    Uses additive scoring from 100 with deterministic override rules.
    """
    result = BankingAuthenticityResult()
    if not text:
        logger.warning("BANKING_NO_TEXT", msg="Empty text provided to banking authenticity engine")
        result.authenticity_score = 0.0
        return result

    text_clean = _normalise(text)
    result.findings = []
    score = 100.0
    decision_reasons = []

    # ── Extract transactions once for reuse ──────────────────────────
    transactions = _extract_structured_transactions(text)
    result.transaction_count = len(transactions)
    parser_confidence = _compute_parser_confidence(transactions, text)
    logger.info("PARSER_CONFIDENCE", confidence=parser_confidence,
                transaction_count=len(transactions))

    # ── OCR Quality Gate ─────────────────────────────────────────────
    ocr_failed = ocr_reliability is not None and ocr_reliability < 0.7
    ocr_score = ocr_reliability if ocr_reliability is not None else 1.0
    if ocr_failed:
        logger.warning("OCR_QUALITY_GATE",
                       ocr_reliability=ocr_reliability,
                       parser_confidence=parser_confidence,
                       msg="Financial integrity checks disabled — OCR quality too low")

    # ── 1. Template detection ────────────────────────────────────────
    template_finding = check_template_document(text)
    if template_finding:
        result.findings.append(template_finding)
        score -= 50
        result.has_template_indicators = True
        decision_reasons.append("template_watermark")

    # ── 2. Bank identity validation ──────────────────────────────────
    detected_bank, bank_confidence, bank_findings = check_bank_identity(text)
    result.bank_name = detected_bank
    result.bank_confidence = bank_confidence

    ifsc = _extract_ifsc(text)
    accounts = _extract_account_numbers(text)
    branch_present = _field_present("branch", text)
    logger.warning("===== BANK EXTRACTION =====")
    logger.warning("BANK=%s", detected_bank)
    logger.warning("IFSC=%s", ifsc)
    logger.warning("ACCOUNT=%s", accounts[:1] if accounts else None)
    logger.warning("BRANCH=%s (present=%s)", "found" if branch_present else "NOT found", branch_present)
    logger.warning("===========================")

    for f in bank_findings:
        result.findings.append(f)
        field = f.field
        finding_lower = f.finding.lower()
        if "ifsc" in finding_lower and "missing" in finding_lower:
            score -= 10
            if "ifsc" not in decision_reasons:
                decision_reasons.append("missing_ifsc")
        elif "account number" in finding_lower and "missing" in finding_lower:
            score -= 35
            decision_reasons.append("missing_account_number")
        elif "branch" in finding_lower and "missing" in finding_lower:
            score -= 10
            if "branch" not in decision_reasons:
                decision_reasons.append("missing_branch")
        elif "customer" in finding_lower and "missing" in finding_lower:
            score -= 5
        elif "ifsc code" in finding_lower and "does not match" in finding_lower:
            score -= 15
            decision_reasons.append("ifsc_mismatch")
        elif "bank identity conflict" in finding_lower:
            score -= 25
            decision_reasons.append("bank_identity_conflict")

    # ── 3. Currency consistency ──────────────────────────────────────
    currency_finding = check_currency_consistency(text, detected_bank)
    if currency_finding:
        result.findings.append(currency_finding)
        score -= 20
        result.has_currency_mismatch = True
        decision_reasons.append("currency_mismatch")

    # ── 4. Running balance validation (gated on OCR quality) ────────
    if ocr_failed:
        result.findings.append(AuthenticityFinding(
            finding="Unable to verify running balance — OCR quality too low",
            severity="LOW",
            risk_points=0,
            status="UNKNOWN",
            confidence=ocr_score,
            evidence=f"OCR reliability {ocr_score:.2f} < 0.70 — running balance check skipped",
            field="transaction_integrity",
        ))
        logger.info("RUNNING_BALANCE_SKIPPED_OCR", ocr_reliability=ocr_score)
    else:
        balance_finding = check_running_balance(text)
        if balance_finding:
            result.findings.append(balance_finding)
            result.has_running_balance_issue = True
            result.balance_valid = False
            if parser_confidence >= 0.8:
                score -= 40
                decision_reasons.append("running_balance_mismatch")
            else:
                score -= 5
        else:
            if len(transactions) >= 3:
                result.balance_valid = True

    # ── 5. Transaction Coverage (before totals check) ────────────────
    expected_rows = 0
    # Estimate expected rows from summary lines
    for marker in ["opening balance", "opening", "total credits", "total debits", "closing balance"]:
        if marker in text.lower():
            expected_rows += 1
    declared = _extract_declared_balances(text)
    expected_rows = max(expected_rows, len(transactions) + 1)
    coverage = len(transactions) / max(expected_rows * 0.3, 1)  # 30% of lines expected to be transactions
    coverage = min(coverage, 1.0)

    # ── 5. Balance reconciliation (gated on OCR quality) ─────────────
    if ocr_failed:
        result.findings.append(AuthenticityFinding(
            finding="Unable to verify balance reconciliation — OCR quality too low",
            severity="LOW",
            risk_points=0,
            status="UNKNOWN",
            confidence=ocr_score,
            evidence=f"OCR reliability {ocr_score:.2f} < 0.70 — balance reconciliation check skipped",
            field="transaction_integrity",
        ))
        logger.info("BALANCE_RECONCILIATION_SKIPPED_OCR", ocr_reliability=ocr_score)
    else:
        reconciliation_finding = check_balance_reconciliation(text, parser_confidence, coverage)
        if reconciliation_finding:
            result.findings.append(reconciliation_finding)
            if reconciliation_finding.status == "FAIL":
                result.has_balance_reconciliation_issue = True
                result.balance_valid = False
                score -= 40
                decision_reasons.append("balance_mismatch")
            # UNKNOWN status: no score deduction, just log it
            elif reconciliation_finding.status == "UNKNOWN":
                result.balance_valid = None
                logger.info("BALANCE_RECONCILIATION_UNKNOWN",
                            reason=reconciliation_finding.finding)
            logger.info("BALANCE_RECONCILIATION_FINDING",
                        finding=reconciliation_finding.finding,
                        status=reconciliation_finding.status,
                        risk_points=reconciliation_finding.risk_points)
        else:
            logger.info("BALANCE_RECONCILIATION_PASS")
            result.balance_valid = True
            decision_reasons.append("balance_passes")

    # ── 6. Transaction total mismatch (gated on OCR quality) ─────────
    if ocr_failed:
        result.findings.append(AuthenticityFinding(
            finding="Unable to verify transaction totals — OCR quality too low",
            severity="LOW",
            risk_points=0,
            status="UNKNOWN",
            confidence=ocr_score,
            evidence=f"OCR reliability {ocr_score:.2f} < 0.70 — transaction total check skipped",
            field="transaction_integrity",
        ))
        logger.info("TRANSACTION_TOTAL_SKIPPED_OCR", ocr_reliability=ocr_score)
    else:
        total_mismatch_finding = check_transaction_total_mismatch(text, parser_confidence, coverage)
        if total_mismatch_finding:
            result.findings.append(total_mismatch_finding)
            if total_mismatch_finding.status == "FAIL":
                result.has_transaction_total_mismatch = True
                score -= 25
                decision_reasons.append("transaction_total_mismatch")
            elif total_mismatch_finding.status == "UNKNOWN":
                logger.info("TRANSACTION_TOTAL_UNKNOWN",
                            reason=total_mismatch_finding.finding)
            logger.info("TRANSACTION_TOTAL_FINDING",
                        finding=total_mismatch_finding.finding,
                        status=total_mismatch_finding.status,
                        risk_points=total_mismatch_finding.risk_points)
        else:
            logger.info("TRANSACTION_TOTAL_PASS")

    # ── 7. Transaction pattern analysis ──────────────────────────────
    pattern_findings = check_transaction_patterns(text)
    for f in pattern_findings:
        result.findings.append(f)
        score -= min(f.risk_points, 15)

    # ── 8. Transaction Intelligence + AML ────────────────────────────
    txn_intel_findings, type_counts_result = analyze_transaction_intelligence(text, transactions)
    result.transaction_types = type_counts_result
    for f in txn_intel_findings:
        result.findings.append(f)
        score -= min(f.risk_points, 10)

    aml_findings = check_aml_indicators(transactions)
    for f in aml_findings:
        result.findings.append(f)
        result.has_aml_structuring = True
        score -= min(f.risk_points, 15)

    # ── 9. Fraud Loss Estimate (only with high confidence + real mismatch) ──
    has_balance_issue = result.has_balance_reconciliation_issue or result.has_running_balance_issue
    loss_estimate = estimate_fraud_loss(
        transactions, result.findings, parser_confidence,
        has_balance_mismatch=has_balance_issue,
        has_txn_mismatch=result.has_transaction_total_mismatch,
    )
    if loss_estimate:
        result.estimated_fraud_loss = loss_estimate["total_loss"]
        result.has_fraud_loss_estimate = True

    # ── 10. Timeline events ──────────────────────────────────────────
    result.timeline_events = []
    for i, f in enumerate(result.findings):
        result.timeline_events.append({
            "event": f.finding[:80],
            "severity": f.severity,
            "risk_points": f.risk_points,
            "field": f.field,
            "index": i,
        })

    # ── 11. Metadata analysis ────────────────────────────────────────
    meta_provided = meta is not None and isinstance(meta, dict)
    if meta_provided:
        pdf_meta = meta.get("pdf_metadata", {})
        has_meta_content = bool(pdf_meta and any(v for v in pdf_meta.values() if v))
        if has_meta_content:
            meta_findings = check_metadata_timeline(meta)
            for f in meta_findings:
                result.findings.append(f)
                score -= f.risk_points
        else:
            meta_missing_finding = AuthenticityFinding(
                finding="Missing PDF metadata — document may not be from a banking source",
                severity="MEDIUM",
                risk_points=WEIGHTS["metadata_missing"],
                evidence="No PDF metadata (creation date, producer, etc.) found",
                field="metadata_forensics",
            )
            result.findings.append(meta_missing_finding)
            score -= WEIGHTS["metadata_missing"]
            result.has_metadata_missing = True

    # ── 12. Invoice layout detection ─────────────────────────────────
    invoice_finding = check_invoice_layout(text)
    if invoice_finding:
        result.findings.append(invoice_finding)
        score -= 25
        result.has_invoice_layout = True

    # ── 13. Public template source ───────────────────────────────────
    public_template_finding = check_public_template_source(text)
    if public_template_finding:
        result.findings.append(public_template_finding)
        score -= 30
        result.has_public_template_indicator = True

    # ── 14. Layout similarity check ──────────────────────────────────
    layout_finding = check_layout_similarity(text, detected_bank)
    if layout_finding:
        result.findings.append(layout_finding)
        score -= layout_finding.risk_points

    # ── 15. Bank-specific template validation ────────────────────────
    template_findings = validate_bank_template(text, detected_bank)
    for f in template_findings:
        result.findings.append(f)
        score -= min(f.risk_points, 15)

    # ── Positive Trust Scoring ──────────────────────────────────────
    # Modestly reward genuine documents for having expected fields.
    # Values are set small enough that missing-field deductions still
    # produce a net negative effect on the final score.
    total_trust = 0
    if ifsc:
        total_trust += 2
        decision_reasons.append("trust_ifsc")
    if accounts:
        total_trust += 2
        decision_reasons.append("trust_account")
    if branch_present:
        total_trust += 1
        decision_reasons.append("trust_branch")
    if _field_present("customer id", text):
        total_trust += 1
        decision_reasons.append("trust_customer")
    if not result.has_currency_mismatch and detected_bank:
        total_trust += 1
        decision_reasons.append("trust_currency")
    if result.balance_valid is True:
        total_trust += 3
        decision_reasons.append("trust_balance")
    if transactions and not result.has_transaction_total_mismatch:
        total_trust += 3
        decision_reasons.append("trust_transactions")
    score += min(total_trust, 10)  # Cap total trust bonus at 10

    # ── Extraction Quality ─────────────────────────────────────────────
    declared = _extract_declared_balances(text)
    balance_keys_found = sum(1 for k in ("opening_balance", "closing_balance", "total_credits", "total_debits") if k in declared)
    extraction_quality = min(1.0, (
        0.4 * (parser_confidence if len(transactions) > 0 else 0.0)
        + 0.3 * (balance_keys_found / 4.0)
        + 0.2 * (bank_confidence if detected_bank else 0.0)
        + 0.1 * (1.0 if len(transactions) >= 3 else 0.3 if len(transactions) > 0 else 0.0)
    ))
    result.extraction_quality = round(extraction_quality, 2)

    # ── Transaction Reconstruction ─────────────────────────────────────
    if all(k in declared for k in ("opening_balance", "total_credits", "total_debits", "closing_balance")):
        result.transaction_reconstruction = reconstruct_transaction_flow(
            opening=declared["opening_balance"],
            credits=declared["total_credits"],
            debits=declared["total_debits"],
            observed_closing=declared["closing_balance"],
        )

    # ── Clamp score ──────────────────────────────────────────────────
    result.authenticity_score = max(0.0, min(100.0, score))
    result.document_type = detect_document_type(text)

    # ── Whitelist signals ────────────────────────────────────────────
    whitelist = compute_whitelist_signals(text, detected_bank, meta)
    result.whitelist_signals = whitelist
    total_reduction = sum(s["reduction"] for s in whitelist)
    result.authenticity_score = max(0, result.authenticity_score - total_reduction)

    # ── Incremental risk penalties (replaces hard overrides) ─────────
    adjusted, penalty_reasons = apply_incremental_penalties(result, float(result.authenticity_score))
    if penalty_reasons:
        logger.info("BANKING_PENALTIES_APPLIED",
                    original=result.authenticity_score,
                    adjusted=adjusted,
                    reasons=penalty_reasons)
        result.authenticity_score = max(0.0, adjusted)
        if "Template watermark" in penalty_reasons[0]:
            decision_reasons.append("template_watermark")
        if "Non-INR" in penalty_reasons[0]:
            decision_reasons.append("currency_mismatch")
        if "Balance reconciliation" in penalty_reasons[0]:
            decision_reasons.append("balance_mismatch")
        if "Transaction total" in penalty_reasons[0]:
            decision_reasons.append("transaction_total_mismatch")

    logger.info("BANKING_ANALYSIS_COMPLETE",
                bank=result.bank_name,
                authenticity_score=result.authenticity_score,
                findings_count=len(result.findings),
                balance_valid=result.balance_valid,
                parser_confidence=parser_confidence,
                template_detected=result.has_template_indicators,
                currency_mismatch=result.has_currency_mismatch,
                document_type=result.document_type,
                decision_reasons=decision_reasons)

    return result
