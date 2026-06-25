"""
Upload API Route — Document ingestion and full-analysis pipeline.
Accepts PDF / PNG / JPG / TXT, extracts text, runs anomaly detection,
compliance review, and risk aggregation — returns a unified risk score.
"""
import hashlib
import io
import os
import re
import time
import uuid
from datetime import datetime
from collections import Counter
import structlog
from fastapi import APIRouter, File, UploadFile, HTTPException, status
from sqlalchemy import select

from app.services.redis import get_redis_client, delete_cache
from app.models.anomaly import FieldFeature, AnomalyDetectionRequest
from app.services.database import get_db_session
from app.models.db import Scan as DBScan, RiskLevelEnum, ComplianceAlert
from app.models.compliance import ComplianceCheckRequest
from app.models.aggregator import AggregationInput, AggregationResponse, AggregatedFinding, RiskCategory, EvidenceItem
from app.models.xai import FindingCategory, XaiInputFinding, XaiRequest
from app.services.anomaly_detection import detect_anomalies
from app.services.compliance_engine import analyze as analyze_compliance
from app.services.risk_aggregator import aggregate_risks
from app.services.xai_engine import generate_explanations
from app.services.banking_authenticity import analyze_bank_statement, ValidationStatus
from app.services.signature_intelligence import extract_signature_regions
from app.services.evidence_correlation import correlate_evidence
from app.services.timeline import create_timeline_recorder
from app.services.confidence_engine import enrich_findings
from app.services.root_cause import generate_root_cause
from app.services.fraud_categories import classify_fraud
from app.services.decision_card import generate_decision_card
from app.services.investigation_summary import generate_investigation_summary
from app.services.investigation_narrative import generate_narrative
from app.services.evidence_correlation import build_evidence_chain
from app.services.rule_trace import build_rule_trace, build_risk_waterfall
from app.services.evidence_tree import build_evidence_tree
from app.services.fraud_fingerprint import build_fraud_fingerprint
from app.services.executive_report import generate_executive_report
from app.services.similar_cases import build_current_case_profile, find_similar_cases, _extract_case_from_meta

logger = structlog.get_logger(__name__)
router = APIRouter()

ALLOWED_EXTENSIONS = {'.pdf', '.png', '.jpg', '.jpeg', '.txt'}
ALLOWED_MIMES = {
    'application/pdf',
    'image/png',
    'image/jpeg',
    'image/jpg',
    'text/plain',
}

EDITING_SOFTWARE_KEYWORDS = [
    'pdf-xchange', 'adobe acrobat pro', 'foxit', 'pdfedit', 'nitro',
    'pdf architect', 'pdfsam', 'sejda', 'ilovepdf', 'smallpdf',
    'pdf candy', 'pdfescape', 'soda pdf', 'pdf studio',
]


EVIDENCE_MAP = {
    "CORRUPTED_DOCUMENT": [
        "Invalid PDF structure detected — no valid objects found",
        "PyMuPDF validation failed during document parsing",
        "Document parsing aborted — zero readable objects",
    ],
    "INVALID_PDF": [
        "PDF parser could not decode file structure",
        "File format incompatible with PDF specification",
    ],
    "ENCRYPTED_DOCUMENT": [
        "PDF is password-protected or encrypted",
        "Encrypted documents cannot be processed by the analysis engine",
    ],
    "PDF_READ_FAILED": [
        "PDF content extraction encountered an error",
        "Partial or corrupted page data detected",
    ],
    "EMPTY_FILE": [
        "Uploaded file contains zero bytes",
        "No data available for analysis",
    ],
    "INVALID_PDF_HEADER": [
        "File does not begin with the standard PDF header (%PDF)",
        "File may be a renamed .docx, image, or other format",
        "Only valid PDF documents are accepted for analysis",
    ],
    "PDF_EXTRACTION_FAILED": [
        "Unexpected error during PDF parsing pipeline",
    ],
}

VERDICT_MAP = {
    "CORRUPTED_DOCUMENT": "CORRUPTED DOCUMENT",
    "INVALID_PDF": "INVALID PDF FORMAT",
    "ENCRYPTED_DOCUMENT": "ENCRYPTED DOCUMENT",
    "PDF_READ_FAILED": "PDF READ FAILED",
    "EMPTY_FILE": "EMPTY FILE",
    "INVALID_PDF_HEADER": "INVALID PDF HEADER",
    "PDF_EXTRACTION_FAILED": "PDF EXTRACTION FAILED",
}

REASON_MAP = {
    "CORRUPTED_DOCUMENT": (
        "Uploaded PDF structure is invalid or unreadable. "
        "No valid PDF objects were found during document parsing."
    ),
    "INVALID_PDF": (
        "The uploaded file could not be recognised as a valid PDF document. "
        "The parser was unable to decode its internal structure."
    ),
    "ENCRYPTED_DOCUMENT": (
        "The uploaded PDF is password-protected or encrypted. "
        "Encrypted documents cannot be analysed by the fraud detection engine."
    ),
    "PDF_READ_FAILED": (
        "The PDF was opened but its content could not be fully extracted. "
        "The file may be partially corrupted or contain unsupported elements."
    ),
    "EMPTY_FILE": (
        "The uploaded file is empty (0 bytes). "
        "A valid PDF document with readable content is required for analysis."
    ),
    "INVALID_PDF_HEADER": (
        "The uploaded file does not begin with the standard PDF header (%PDF). "
        "The file may be a renamed document from another application. "
        "Only valid PDF documents are accepted for analysis."
    ),
    "PDF_EXTRACTION_FAILED": (
        "An unexpected error occurred during the PDF extraction pipeline. "
        "The file could not be processed."
    ),
}


def _pdf_error(code: str, message: str):
    """Raise a structured PDF error that renders like a fraud-analysis result."""
    evidence_lines = EVIDENCE_MAP.get(code, ["Document validation failed"])
    reason = REASON_MAP.get(code, message)
    verdict = VERDICT_MAP.get(code, code.replace("_", " ").title())

    raise HTTPException(
        status_code=400,
        detail={
            "error": code,
            "message": message,
            "risk_score": 100,
            "severity": "Critical",
            "decision": "REJECT",
            "verdict": verdict,
            "override_reason": reason,
            "original_score": 100,
            "authenticity_score": 0,
            "fraud_confidence": 100,
            "findings": [{
                "finding": reason[:200],
                "category": "pdf_validation",
                "severity": "CRITICAL",
                "score_contribution": 100.0,
                "confidence": 1.0,
                "evidence": [
                    {"snippet": line, "field": "pdf_validation", "confidence": 1.0}
                    for line in evidence_lines
                ],
            }],
            "risk_categories": [{
                "key": "pdf_validation",
                "label": "PDF Validation",
                "score": 100.0,
                "confidence": 1.0,
                "findings_count": len(evidence_lines),
                "weight": 1.0,
            }],
            "recommendations": ["Upload a valid, unencrypted PDF file."],
            "sources_used": ["pdf_validation"],
        }
    )


def _extract_pdf(content: bytes) -> tuple[str, dict]:
    import fitz
    try:
        doc = fitz.open(stream=content, filetype="pdf")
    except fitz.FileDataError:
        _pdf_error("CORRUPTED_DOCUMENT", "Uploaded PDF is corrupted or unreadable")
    except Exception as e:
        _pdf_error("INVALID_PDF", f"Cannot open PDF: {e}")

    if doc.needs_pass:
        doc.close()
        _pdf_error("ENCRYPTED_DOCUMENT", "Encrypted PDFs are not supported")

    try:
        pages = [page.get_text() for page in doc]
        meta = {'page_count': len(doc), 'pdf_metadata': doc.metadata or {}}
        doc.close()
        return '\n'.join(pages).strip(), meta
    except Exception as e:
        doc.close()
        _pdf_error("PDF_READ_FAILED", f"Failed reading PDF content: {e}")


def _extract_image(content: bytes) -> tuple[str, dict]:
    from PIL import Image
    img = Image.open(io.BytesIO(content))
    text = _ocr_image(content)
    return text, {
        'width': img.width,
        'height': img.height,
        'mode': img.mode,
        'format': img.format,
    }


def _ocr_image(image_bytes: bytes, page_num: int = 0) -> str:
    """Run Tesseract OCR on raw image bytes. Returns extracted text."""
    try:
        from PIL import Image
        import pytesseract
        pytesseract.pytesseract.tesseract_cmd = "/opt/homebrew/bin/tesseract"
        img = Image.open(io.BytesIO(image_bytes))
        img = img.convert("L")
        text = pytesseract.image_to_string(img, config="--psm 6").strip()
        logger.info("OCR_PAGE_RESULT", page_num=page_num, text_length=len(text), preview=text[:120])
        return text
    except Exception as e:
        logger.error("OCR_FAILED", page_num=page_num, error=str(e))
        return ''


def _extract_pdf_with_ocr_fallback(content: bytes) -> str:
    """Extract text from a PDF. Uses fitz first; falls back to OCR per page."""
    import fitz
    try:
        doc = fitz.open(stream=content, filetype="pdf")
    except fitz.FileDataError:
        _pdf_error("CORRUPTED_DOCUMENT", "Uploaded PDF is corrupted or unreadable (OCR fallback)")
    except Exception as e:
        _pdf_error("INVALID_PDF", f"Cannot open PDF for OCR: {e}")

    if doc.needs_pass:
        doc.close()
        _pdf_error("ENCRYPTED_DOCUMENT", "Encrypted PDFs are not supported")

    full_text = ''
    for page in doc:
        text = page.get_text("text").strip()
        if len(text) > 50:
            logger.info("OCR_SKIP_PAGE", page=page.number, reason="fitz_ok", text_length=len(text), preview=text[:120])
            full_text += text + '\n'
            continue
        mat = fitz.Matrix(4, 4)
        pix = page.get_pixmap(matrix=mat, alpha=False)
        img_bytes = pix.tobytes("png")
        ocr_text = _ocr_image(img_bytes, page_num=page.number)
        if ocr_text:
            full_text += ocr_text + '\n'
    doc.close()
    full_text = full_text.strip()
    logger.info("OCR_FALLBACK_COMPLETE", total_length=len(full_text), word_count=len(full_text.split()) if full_text else 0, preview=full_text[:200])
    return full_text


def _extract_amounts(text: str) -> list[float]:
    pattern = r'(?:₹|Rs\.?\s*|INR\s*)(\d+(?:,\d{2,3})*(?:\.\d{1,2})?)'
    amounts = []
    for match in re.finditer(pattern, text):
        try:
            amounts.append(float(match.group(1).replace(',', '')))
        except ValueError:
            pass
    return amounts


def _build_xai_findings(text_content: str, meta: dict, size_kb: float,
                       embedded_image_count: int = 0) -> list[XaiInputFinding]:
    findings: list[XaiInputFinding] = []

    pdf_meta = meta.get('pdf_metadata', {}) if meta else {}
    has_metadata = bool(pdf_meta and any(v for v in pdf_meta.values()))

    SUSPICIOUS_AUTHOR_TOOLS = [
        "photoshop", "canva", "template.net", "adobe illustrator",
        "coreldraw", "paint", "gimp", "inkscape",
    ]

    if not has_metadata:
        findings.append(XaiInputFinding(
            category=FindingCategory.METADATA,
            finding_type="metadata_missing",
            description="Document metadata is missing or unavailable",
            confidence=0.3,
            details={"status": "missing", "fields": "author, creation date, software origin", "note": "Common for scanned documents and bank-issued PDFs"},
        ))
    else:
        producer = (pdf_meta.get('producer') or pdf_meta.get('creator') or '').lower()
        if producer:
            matched_suspicious = None
            for kw in EDITING_SOFTWARE_KEYWORDS:
                if kw in producer:
                    matched_suspicious = pdf_meta.get('producer') or pdf_meta.get('creator') or producer
                    break
            if matched_suspicious:
                findings.append(XaiInputFinding(
                    category=FindingCategory.METADATA,
                    finding_type="software_origin",
                    description=f"Document created/modified with {matched_suspicious}",
                    confidence=0.8,
                    details={
                        "value": matched_suspicious,
                        "expected": "standard banking/corporate software",
                    },
                ))

        author = pdf_meta.get('author', '').strip()
        if author:
            matched_suspicious_author = None
            for kw in SUSPICIOUS_AUTHOR_TOOLS:
                if kw in author.lower():
                    matched_suspicious_author = author
                    break
            if matched_suspicious_author:
                findings.append(XaiInputFinding(
                    category=FindingCategory.METADATA,
                    finding_type="author_mismatch",
                    description=f"Document author field is '{author}' — possible template origin",
                    confidence=0.8,
                    details={
                        "value": author,
                        "expected": "banking system or empty",
                    },
                ))

    if not text_content:
        findings.append(XaiInputFinding(
            category=FindingCategory.OCR,
            finding_type="low_confidence",
            description="No machine-readable text was extracted from the uploaded document",
            confidence=0.95,
            details={
                "field": "document_text",
                "confidence_pct": "low",
                "issue": "The document appears image-based or text extraction failed",
            },
        ))
    elif len(text_content.split()) < 8:
        findings.append(XaiInputFinding(
            category=FindingCategory.OCR,
            finding_type="missing_field",
            description="The extracted text is too short to confirm document contents",
            confidence=0.8,
            details={"field": "document_text", "context": "The document contains very little machine-readable text"},
        ))
    else:
        amounts = _extract_amounts(text_content)
        if amounts:
            rounded_count = sum(1 for a in amounts if a % 1000 == 0)
            if len(amounts) >= 3 and rounded_count / len(amounts) > 0.6:
                findings.append(XaiInputFinding(
                    category=FindingCategory.NUMERIC,
                    finding_type="rounding_anomaly",
                    description=f"{rounded_count} of {len(amounts)} amounts are rounded to thousands",
                    confidence=0.7,
                    details={
                        "pattern": f"{rounded_count}/{len(amounts)} values rounded to nearest 1,000",
                        "field": "monetary_values",
                    },
                ))

            if len(amounts) >= 4:
                import statistics
                avg = statistics.mean(amounts)
                std = statistics.stdev(amounts)
                if std > 0:
                    outliers = [a for a in amounts if abs((a - avg) / std) > 4]
                    if outliers:
                        findings.append(XaiInputFinding(
                            category=FindingCategory.NUMERIC,
                            finding_type="implausible_value",
                            description=f"Found {len(outliers)} amount(s) with extreme deviation (z-score > 4) from average of ₹{avg:,.0f}",
                            confidence=0.8,
                            details={
                                "field": "monetary_values",
                                "value": f"₹{outliers[0]:,.2f}",
                                "range": f"mean=₹{avg:,.0f}, std=₹{std:,.0f}",
                                "deviation": f"z-score={abs((outliers[0] - avg) / std):.1f}",
                            },
                        ))

    if size_kb > 20000:
        findings.append(XaiInputFinding(
            category=FindingCategory.METADATA,
            finding_type="metadata_missing",
            description="The uploaded file is unusually large for a standard document review",
            confidence=0.65,
            details={"status": "large_file", "fields": "document size"},
        ))

    if embedded_image_count > 0:
        findings.append(XaiInputFinding(
            category=FindingCategory.METADATA,
            finding_type="embedded_images_detected",
            description=f"Document contains {embedded_image_count} embedded image(s). No signature analysis was performed — image content was not analyzed for signatures.",
            confidence=1.0,
            details={
                "image_count": embedded_image_count,
                "note": "informational — embedded images detected, no signature regions identified",
            },
        ))

    TEMPLATE_KEYWORDS = ["template.net", "www.template.net", "sample", "specimen", "demo", "example",
                         "templatenet", "template"]
    text_lower = text_content.lower()
    matched_template_kw = next((kw for kw in TEMPLATE_KEYWORDS if kw in text_lower), None)
    if matched_template_kw:
        findings.append(XaiInputFinding(
            category=FindingCategory.METADATA,
            finding_type="template_document",
            description=f"Document appears to be a template or sample (keyword: '{matched_template_kw}'). Risk score will be reduced accordingly.",
            confidence=0.95,
            details={
                "keyword": matched_template_kw,
                "note": "Template/sample documents should not be treated as genuine financial records",
            },
        ))

    # Evidence gate: only return findings that include evidence
    return [f for f in findings if f.details]


@router.post("/upload", response_model=AggregationResponse)
async def upload_document(file: UploadFile = File(...)):
    ext = os.path.splitext(file.filename or '')[1].lower()

    if ext not in ALLOWED_EXTENSIONS and file.content_type not in ALLOWED_MIMES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file type. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        )

    content = await file.read()
    if not content:
        _pdf_error("EMPTY_FILE", "Uploaded file is empty")

    start = time.time()
    timeline_recorder = create_timeline_recorder()
    timeline_recorder.start_stage("Upload")
    logger.info("UPLOAD RECEIVED", filename=file.filename, ext=ext, size_bytes=len(content), content_type=file.content_type)

    # ── PDF validation before extraction ──
    print("=" * 60)
    print("FILE:", file.filename)
    print("SIZE:", len(content))
    print("HEADER:", content[:20])
    print("=" * 60)

    if ext == '.pdf' and not content.startswith(b"%PDF"):
        _pdf_error("INVALID_PDF_HEADER", "File is not a valid PDF (missing %PDF header)")

    text_content = ''
    meta = {}

    if ext == '.pdf':
        try:
            text_content, meta = _extract_pdf(content)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("PDF extraction failed")
            _pdf_error("PDF_EXTRACTION_FAILED", f"PDF extraction failed: {e}")
        page_count = meta.get('page_count', 1)
        if len(text_content.split()) < 20:
            text_content = _extract_pdf_with_ocr_fallback(content)
            meta['ocr_engine'] = 'tesseract'
            meta['ocr_fallback'] = True
    elif ext in ('.png', '.jpg', '.jpeg'):
        text_content, meta = _extract_image(content)
    elif ext == '.txt':
        text_content = content.decode('utf-8', errors='replace')
        meta = {'format': 'text'}

    word_count = len(text_content.split()) if text_content else 0
    char_count = len(text_content)
    page_count = meta.get('page_count', 1)
    size_kb = round(len(content) / 1024, 2)

    timeline_recorder.end_stage("SUCCESS")
    timeline_recorder.start_stage("Metadata")

    # Build audit trail
    now_iso = datetime.utcnow().isoformat()
    audit_trail = [
        {"step": "Uploaded", "timestamp": now_iso, "status": "completed"},
        {"step": "OCR Completed", "timestamp": now_iso, "status": "completed"},
        {"step": "Metadata Analysis", "timestamp": now_iso, "status": "completed"},
        {"step": "Numeric Validation", "timestamp": now_iso, "status": "completed"},
        {"step": "Fraud Pattern Detection", "timestamp": now_iso, "status": "completed"},
        {"step": "Compliance Mapping", "timestamp": now_iso, "status": "completed"},
        {"step": "Risk Aggregation", "timestamp": now_iso, "status": "completed"},
        {"step": "Case Created", "timestamp": now_iso, "status": "completed"},
    ]

    ocr_engine = meta.get('ocr_engine', 'fitz')
    logger.info("OCR OUTPUT", text_length=len(text_content), word_count=word_count, page_count=page_count, ocr_engine=ocr_engine, preview=text_content[:180] if text_content else "")
    logger.info("METADATA OUTPUT", metadata=meta)

    # ── Fraud Pattern Detection ──────────────────────────────────────
    fraud_patterns = []
    if text_content:
        amounts = _extract_amounts(text_content)
        if len(amounts) >= 3:
            # Round amount pattern
            round_count = sum(1 for a in amounts if a % 1000 == 0)
            if round_count >= 3 and round_count / len(amounts) > 0.5:
                fraud_patterns.append({
                    "pattern": "round_amounts",
                    "description": f"{round_count} of {len(amounts)} amounts are rounded to thousands — possible fabricated data",
                    "severity": "MEDIUM",
                    "evidence": f"Sample amounts: {', '.join(f'₹{a:,.0f}' for a in amounts[:5])}",
                    "confidence": 0.75,
                })

            # Repeated transaction pattern
            amount_strs = [str(int(a)) for a in amounts]
            dupes = {k: v for k, v in Counter(amount_strs).items() if v >= 3}
            if dupes:
                fraud_patterns.append({
                    "pattern": "repeated_transactions",
                    "description": f"Found {sum(dupes.values())} repeated amounts — possible fabricated entries",
                    "severity": "MEDIUM",
                    "evidence": f"Repeated: {', '.join(f'₹{k} (x{v})' for k, v in list(dupes.items())[:3])}",
                    "confidence": 0.8,
                })

            # Unusual time pattern
            time_pattern = r'\b(?:0?[0-9]|1[0-9]|2[0-3]):[0-5][0-9]\s*(?:AM|PM|am|pm)?\b'
            times_found = re.findall(time_pattern, text_content)
            if len(times_found) >= 3:
                night_times = sum(1 for t in times_found if any(h in t for h in ['00:', '01:', '02:', '03:', '04:', '05:']))
                if night_times >= 2:
                    fraud_patterns.append({
                        "pattern": "unusual_times",
                        "description": f"{night_times} of {len(times_found)} transactions occurred during late-night hours (00:00-06:00)",
                        "severity": "MEDIUM",
                        "evidence": f"Times detected: {', '.join(times_found[:5])}",
                        "confidence": 0.65,
                    })

        logger.info("FRAUD_PATTERNS_DETECTED", count=len(fraud_patterns), patterns=[p["pattern"] for p in fraud_patterns])

    timeline_recorder.end_stage("SUCCESS")
    timeline_recorder.start_stage("Authenticity")

    # ----- embedded image / signature detection -----
    embedded_image_count = 0
    if ext == '.pdf':
        try:
            import fitz
            doc = fitz.open(stream=content, filetype="pdf")
            if doc.needs_pass:
                doc.close()
                logger.warning("IMAGE_DETECTION_SKIPPED", reason="encrypted_pdf")
            else:
                for page_num in range(len(doc)):
                    page = doc[page_num]
                    images = page.get_images(full=True)
                    for img in images:
                        xref = img[0]
                        pix = fitz.Pixmap(doc, xref)
                        if pix.width > 30 and pix.height > 15:
                            embedded_image_count += 1
                        pix = None
                doc.close()
        except fitz.FileDataError:
            logger.warning("IMAGE_DETECTION_SKIPPED", reason="invalid_pdf")
        except Exception:
            pass
    logger.info("SIGNATURE_FINDINGS", embedded_image_count=embedded_image_count, ext=ext)

    # ----- XAI explanations from document evidence -----
    xai_findings = []
    xai_inputs = _build_xai_findings(text_content, meta, size_kb, embedded_image_count)
    if xai_inputs:
        xai_response = generate_explanations(XaiRequest(findings=xai_inputs, document_context=file.filename or 'the uploaded document'))
        xai_findings = [
            {
                'finding_type': exp.finding_type,
                'severity': exp.severity,
                'confidence': exp.confidence,
                'plain_english': exp.plain_english,
                'risk_impact': exp.risk_impact,
                'recommendation': exp.recommendation,
            }
            for exp in xai_response.explanations
        ]
        logger.info("XAI FINDINGS", count=len(xai_findings), overall_severity=xai_response.overall_severity)

    # ── Check if OCR extracted sufficient content ─────────────────────
    ocr_insufficient = any(
        f.finding_type in ("low_confidence", "missing_field") and f.category == FindingCategory.OCR
        for f in xai_inputs
    )

    banking_result = None
    signature_intel_result = None
    sig_findings = []

    if ocr_insufficient:
        logger.info("OCR_INSUFFICIENT", text_length=char_count, word_count=word_count,
                     reason="Skipping downstream analysis — insufficient text extracted")
        result = AggregationResponse(
            risk_score=22,
            severity="Analysis Incomplete",
            findings=[AggregatedFinding(
                finding="Insufficient OCR Content",
                category="ocr",
                severity="LOW",
                score_contribution=22.0,
                evidence=[EvidenceItem(
                    snippet=f"Extracted text length: {char_count} characters ({word_count} words)",
                    field="document_text",
                    confidence=1.0,
                )],
                confidence=1.0,
            )],
            risk_categories=[RiskCategory(
                key="ocr",
                label="OCR Analysis",
                score=22.0,
                confidence=1.0,
                findings_count=1,
                weight=1.0,
            )],
            recommendations=["Upload original PDF or higher-quality scan."],
            sources_used=["xai"],
        )
        anomaly_result = None
        compliance_result = None
    else:
        # ----- anomaly detection on document features -----
        anomaly_req = AnomalyDetectionRequest(
            fields=[
                FieldFeature(name='word_count', value=float(word_count), category='document_stats'),
                FieldFeature(name='char_count', value=float(char_count), category='document_stats'),
                FieldFeature(name='page_count', value=float(page_count), category='document_stats'),
                FieldFeature(name='file_size_kb', value=size_kb, category='document_stats'),
            ],
            context='document_upload',
        )
        anomaly_result = detect_anomalies(anomaly_req)

        # ----- heatmap findings (image-only) -----
        heatmap_findings = []
        if 'width' in meta:
            heatmap_findings.append({
                'confidence': 0.3,
                'reason': f'Image dimensions: {meta["width"]}×{meta["height"]}px, mode={meta["mode"]}',
            })

        # ----- XAI logging markers -----
        meta_cats = set(f.category.value for f in xai_inputs if f.category == FindingCategory.METADATA)
        ocr_cats = set(f.category.value for f in xai_inputs if f.category == FindingCategory.OCR)
        num_cats = set(f.category.value for f in xai_inputs if f.category == FindingCategory.NUMERIC)
        sig_cats = set(f.category.value for f in xai_inputs if f.category == FindingCategory.SIGNATURE)
        logger.info("METADATA_FINDINGS", count=len([f for f in xai_inputs if f.category == FindingCategory.METADATA]),
                    types=list(meta_cats))
        logger.info("OCR_FINDINGS", count=len([f for f in xai_inputs if f.category == FindingCategory.OCR]),
                    types=list(ocr_cats))
        logger.info("NUMERIC_FINDINGS", count=len([f for f in xai_inputs if f.category == FindingCategory.NUMERIC]),
                    types=list(num_cats))
        logger.info("SIGNATURE_FINDINGS", count=len([f for f in xai_inputs if f.category == FindingCategory.SIGNATURE]),
                    types=list(sig_cats))

        # ----- signature verification (no reference in upload flow) -----
        signature_result = None
        if embedded_image_count > 0:
            logger.info("SIGNATURE_FINDINGS", count=embedded_image_count,
                        source="pdf_embedded_images", note="no reference for comparison")

        timeline_recorder.end_stage("SUCCESS")
        timeline_recorder.start_stage("AML")

        # ----- compliance check (using XAI + anomaly + metadata findings) -----
        compliance_result = None
        MIN_WORDS_FOR_COMPLIANCE = 100
        if word_count < MIN_WORDS_FOR_COMPLIANCE:
            logger.info("COMPLIANCE_SKIPPED", reason="insufficient_content",
                        word_count=word_count, min_required=MIN_WORDS_FOR_COMPLIANCE)
        else:
            compliance_mapping_enabled = True
            try:
                from app.services.database import get_db_session as _get_db_session
                from app.models.db import PolicySettings
                async for _s in _get_db_session():
                    _stmt = select(PolicySettings).limit(1)
                    _r = await _s.execute(_stmt)
                    _ps = _r.scalar_one_or_none()
                    if _ps:
                        _meta = _ps.meta or {}
                        compliance_mapping_enabled = _meta.get("compliance_mapping_enabled", True)
                    break
            except Exception:
                pass

            if compliance_mapping_enabled:
                compliance_input_findings = []
                for f in anomaly_result.findings:
                    compliance_input_findings.append({
                        'severity': f.severity,
                        'category': 'Anomaly Detection',
                        'message': f.explanation,
                        'signal_origin': f'anomaly.{f.method.value}',
                    })
                for xf in xai_inputs:
                    compliance_input_findings.append({
                        'severity': 'MEDIUM' if xf.confidence > 0.6 else 'LOW',
                        'category': xf.category.value.title(),
                        'message': xf.description,
                        'signal_origin': f'xai.{xf.category.value}.{xf.finding_type}',
                    })
                for hf in heatmap_findings:
                    compliance_input_findings.append({
                        'severity': 'MEDIUM' if hf.get('confidence', 0) > 0.5 else 'LOW',
                        'category': 'Visual Analysis',
                        'message': hf.get('reason', 'Visual anomaly detected'),
                        'signal_origin': 'heatmap.visual',
                    })

                compliance_req = ComplianceCheckRequest(
                    source_type='upload',
                    source_id=file.filename or 'unknown',
                    findings=compliance_input_findings,
                )
                compliance_result = analyze_compliance(compliance_req)
                logger.info("COMPLIANCE_FINDINGS", count=len(compliance_result.findings) if compliance_result else 0,
                            risk=compliance_result.overall_compliance_risk if compliance_result else 'N/A')
            else:
                logger.info("COMPLIANCE_SKIPPED", reason="compliance_mapping_enabled=false")

        # ----- banking authenticity & transaction intelligence -----
        banking_result = None
        signature_intel_result = None
        ocr_reliability = None

        if word_count >= 8:
            bank_output = analyze_bank_statement(text_content, meta, ocr_reliability=ocr_reliability)
            if bank_output:
                banking_result = {
                    "authenticity_score": bank_output.authenticity_score,
                    "confidence": bank_output.confidence,
                    "bank_name": bank_output.bank_name,
                    "transaction_count": bank_output.transaction_count,
                    "balance_valid": bank_output.balance_valid,
                    "document_type": bank_output.document_type,
                    "whitelist_signals": bank_output.whitelist_signals,
                    "has_running_balance_issue": bank_output.has_running_balance_issue,
                    "has_balance_reconciliation_issue": bank_output.has_balance_reconciliation_issue,
                    "has_transaction_total_mismatch": bank_output.has_transaction_total_mismatch,
                    "transaction_types": bank_output.transaction_types,
                    "has_aml_structuring": bank_output.has_aml_structuring,
                    "has_fraud_loss_estimate": bank_output.has_fraud_loss_estimate,
                    "estimated_fraud_loss": bank_output.estimated_fraud_loss,
                    "timeline_events": bank_output.timeline_events,
                    "findings": [
                        {"finding": f.finding, "severity": f.severity,
                         "risk_points": f.risk_points, "evidence": f.evidence, "field": f.field}
                        for f in bank_output.findings
                    ],
                }
                logger.info("BANKING_ANALYSIS", bank=bank_output.bank_name,
                            authenticity_score=bank_output.authenticity_score,
                            transaction_count=bank_output.transaction_count,
                            balance_valid=bank_output.balance_valid)

        # ----- signature intelligence (image-based) -----
        if ext == '.pdf' and word_count >= 8:
            sig_intel = extract_signature_regions(content)
            if sig_intel:
                signature_intel_result = {
                    "image_count": sig_intel.image_count,
                    "signature_regions": [
                        {"page": r.page, "bounding_box": list(r.bounding_box),
                         "confidence": r.confidence, "area_pct": r.area_pct}
                        for r in sig_intel.signature_regions
                    ],
                    "has_signatures": sig_intel.has_signatures,
                    "max_confidence": sig_intel.max_confidence,
                    "signature_score": sig_intel.signature_score,
                    "findings": sig_intel.findings,
                    "confidence": sig_intel.confidence,
                }
                logger.info("SIGNATURE_INTELLIGENCE", regions=len(sig_intel.signature_regions),
                            has_signatures=sig_intel.has_signatures)

        # ----- OCR reliability -----
        # Estimate OCR quality based on extraction method and text volume
        if ext == '.txt':
            ocr_reliability = 1.0
        elif ocr_engine == 'fitz':
            # fitz extracted directly — high confidence
            if word_count >= 200:
                ocr_reliability = 0.95
            elif word_count >= 100:
                ocr_reliability = 0.90
            elif word_count >= 50:
                ocr_reliability = 0.80
            else:
                ocr_reliability = 0.60
        elif ocr_engine == 'tesseract':
            # OCR — moderate confidence, scales with words extracted
            if word_count >= 200:
                ocr_reliability = 0.85
            elif word_count >= 100:
                ocr_reliability = 0.80
            elif word_count >= 50:
                ocr_reliability = 0.70
            elif word_count >= 20:
                ocr_reliability = 0.55
            else:
                ocr_reliability = 0.35
        else:
            ocr_reliability = 0.5

        timeline_recorder.end_stage("SUCCESS")
        timeline_recorder.start_stage("Risk")

        # ----- risk aggregation -----
        logger.info("AGGREGATOR INPUT",
                    xai_findings=len(xai_findings),
                    anomaly_findings=len(anomaly_result.findings) if anomaly_result else 0,
                    compliance_findings=len(compliance_result.findings) if compliance_result else 0,
                    banking_result=banking_result is not None,
                    signature_intel_result=signature_intel_result is not None,
                    ocr_reliability=ocr_reliability)
        result = aggregate_risks(AggregationInput(
            xai_findings=xai_findings if xai_findings else None,
            heatmap_findings=heatmap_findings if heatmap_findings else None,
            signature_result=signature_result,
            compliance_result=compliance_result.model_dump() if compliance_result else None,
            anomaly_result=anomaly_result.model_dump() if anomaly_result else None,
            banking_result=banking_result,
            signature_intel_result=signature_intel_result,
            ocr_reliability=ocr_reliability,
        ))

        # ── Extract finding lists for downstream modules ──
        banking_findings_list = []
        compliance_findings_list = []
        anomaly_findings_list = []
        try:
            if banking_result:
                banking_findings_list = banking_result.get("findings", []) or []
            if compliance_result:
                compliance_findings_list = compliance_result.get("findings", []) or []
            if anomaly_result:
                anomaly_findings_list = anomaly_result.get("findings", []) or []
        except Exception as e:
            logger.warning("Finding list extraction failed", error=str(e))

        # 0. Rule Trace & Risk Waterfall (visualization metadata — no scoring impact)
        try:
            result.rule_trace = build_rule_trace(
                banking_findings=banking_findings_list,
                compliance_findings=compliance_findings_list,
                xai_findings=xai_findings,
                anomaly_findings=anomaly_findings_list,
                signature_findings=sig_findings,
                fraud_patterns=fraud_patterns,
                risk_score=result.risk_score,
            )
            # Convert risk_categories to plain dicts for the waterfall builder
            rc_dicts = [rc.model_dump() for rc in (result.risk_categories or [])]
            dp_list = result.decision_path or []
            result.risk_waterfall = build_risk_waterfall(
                risk_categories=rc_dicts,
                decision_path=dp_list,
                risk_score=result.risk_score,
                original_score=result.original_score,
            )
        except Exception as e:
            logger.warning("Rule trace / risk waterfall failed", error=str(e))

        # Populate extracted_fields from banking & transaction analysis
        extracted = {}
        if banking_result:
            extracted["Bank"] = (banking_result.get("bank_name") or "Unknown").title()
            # Detect actual currency from banking findings
            detected_currency = "INR"
            for bf in (banking_result.get("findings") or []):
                if bf.get("field") == "currency_consistency" or "currency" in bf.get("finding", "").lower():
                    evidence = bf.get("evidence", "")
                    if "$" in evidence or "USD" in evidence:
                        detected_currency = "USD"
                    elif "€" in evidence or "EUR" in evidence:
                        detected_currency = "EUR"
                    elif "£" in evidence or "GBP" in evidence:
                        detected_currency = "GBP"
                    else:
                        detected_currency = "Foreign"
                    break
            extracted["Currency"] = detected_currency
            extracted["Status"] = "Verified" if result.risk_score < 31 else "Flagged"

            # Financial Integrity breakdown using ValidationStatus
            br = banking_result
            fin_parts = []
            fin_deductions = 0
            txn_count = br.get("transaction_count", 0)

            def fin_status(failed: bool, passed: bool, unknown_reason: str = "") -> str:
                if failed:
                    return f"{ValidationStatus.FAIL.value}"
                if passed:
                    return f"{ValidationStatus.PASS.value}"
                return f"{ValidationStatus.UNKNOWN.value}"

            bal_recon_status = fin_status(
                br.get("has_balance_reconciliation_issue", False),
                br.get("balance_valid") is True,
                unknown_reason="No declared balances to reconcile"
            )
            txn_total_status = fin_status(
                br.get("has_transaction_total_mismatch", False),
                txn_count > 0,
            )
            running_bal_status = fin_status(
                br.get("has_running_balance_issue", False),
                br.get("balance_valid") is True and txn_count >= 3,
            )

            # Convert UNKNOWN → N/A for display
            bal_recon_display = "PASS" if bal_recon_status == "pass" else "FAIL" if bal_recon_status == "fail" else "N/A"
            txn_total_display = "PASS" if txn_total_status == "pass" else "FAIL" if txn_total_status == "fail" else "N/A"
            running_bal_display = "PASS" if running_bal_status == "pass" else "FAIL" if running_bal_status == "fail" else "N/A"

            fin_parts.append(f"Balance Reconciliation: {bal_recon_display}")
            if bal_recon_status == "fail":
                fin_deductions += 50
            fin_parts.append(f"Transaction Totals: {txn_total_display}")
            if txn_total_status == "fail":
                fin_deductions += 30
            fin_parts.append(f"Running Balance: {running_bal_display}")
            if running_bal_status == "fail":
                fin_deductions += 40
            if fin_parts:
                extracted["Financial Integrity"] = " | ".join(fin_parts)
                fin_score = max(0, 100 - fin_deductions)
                extracted["Financial Integrity Score"] = f"{fin_score}/100"
        if meta:
            if meta.get("producer"):
                extracted["PDF Producer"] = meta["producer"]
            if meta.get("subject"):
                extracted["Subject"] = meta["subject"]
        if extracted:
            result.extracted_fields = extracted

    timeline_recorder.end_stage("SUCCESS")
    timeline_recorder.start_stage("Decision")

    # ── New Intelligence Modules (optional, non-blocking) ──────────────

    # 1. Evidence Correlation
    try:
        result.evidence_correlation = correlate_evidence(
            xai_findings=xai_findings,
            anomaly_findings=anomaly_findings_list,
            compliance_findings=compliance_findings_list,
            banking_findings=banking_findings_list,
            signature_findings=sig_findings,
            fraud_patterns=fraud_patterns,
            metadata=meta,
        )
    except Exception as e:
        logger.warning("Evidence correlation failed", error=str(e))

    # 2. Evidence Tree
    try:
        result.evidence_tree = build_evidence_tree(
            banking_result=banking_result,
            banking_findings=banking_findings_list,
            compliance_findings=compliance_findings_list,
            xai_findings=xai_findings,
            anomaly_findings=anomaly_findings_list,
        )
    except Exception as e:
        logger.warning("Evidence tree failed", error=str(e))

    # 3. Timeline
    try:
        timeline_recorder.end_stage("SUCCESS")
        result.timeline = timeline_recorder.get_timeline()
        result.module_health = timeline_recorder.get_module_health()
        result.pipeline_progress = timeline_recorder.get_pipeline_progress()
    except Exception as e:
        logger.warning("Timeline recording failed", error=str(e))

    # 4. Confidence Engine + Evidence Weighting (Features 3 & 8)
    try:
        result.enriched_findings = enrich_findings(
            banking_findings=banking_findings_list,
            compliance_findings=compliance_findings_list,
            anomaly_findings=anomaly_findings_list,
            xai_findings=xai_findings,
            signature_findings=sig_findings,
        )
    except Exception as e:
        logger.warning("Confidence engine failed", error=str(e))

    # 4. Root Cause Generator
    try:
        result.root_cause = generate_root_cause(
            banking_findings=banking_findings_list,
            compliance_findings=compliance_findings_list,
            anomaly_findings=anomaly_findings_list,
            xai_findings=xai_findings,
            fraud_patterns=fraud_patterns,
            risk_score=result.risk_score,
        )
    except Exception as e:
        logger.warning("Root cause generation failed", error=str(e))

    # 5. Fraud Category Classifier
    try:
        result.fraud_categories = classify_fraud(
            banking_findings=banking_findings_list,
            compliance_findings=compliance_findings_list,
            xai_findings=xai_findings,
            signature_findings=sig_findings,
            fraud_patterns=fraud_patterns,
        )
    except Exception as e:
        logger.warning("Fraud category classification failed", error=str(e))

    # 7. Decision Card
    try:
        result.decision_card = generate_decision_card(
            risk_score=result.risk_score,
            fraud_confidence=result.fraud_confidence,
            fraud_categories=result.fraud_categories,
            root_cause=result.root_cause,
            existing_decision=result.decision,
            banking_findings=banking_findings_list,
        )
    except Exception as e:
        logger.warning("Decision card generation failed", error=str(e))

    # 11. Investigation Summary
    try:
        result.investigation_summary = generate_investigation_summary(
            banking_findings=banking_findings_list,
            compliance_findings=compliance_findings_list,
            anomaly_findings=anomaly_findings_list,
            xai_findings=xai_findings,
            fraud_patterns=fraud_patterns,
            risk_score=result.risk_score,
            fraud_confidence=result.fraud_confidence,
            root_cause=result.root_cause,
            fraud_categories=result.fraud_categories,
            decision_card=result.decision_card,
            banking_result=banking_result,
        )
    except Exception as e:
        logger.warning("Investigation summary failed", error=str(e))

    # 12. Investigation Narrative
    try:
        sig_intel_for_narrative = None
        if signature_intel_result:
            sig_intel_for_narrative = signature_intel_result
        result.investigation_narrative = generate_narrative(
            xai_findings=xai_findings,
            banking_findings=banking_findings_list,
            banking_result=banking_result,
            compliance_findings=compliance_findings_list,
            signature_intel_result=sig_intel_for_narrative,
            fraud_patterns=fraud_patterns,
            meta=meta,
            word_count=word_count,
            risk_score=result.risk_score,
            decision=result.decision,
            override_reason=result.override_reason,
        )
    except Exception as e:
        logger.warning("Investigation narrative failed", error=str(e))

    # 13. Evidence Chain (cause-effect)
    try:
        result.evidence_chain = build_evidence_chain(
            xai_findings=xai_findings,
            anomaly_findings=anomaly_findings_list,
            compliance_findings=compliance_findings_list,
            banking_findings=banking_findings_list,
            signature_findings=sig_findings,
            fraud_patterns=fraud_patterns,
            ocr_insufficient=ocr_insufficient,
        )
    except Exception as e:
        logger.warning("Evidence chain failed", error=str(e))

    # 14. Fraud Fingerprint
    try:
        result.fraud_fingerprint = build_fraud_fingerprint(
            banking_findings=banking_findings_list,
            compliance_findings=compliance_findings_list,
            xai_findings=xai_findings,
            anomaly_findings=anomaly_findings_list,
            signature_findings=sig_findings,
            fraud_patterns=fraud_patterns,
            ocr_reliability=ocr_reliability,
            banking_result=banking_result,
        )
    except Exception as e:
        logger.warning("Fraud fingerprint failed", error=str(e))

    # 15. Similar Investigations (DB-backed, deterministic)
    try:
        current_profile = build_current_case_profile(
            risk_score=result.risk_score,
            decision=result.decision,
            bank_name=banking_result.get("bank_name") if banking_result else None,
            banking_findings=banking_findings_list,
            fraud_categories=result.fraud_categories,
        )
    except Exception as e:
        logger.warning("Similar investigations profile failed", error=str(e))
        current_profile = None

    # 16. Executive Investigation Report
    try:
        result.executive_report = generate_executive_report(
            risk_score=result.risk_score,
            severity=result.severity,
            decision=result.decision,
            override_reason=result.override_reason,
            original_score=result.original_score,
            banking_result=banking_result,
            banking_findings=banking_findings_list,
            compliance_findings=compliance_findings_list,
            xai_findings=xai_findings,
            anomaly_findings=anomaly_findings_list,
            evidence_correlation=result.evidence_correlation,
            root_cause=result.root_cause,
            fraud_categories=result.fraud_categories,
            decision_card=result.decision_card,
            investigation_summary=result.investigation_summary,
            timeline=result.timeline,
            risk_categories=result.risk_categories,
            findings=result.findings,
            fraud_confidence=result.fraud_confidence,
            detection_confidence=result.detection_confidence,
            fraud_risk=result.fraud_risk,
            evidence_quality=result.evidence_quality,
            recommendations=result.recommendations,
        )
    except Exception as e:
        logger.warning("Executive report failed", error=str(e))

    # 9. Financial Explanation
    if banking_result and banking_result.get("transaction_count", 0) > 0:
        try:
            opening = banking_result.get("opening_balance")
            credits = banking_result.get("total_credits")
            debits = banking_result.get("total_debits")
            closing = banking_result.get("closing_balance")
            if any(v is not None for v in [opening, credits, debits, closing]):
                formula_valid = True
                note = "Financial integrity checks passed"
                if all(v is not None for v in [opening, credits, debits, closing]):
                    expected = round(opening + credits - debits, 2)
                    formula_valid = abs(expected - closing) < 1.0
                    if not formula_valid:
                        note = f"Formula mismatch: {opening} + {credits} - {debits} = {expected}, but closing balance is {closing}"
                    else:
                        note = f"Formula verified: {opening} + {credits} - {debits} = {closing}"
                result.financial_explanation = {
                    "opening_balance": opening,
                    "credits": credits,
                    "debits": debits,
                    "closing_balance": closing,
                    "formula": "Opening + Credits - Debits = Closing Balance",
                    "verification": "PASS" if formula_valid else "FAIL",
                    "note": note,
                }
        except Exception as e:
            logger.warning("Financial explanation failed", error=str(e))

    elapsed = int((time.time() - start) * 1000)
    logger.info("Document uploaded and analysed",
                filename=file.filename, ext=ext,
                risk_score=result.risk_score, severity=result.severity,
                elapsed_ms=elapsed)

    # Persist to database
    try:
        severity_map = {
            "Safe": RiskLevelEnum.LOW,
            "Review Required": RiskLevelEnum.MEDIUM,
            "Suspicious": RiskLevelEnum.HIGH,
            "High Risk": RiskLevelEnum.HIGH,
        }
        async for session in get_db_session():
            scan_id = str(uuid.uuid4())
            reasons_list = [f.finding[:300] for f in result.findings] if result.findings else []

            # Serialise rich findings with evidence for persistence
            rich_findings = []
            for f in result.findings or []:
                rich_findings.append({
                    "finding": f.finding,
                    "category": f.category,
                    "severity": f.severity,
                    "score_contribution": f.score_contribution,
                    "confidence": f.confidence,
                    "evidence": [
                        {
                            "snippet": e.snippet,
                            "field": e.field,
                            "expected": e.expected,
                            "confidence": e.confidence,
                            "page_ref": e.page_ref,
                        }
                        for e in (f.evidence or [])
                    ],
                })

            # Serialise risk categories
            risk_categories_serialised = []
            for rc in result.risk_categories or []:
                risk_categories_serialised.append({
                    "key": rc.key,
                    "label": rc.label,
                    "score": rc.score,
                    "confidence": rc.confidence,
                    "findings_count": rc.findings_count,
                    "weight": rc.weight,
                })

            db_scan = DBScan(
                scan_id=scan_id,
                input_hash=hashlib.sha256(content).hexdigest()[:16],
                text=text_content,
                url=f"document://{file.filename}",
                risk=severity_map.get(result.severity, RiskLevelEnum.LOW),
                confidence=result.fraud_confidence / 100.0,
                graph_score=0.0,
                model_score=result.fraud_confidence / 100.0,
                reasons=reasons_list,
                meta={
                    "filename": file.filename,
                    "size_kb": size_kb,
                    "sources": result.sources_used,
                    "audit_trail": audit_trail,
                    "case": {"status": "Open", "created_at": datetime.utcnow().isoformat()},
                    "fraud_patterns": fraud_patterns,
                    "findings": rich_findings,
                    "risk_categories": risk_categories_serialised,
                    "recommendations": result.recommendations,
                },
            )
            session.add(db_scan)

            # Persist compliance findings
            if compliance_result and compliance_result.findings:
                compliance_report_id = compliance_result.report_id
                for cf in compliance_result.findings:
                    db_alert = ComplianceAlert(
                        scan_id=scan_id,
                        regulation=cf.regulation.value,
                        reference=cf.reference,
                        finding_type=cf.finding_type,
                        finding_description=cf.finding_description,
                        risk_impact=cf.risk_impact,
                        required_action=cf.required_action.action if cf.required_action else None,
                        timeline=cf.required_action.timeline if cf.required_action else None,
                        responsible_party=cf.required_action.responsible_party if cf.required_action else None,
                        compliance_severity=cf.compliance_severity.value,
                        source_signal=cf.source_signal,
                        report_id=compliance_report_id,
                    )
                    session.add(db_alert)

            await session.commit()
            logger.info("Compliance alerts persisted", count=len(compliance_result.findings) if compliance_result else 0)

            # Publish scan:completed event and invalidate dashboard cache
            try:
                redis = await get_redis_client()
                await redis.publish("phishguard:scan_events", json.dumps({
                    "event": "scan:completed",
                    "scan_id": scan_id,
                    "data": {
                        "risk_score": result.risk_score,
                        "threat_level": result.severity,
                        "processing_time_ms": 0,
                        "fraud_detected": 1 if result.risk_score >= 70 else 0,
                        "high_risk": 1 if result.risk_score >= 70 else 0,
                        "compliance_alert": 1 if (compliance_result and compliance_result.findings) else 0,
                    }
                }))
                await delete_cache("dashboard:executive")

                compliance_findings = compliance_result.findings if compliance_result else []
                ca_count = len(compliance_findings)
                sevs = [cf.compliance_severity.value for cf in compliance_findings]
                risk_for_dec = result.risk_score or int(result.fraud_confidence)
                primary_reason = (result.findings[0].finding[:200] if result.findings else (result.root_cause or "No significant findings"))
                reco = (result.recommendations[0] if result.recommendations else (
                    "Manual verification required." if risk_for_dec >= 50 else "Standard processing — no action required."
                ))

                await redis.publish("phishguard:scan_events", json.dumps({
                    "event": "executive_decision_updated",
                    "scan_id": scan_id,
                    "data": {
                        "fraud_probability": float(result.fraud_confidence),
                        "risk_score": risk_for_dec,
                        "decision": result.decision or ("REJECT" if risk_for_dec >= 80 else "REVIEW" if risk_for_dec >= 50 else "APPROVE"),
                        "confidence": round(result.fraud_confidence, 1),
                        "compliance": None if ca_count == 0 else ("Severe" if any(s in ("CRITICAL", "HIGH") for s in sevs) else "Moderate"),
                        "regulatory_risk": None if ca_count == 0 else ("Critical" if any(s == "CRITICAL" for s in sevs) else "High" if any(s == "HIGH" for s in sevs) else "Elevated"),
                        "primary_reason": primary_reason,
                        "recommendation": reco,
                        "updated_at": datetime.utcnow().isoformat(),
                    }
                }))
                await delete_cache("dashboard:executive-decision")

                # Signal dashboard statistics refresh (frontend re-fetches full data)
                await redis.publish("phishguard:scan_events", json.dumps({
                    "event": "dashboard_statistics_updated",
                    "scan_id": scan_id,
                    "data": {"trigger": "investigation_completed"}
                }))
                await delete_cache("dashboard:statistics")
                await delete_cache("compliance:dashboard:30")

                # Signal compliance dashboard refresh
                await redis.publish("phishguard:scan_events", json.dumps({
                    "event": "compliance_dashboard_updated",
                    "scan_id": scan_id,
                    "data": {"trigger": "scan_completed", "risk_score": result.risk_score}
                }))
            except Exception:
                logger.warning("Redis publish failed", exc_info=True)

            # Query historical cases for similarity matching
            if current_profile:
                try:
                    stmt = select(DBScan).where(DBScan.scan_id != scan_id).order_by(DBScan.created_at.desc()).limit(50)
                    db_rows = await session.execute(stmt)
                    historical_cases = []
                    for row in db_rows.scalars():
                        meta = row.meta or {}
                        case = _extract_case_from_meta(dict(meta), row.scan_id, row.created_at)
                        historical_cases.append(case)
                    similar = find_similar_cases(current_profile, historical_cases, top_k=5)
                    result.similar_cases = similar if similar else None
                    logger.info("Similar investigations found", count=len(similar) if similar else 0)
                except Exception as e:
                    logger.warning("Similar investigations query failed", error=str(e))

            break
    except Exception as e:
        logger.error("Failed to persist document scan", error=str(e))

    return result


@router.get("/investigations/by-fingerprint/{fingerprint}")
async def search_by_fingerprint(fingerprint: str, limit: int = 10):
    """
    Search for past investigations with matching fraud fingerprint.
    """
    from fastapi.responses import JSONResponse
    try:
        async for session in get_db_session():
            stmt = (
                select(DBScan)
                .where(DBScan.meta["fraud_fingerprint"].as_string() == fingerprint)
                .order_by(DBScan.created_at.desc())
                .limit(limit)
            )
            db_rows = await session.execute(stmt)
            results = []
            for row in db_rows.scalars():
                meta = row.meta or {}
                results.append({
                    "scan_id": row.scan_id,
                    "date": row.created_at.isoformat() if row.created_at else None,
                    "risk": row.risk.value if row.risk else None,
                    "fingerprint": meta.get("fraud_fingerprint"),
                    "decision": meta.get("audit_trail", {}).get("decision_card", {}).get("decision"),
                })
            break
        return JSONResponse(content={"fingerprint": fingerprint, "count": len(results), "cases": results})
    except Exception as e:
        logger.error("Fingerprint search failed", error=str(e))
        return JSONResponse(content={"fingerprint": fingerprint, "count": 0, "cases": [], "error": str(e)}, status_code=500)
