"""
Explainable AI (XAI) Engine.

Translates raw findings from five analysis pipelines into human-readable
explanations with confidence levels, risk impact, and recommendations.

Input pipelines:
- Metadata findings (EXIF, author, dates, software origin)
- ELA findings (JPEG error level, compression inconsistencies)
- OCR findings (text extraction, field presence, text mismatches)
- Numeric inconsistencies (totals, cross-field validation, rounding)
- Signature results (similarity, forgery probability, quality)
"""
import structlog
from typing import List, Tuple

from app.models.xai import (
    XaiRequest,
    XaiInputFinding,
    XaiExplanation,
    XaiResponse,
    FindingCategory,
)

logger = structlog.get_logger(__name__)

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# ── Metadata explanation templates ────────────────────────────────────

META_TEMPLATES: List[dict] = [
    {
        "match_types": ["author_mismatch", "author", "creator"],
        "match_keywords": ["author", "creator", "producer"],
        "generate": lambda f: (
            f"Document metadata shows author as '{f.details.get('value', 'unknown')}', "
            f"while expected value was '{f.details.get('expected', 'not specified')}'. "
            f"This difference may be worth checking if the document is expected "
            f"to come from a known source.",
            f"Document author in metadata differs from expected value — "
            f"worth verifying with the claimed sender if this is a critical document.",
            f"Verify document origin with the claimed sender through an independent channel.",
        ),
        "sev": lambda c: "MEDIUM" if c > 0.7 else "LOW",
    },
    {
        "match_types": ["date_anomaly", "creation_date", "modify_date", "date"],
        "match_keywords": ["date", "timestamp", "created", "modified"],
        "generate": lambda f: (
            f"Document timestamp shows '{f.details.get('value', 'an unexpected date')}', "
            f"which differs from the expected '{f.details.get('expected', 'timeline')}'. "
            f"The difference is {f.details.get('discrepancy', 'unknown')}.",
            f"Document date in metadata does not match expected timeline — "
            f"may indicate backdating if the difference is significant.",
            f"Request original unmodified document and verify creation date through independent records.",
        ),
        "sev": lambda c: "MEDIUM",
    },
    {
        "match_types": ["software_origin", "software", "application"],
        "match_keywords": ["software", "application", "tool", "generator"],
        "generate": lambda f: (
            f"Document metadata indicates it was created with "
            f"'{f.details.get('value', 'unknown software')}', "
            f"while '{f.details.get('expected', 'standard software')}' was expected. "
            f"This may indicate the document was processed through non-standard software.",
            f"Document software origin differs from what was expected — "
            f"worth noting but not conclusive of tampering.",
            f"Request the original file from the claimed source application if verification is critical.",
        ),
        "sev": lambda c: "MEDIUM" if c > 0.8 else "LOW",
    },
    {
        "match_types": ["geo_location", "location", "gps", "timezone"],
        "match_keywords": ["location", "gps", "geo", "timezone", "region"],
        "generate": lambda f: (
            f"Document metadata records location '{f.details.get('value', 'unknown')}', "
            f"while '{f.details.get('expected', 'claimed source')}' was expected. "
            f"This may be relevant if geographic origin is important for compliance.",
            f"Document geographic metadata differs from expected — "
            f"may be relevant for jurisdiction-specific compliance checks.",
            f"Verify the claimed source location through IP or network logs if cross-border implications exist.",
        ),
        "sev": lambda c: "MEDIUM" if c > 0.7 else "LOW",
    },
    {
        "match_types": ["editing_history", "revision", "edit", "history"],
        "match_keywords": ["revision", "edit", "history", "version", "changes"],
        "generate": lambda f: (
            f"Document metadata shows {f.details.get('count', 'some')} revision(s). "
            f"Changes detected: {f.details.get('changes', 'content modifications')}. "
            f"Multiple revisions may be normal depending on document workflow.",
            f"Document has revision history — this is normal for many document types "
            f"but may warrant review if the document is expected to be an original.",
            f"Review version history if available. Request the earliest available version for comparison.",
        ),
        "sev": lambda c: "MEDIUM" if c > 0.75 else "LOW",
    },
    {
        "match_types": ["metadata_missing", "missing", "stripped", "cleaned"],
        "match_keywords": ["missing", "stripped", "cleaned", "removed", "empty"],
        "generate": lambda f: (
            f"Document metadata could not be read. "
            f"Expected fields not found: '{f.details.get('fields', 'standard metadata fields')}'. "
            f"This may happen with scanned documents, text files, or documents "
            f"that have been re-saved. Without metadata, document origin "
            f"and history cannot be verified from file properties alone.",
            f"Metadata unavailable — document origin and history could not be verified "
            f"from file properties because metadata fields are empty or absent.",
            f"Request the original unmodified document. Compare hash values across distribution channels if available.",
        ),
        "sev": lambda c: "LOW",
    },
]

# ── ELA explanation templates ─────────────────────────────────────────

ELA_TEMPLATES: List[dict] = [
    {
        "match_types": ["tampered_region", "tampered", "altered_region", "manipulation"],
        "match_keywords": ["tamper", "alter", "manipulate", "modified", "change"],
        "generate": lambda f: (
            f"Error Level Analysis highlights inconsistent compression in the "
            f"'{f.details.get('region', 'document')}' area "
            f"({f.details.get('confidence_pct', 'high')} confidence). "
            f"The '{f.details.get('field', 'field')}' displays different JPEG "
            f"error characteristics than the surrounding image, "
            f"strongly suggesting this content has been digitally altered "
            f"after the original capture.",
            f"Image manipulation detected — the flagged area has been digitally "
            f"altered, potentially to modify critical document fields.",
            f"Request the original unprocessed document. Compare the flagged "
            f"region against independent records or verified duplicates.",
        ),
        "sev": lambda c: "CRITICAL" if c > 0.8 else "HIGH",
    },
    {
        "match_types": ["spliced_region", "spliced", "composited", "copy_paste"],
        "match_keywords": ["splice", "composite", "copy", "paste", "merge"],
        "generate": lambda f: (
            f"ELA reveals multiple distinct compression levels across the document, "
            f"consistent with image splicing. The '{f.details.get('region', 'flagged area')}' "
            f"area (confidence: {f.details.get('confidence_pct', 'high')}) "
            f"appears to be composited from a different source image. "
            f"This pattern is characteristic of cut-and-paste forgery.",
            f"Image compositing detected — portions of the document originate from "
            f"different source images, indicating assembly rather than a single capture.",
            f"Conduct detailed pixel-level analysis of the spliced boundary. "
            f"Request separate source images for each composited element.",
        ),
        "sev": lambda c: "CRITICAL",
    },
    {
        "match_types": ["text_overlay", "overlay", "overwritten"],
        "match_keywords": ["overlay", "overwrite", "superimpose", "text_on_image"],
        "generate": lambda f: (
            f"Error Level Analysis indicates text in the "
            f"'{f.details.get('region', 'text area')}' region "
            f"shows uniform compression inconsistent with the surrounding image. "
            f"This suggests text was overlaid onto the image after capture, "
            f"which is a common technique for altering document values "
            f"while preserving the appearance of an original scan.",
            f"Text overlay detected — document values may have been digitally "
            f"overwritten. Standard forensic examination cannot determine "
            f"whether the original values were accurate.",
            f"Request original pre-signature version. Verify the overlaid "
            f"values through independent data sources or transaction records.",
        ),
        "sev": lambda c: "HIGH",
    },
    {
        "match_types": ["compression_anomaly", "compression", "quality"],
        "match_keywords": ["compression", "quality", "re-save", "recompress", "jpeg"],
        "generate": lambda f: (
            f"ELA identifies non-uniform compression artefacts across the document surface. "
            f"The {f.details.get('region', 'overall')} compression pattern "
            f"({f.details.get('detail', 'inconsistent quality')}) "
            f"differs significantly from standard scanner output. "
            f"Multiple compression cycles suggest the image has been re-saved "
            f"multiple times, potentially to mask forensic evidence of tampering.",
            f"Compression anomalies — multiple re-save cycles indicate the document "
            f"has been re-processed, potentially to hide forensic evidence.",
            f"Compare against scanner-native output format. Analyse for "
            f"JPEG ghost (double compression) artefacts in critical fields.",
        ),
        "sev": lambda c: "MEDIUM" if c < 0.6 else "HIGH",
    },
    {
        "match_types": ["no_anomaly", "clean", "genuine"],
        "match_keywords": ["no anomaly", "clean", "genuine", "unmodified"],
        "generate": lambda f: (
            f"Error Level Analysis shows consistent compression across the entire "
            f"document surface. No regions of significant compression variance "
            f"were detected. The image compression pattern is consistent with "
            f"a single-capture source, and no evidence of digital manipulation "
            f"was found at the compression level.",
            f"No image tampering detected — the document's compression profile "
            f"is consistent with a genuine single-capture source.",
            f"Proceed with standard verification. Note that ELA alone cannot "
            f"rule out sophisticated forgeries that operate below the "
            f"compression noise floor.",
        ),
        "sev": lambda c: "LOW",
    },
]

# ── OCR explanation templates ─────────────────────────────────────────

OCR_TEMPLATES: List[dict] = [
    {
        "match_types": ["text_mismatch", "mismatch", "field_mismatch"],
        "match_keywords": ["mismatch", "different", "discrepancy", "does not match"],
        "generate": lambda f: (
            f"OCR extracted value '{f.details.get('value', 'detected value')}' "
            f"in field '{f.details.get('field', 'field')}', "
            f"while '{f.details.get('expected', 'reference value')}' was expected "
            f"(OCR confidence: {f.details.get('confidence_pct', 'N/A')}). "
            f"This may indicate the field has been altered after the document was created.",
            f"Text field difference — extracted text does not match expected value. "
            f"May indicate post-issuance alteration.",
            f"Cross-verify the affected field against independent records if the value is critical.",
        ),
        "sev": lambda c: "HIGH" if c > 0.8 else "MEDIUM",
    },
    {
        "match_types": ["low_confidence", "low_ocr_confidence", "poor_quality"],
        "match_keywords": ["low confidence", "poor quality", "blur", "unreadable"],
        "generate": lambda f: (
            f"OCR confidence for '{f.details.get('field', 'field')}' "
            f"is {f.details.get('confidence_pct', 'low')}, "
            f"below the reliability threshold. "
            f"{f.details.get('issue', 'The text may be blurred or distorted')}. "
            f"The extracted text may not be reliable.",
            f"OCR confidence is low for this field — text recognition may not be reliable.",
            f"Request a higher-quality scan or original physical document if the field is critical.",
        ),
        "sev": lambda c: "MEDIUM",
    },
    {
        "match_types": ["missing_field", "absent", "missing"],
        "match_keywords": ["missing", "absent", "not found", "expected but"],
        "generate": lambda f: (
            f"Expected field '{f.details.get('field', 'a field')}' "
            f"was not found in the extracted text. "
            f"{f.details.get('context', 'This field is typically present in this document type')}. "
            f"This may indicate the document is incomplete, uses a different format, "
            f"or the field could not be read.",
            f"Expected field not found in extracted text — document may be incomplete "
            f"or use a different format than expected.",
            f"If this is a standard document type, request a complete version and verify the field is present.",
        ),
        "sev": lambda c: "MEDIUM",
    },
    {
        "match_types": ["altered_text", "overwritten", "patched"],
        "match_keywords": ["overwritten", "patched", "white-out", "correction"],
        "generate": lambda f: (
            f"Text in '{f.details.get('field', 'field')}' region "
            f"shows '{f.details.get('artefact', 'irregular spacing')}' "
            f"which may indicate text patching or correction. "
            f"This is worth investigating if the document is critical.",
            f"Text region shows possible correction artefacts — "
            f"may indicate physical document alteration.",
            f"Flag the document for manual forensic examination if this is a critical document.",
        ),
        "sev": lambda c: "MEDIUM" if c > 0.7 else "LOW",
    },
    {
        "match_types": ["font_inconsistency", "font", "typeface"],
        "match_keywords": ["font", "typeface", "typography", "style"],
        "generate": lambda f: (
            f"Text in '{f.details.get('field', 'field')}' "
            f"uses '{f.details.get('value', 'a different typeface')}', "
            f"while the rest of the document uses "
            f"'{f.details.get('expected', 'a consistent typeface')}'. "
            f"A font difference may indicate text was added separately.",
            f"Font difference detected — the affected field uses a different typeface "
            f"than the rest of the document.",
            f"Compare font characteristics against known genuine samples if suspicious.",
        ),
        "sev": lambda c: "MEDIUM" if c < 0.6 else "LOW",
    },
    {
        "match_types": ["duplicate_text", "duplicate", "repeated"],
        "match_keywords": ["duplicate", "repeated", "double"],
        "generate": lambda f: (
            f"Text '{f.details.get('text', 'duplicate text')}' "
            f"appears in multiple locations where unique content is expected. "
            f"Field '{f.details.get('field', 'field')}' "
            f"contains text identical to "
            f"'{f.details.get('other_field', 'another field')}'. "
            f"This may indicate template-based filling.",
            f"Duplicate content found — multiple fields contain the same text "
            f"where unique values are expected.",
            f"Verify each field independently if the document is critical.",
        ),
        "sev": lambda c: "LOW",
    },
]

# ── Numeric inconsistency templates ───────────────────────────────────

NUMERIC_TEMPLATES: List[dict] = [
    {
        "match_types": ["addition_error", "total_mismatch", "sum_error"],
        "match_keywords": ["total", "sum", "addition", "line item"],
        "generate": lambda f: (
            f"Income or value appears potentially modified. "
            f"The individual line items total {f.details.get('calculated_total', 'X')} "
            f"but the declared total is {f.details.get('declared_total', 'Y')}. "
            f"This {f.details.get('difference', 'Z')} discrepancy "
            f"({'abs_diff' if f.details.get('difference_type') else 'amount'}) "
            f"may indicate intentional inflation or understatement of values.",
            f"Numeric manipulation — the arithmetic in the document does not reconcile, "
            f"suggesting values may have been altered without updating related figures.",
            f"Request an itemised breakdown. Recalculate all totals independently. "
            f"Flag for audit if discrepancy exceeds materiality threshold.",
        ),
        "sev": lambda c: "CRITICAL" if c > 0.85 else "HIGH",
    },
    {
        "match_types": ["rounding_anomaly", "rounding", "fabricated"],
        "match_keywords": ["round", "fabricated", "artificial", "synthetic"],
        "generate": lambda f: (
            f"Declared values exhibit a consistent rounding pattern: "
            f"{f.details.get('pattern', 'all values are rounded to the nearest 1,000')}. "
            f"Genuine financial calculations typically produce varied figures. "
            f"Uniform rounding is a known indicator of data fabrication.",
            f"Rounding anomaly — consistently rounded values suggest fabricated "
            f"rather than calculated figures, a common fraud indicator.",
            f"Request source documents for each declared value. Compare against "
            f"bank statements or transaction records for spot-check verification.",
        ),
        "sev": lambda c: "HIGH",
    },
    {
        "match_types": ["cross_field_mismatch", "cross_reference", "inconsistency"],
        "match_keywords": ["cross", "reference", "inconsistent", "disagree"],
        "generate": lambda f: (
            f"Cross-field validation failed: value '{f.details.get('field_a_value', 'X')}' "
            f"in '{f.details.get('field_a', 'Section A')}' "
            f"differs from '{f.details.get('field_b_value', 'Y')}' "
            f"in '{f.details.get('field_b', 'Section B')}'. "
            f"These fields should contain the same information. "
            f"The {f.details.get('difference', 'discrepancy')} indicates "
            f"at least one of the values has been incorrectly recorded or altered.",
            f"Cross-reference inconsistency — related fields contain conflicting "
            f"information, indicating data integrity failure or deliberate manipulation.",
            f"Determine the correct value by consulting original source documents. "
            f"Investigate why the fields diverged and whether this reflects "
            f"a systemic issue or targeted tampering.",
        ),
        "sev": lambda c: "CRITICAL" if c > 0.85 else "HIGH",
    },
    {
        "match_types": ["implausible_value", "outlier", "implausible"],
        "match_keywords": ["implausible", "outlier", "unreasonable", "extreme"],
        "generate": lambda f: (
            f"Value '{f.details.get('value', 'X')}' in "
            f"'{f.details.get('field', 'the field')}' "
            f"falls outside the expected range "
            f"({f.details.get('range', 'normal parameters')}). "
            f"This value is {f.details.get('deviation', 'significantly')} "
            f"different from typical entries for this document type. "
            f"Implausible values are a strong indicator of data entry error or fraud.",
            f"Implausible value detected — the declared figure is outside "
            f"expected parameters for this document type, requiring investigation.",
            f"Verify the value against independent sources. Check for data "
            f"entry errors including extra digits or misplaced decimal points.",
        ),
        "sev": lambda c: "HIGH",
    },
    {
        "match_types": ["no_inconsistency", "consistent", "reconciled"],
        "match_keywords": ["consistent", "reconciled", "matched", "verified"],
        "generate": lambda f: (
            f"All numeric values in the document are internally consistent. "
            f"Totals reconcile with line items, cross-referenced fields match, "
            f"and no anomalous rounding patterns were detected. "
            f"The financial data appears arithmetically sound.",
            f"Values consistent — no arithmetic discrepancies detected in the document.",
            f"Proceed with verification. Note that numeric consistency alone "
            f"does not confirm the accuracy of the underlying data — "
            f"only that the document's arithmetic is correct.",
        ),
        "sev": lambda c: "LOW",
    },
]

# ── Signature explanation templates ───────────────────────────────────

SIGNATURE_TEMPLATES: List[dict] = [
    {
        "match_types": ["forgery_high", "forgery", "forged"],
        "match_keywords": ["forgery", "forged", "fake", "imitation"],
        "generate": lambda f: (
            f"Signature similarity score ({f.details.get('similarity_score', 'low')}) "
            f"is below the verification threshold "
            f"({f.details.get('threshold', '0.65')}). "
            f"Confidence: {f.details.get('confidence_pct', 'N/A')}. "
            f"The signature features differ from the reference specimen.",
            f"Signature similarity is below the verification threshold — "
            f"the signature may not match the reference.",
            f"Request a fresh signature sample. Consider manual verification.",
        ),
        "sev": lambda c: "HIGH",
    },
    {
        "match_types": ["forgery_low_quality", "low_quality", "unreliable"],
        "match_keywords": ["low quality", "unreliable", "insufficient", "poor"],
        "generate": lambda f: (
            f"Signature verification could not complete reliably. "
            f"The signature image quality is {f.details.get('quality_issue', 'insufficient')}, "
            f"preventing feature extraction. "
            f"Confidence: {f.details.get('confidence_pct', 'low')}.",
            f"Signature quality insufficient for reliable verification.",
            f"Request a fresh signature sample captured at adequate resolution (minimum 300 DPI).",
        ),
        "sev": lambda c: "MEDIUM",
    },
    {
        "match_types": ["genuine", "verified", "match"],
        "match_keywords": ["genuine", "verified", "match", "authentic"],
        "generate": lambda f: (
            f"Signature similarity score ({f.details.get('similarity_score', 'high')}) "
            f"exceeds the verification threshold "
            f"({f.details.get('threshold', '0.65')}). "
            f"The signature features are consistent with the reference specimen.",
            f"Signature matches the reference specimen within acceptable parameters.",
            f"Accept the signature as verified. Maintain documentation for audit purposes.",
        ),
        "sev": lambda c: "LOW",
    },
    {
        "match_types": ["borderline", "uncertain", "inconclusive"],
        "match_keywords": ["borderline", "uncertain", "inconclusive", "ambiguous"],
        "generate": lambda f: (
            f"Signature similarity score ({f.details.get('similarity_score', 'N/A')}) "
            f"is close to the decision threshold "
            f"({f.details.get('threshold', '0.65')}), "
            f"making classification uncertain. "
            f"Additional validation is recommended.",
            f"Signature similarity is borderline — the result is not confident enough "
            f"for a definitive classification.",
            f"Request an additional signature sample. Consider manual verification.",
        ),
        "sev": lambda c: "MEDIUM",
    },
]


# ── Helpers ───────────────────────────────────────────────────────────

def _match_template(finding: XaiInputFinding, templates: List[dict]) -> dict:
    """Find the best-matching template for a finding.

    Priority:
    1. Exact match on finding_type in match_types (winner)
    2. Keyword match in description (fallback)
    3. Keyword match in finding_type (fallback)
    4. Last template as default
    """
    ft = finding.finding_type.lower()
    desc = finding.description.lower()

    exact_match = None
    kw_desc_match = None
    kw_type_match = None

    for tpl in templates:
        if ft in tpl["match_types"]:
            exact_match = tpl
        if kw_desc_match is None and any(kw in desc for kw in tpl["match_keywords"]):
            kw_desc_match = tpl
        if kw_type_match is None and any(kw in ft for kw in tpl["match_keywords"]):
            kw_type_match = tpl

    return exact_match or kw_desc_match or kw_type_match or (templates[-1] if templates else None)


def _build_explanation(finding: XaiInputFinding, templates: List[dict]) -> XaiExplanation:
    """Apply a matching template to produce an XaiExplanation."""
    tpl = _match_template(finding, templates)
    if tpl is None:
        return XaiExplanation(
            finding_type=finding.finding_type,
            plain_english=f"Analysis of '{finding.finding_type}' found: {finding.description}.",
            confidence=finding.confidence,
            risk_impact="No specific risk assessment available for this finding type.",
            recommendation="Review the finding manually and determine appropriate action.",
            severity="MEDIUM",
        )

    plain_en, risk_imp, rec = tpl["generate"](finding)
    severity = tpl["sev"](finding.confidence) if callable(tpl["sev"]) else tpl["sev"]

    adjusted_conf = finding.confidence
    if severity in ("HIGH", "CRITICAL"):
        adjusted_conf = max(adjusted_conf, 0.65)
    elif severity == "LOW":
        adjusted_conf = min(adjusted_conf, 0.4)

    return XaiExplanation(
        finding_type=finding.finding_type,
        plain_english=plain_en,
        confidence=round(adjusted_conf, 3),
        risk_impact=risk_imp,
        recommendation=rec,
        severity=severity,
    )


# ── Public API ────────────────────────────────────────────────────────

def generate_explanations(request: XaiRequest) -> XaiResponse:
    """
    Generate human-readable explanations for all input findings.

    Each finding is matched against category-specific templates and
    translated into plain English with confidence, risk impact, severity,
    and a recommended action. An overall summary is computed from the
    highest-severity findings.
    """
    logger.info("XAI processing started", finding_count=len(request.findings))

    template_map = {
        FindingCategory.METADATA: META_TEMPLATES,
        FindingCategory.ELA: ELA_TEMPLATES,
        FindingCategory.OCR: OCR_TEMPLATES,
        FindingCategory.NUMERIC: NUMERIC_TEMPLATES,
        FindingCategory.SIGNATURE: SIGNATURE_TEMPLATES,
    }

    explanations: List[XaiExplanation] = []
    for finding in request.findings:
        templates = template_map.get(finding.category, [])
        explanation = _build_explanation(finding, templates)
        explanations.append(explanation)

    doc_ctx = request.document_context or "the document"

    if not explanations:
        return XaiResponse(
            explanations=[],
            summary=f"No findings provided for {doc_ctx}.",
            overall_confidence=0.0,
            overall_severity="LOW",
            top_recommendation="No action required.",
        )

    # Compute overall severity
    max_sev = max(explanations, key=lambda e: SEVERITY_ORDER.get(e.severity, 0))
    overall_severity = max_sev.severity

    # Aggregate confidence (average)
    avg_conf = sum(e.confidence for e in explanations) / len(explanations)

    # Build summary text
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for e in explanations:
        sev_counts[e.severity] = sev_counts.get(e.severity, 0) + 1

    summary_parts = []
    if sev_counts["CRITICAL"] > 0:
        summary_parts.append(f"{sev_counts['CRITICAL']} critical")
    if sev_counts["HIGH"] > 0:
        summary_parts.append(f"{sev_counts['HIGH']} high")
    if sev_counts["MEDIUM"] > 0:
        summary_parts.append(f"{sev_counts['MEDIUM']} medium")
    if sev_counts["LOW"] > 0:
        summary_parts.append(f"{sev_counts['LOW']} low")

    summary = (
        f"Analysis of {doc_ctx} identified {' and '.join(summary_parts)} "
        f"severity finding{'s' if len(explanations) != 1 else ''}."
    )

    # Top recommendation
    criticals = [e for e in explanations if e.severity == "CRITICAL"]
    highs = [e for e in explanations if e.severity == "HIGH"]
    top_group = criticals or highs or explanations
    top_rec = top_group[0].recommendation

    logger.info(
        "XAI processing complete",
        explanation_count=len(explanations),
        overall_severity=overall_severity,
        avg_confidence=round(avg_conf, 3),
    )

    return XaiResponse(
        explanations=explanations,
        summary=summary,
        overall_confidence=round(avg_conf, 3),
        overall_severity=overall_severity,
        top_recommendation=top_rec,
    )
