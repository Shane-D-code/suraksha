"""
Signature Intelligence Engine.

Extracts images from PDF documents and detects signature-like regions
using computer vision. Uses OpenCV for contour analysis and edge detection.

Features:
- Embedded image extraction via fitz
- Signature region detection via OpenCV contour analysis
- ORB-based feature matching for signature comparison
- Confidence scoring per detected region
"""
import structlog
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import numpy as np

logger = structlog.get_logger(__name__)

try:
    import cv2
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False
    logger.warning("SIGNATURE_NO_CV2", msg="OpenCV not available — signature detection disabled")

try:
    import fitz
    FITZ_AVAILABLE = True
except ImportError:
    FITZ_AVAILABLE = False
    logger.warning("SIGNATURE_NO_FITZ", msg="fitz not available — PDF image extraction disabled")


@dataclass
class SignatureRegion:
    page: int
    bounding_box: Tuple[int, int, int, int]  # x, y, w, h in pixels
    confidence: float
    area_pct: float  # percentage of page area


@dataclass
class SignatureIntelligenceResult:
    image_count: int = 0
    signature_regions: List[SignatureRegion] = field(default_factory=list)
    has_signatures: bool = False
    max_confidence: float = 0.0
    signature_score: float = 0.0  # 0-100 risk contribution
    findings: List[str] = field(default_factory=list)
    confidence: float = 1.0


def _is_signature_candidate(cnt, page_area: int) -> Tuple[bool, float, float]:
    """Determine if a contour is likely a signature based on size, aspect ratio, and density."""
    if not CV2_AVAILABLE:
        return False, 0.0, 0.0

    area = cv2.contourArea(cnt)
    if area < 50 or area > page_area * 0.15:
        return False, 0.0, 0.0

    x, y, w, h = cv2.boundingRect(cnt)
    aspect_ratio = w / max(h, 1)

    # Signatures are typically wide (aspect ratio 2:1 to 5:1)
    if aspect_ratio < 1.5 or aspect_ratio > 8.0:
        return False, 0.0, 0.0

    area_pct = (area / page_area) * 100.0
    # Signatures usually occupy 0.3-5% of page area
    if area_pct < 0.1 or area_pct > 8.0:
        return False, 0.0, 0.0

    # Calculate circularity — rounder = higher
    perimeter = cv2.arcLength(cnt, True)
    circularity = (4 * np.pi * area) / max(perimeter * perimeter, 0.01)
    # Signatures are NOT circular (low circularity)
    if circularity > 0.5:
        return False, 0.0, 0.0

    confidence = min(1.0, (area_pct / 3.0) * 0.7 + (1.0 - circularity) * 0.3)
    return True, confidence, area_pct


def extract_signature_regions(pdf_bytes: bytes, dpi: int = 150) -> SignatureIntelligenceResult:
    """Extract embedded images from PDF and detect signature-like regions."""
    result = SignatureIntelligenceResult()

    if not FITZ_AVAILABLE:
        result.findings.append("PDF image extraction not available (fitz missing)")
        return result

    if not CV2_AVAILABLE:
        result.findings.append("Signature detection not available (OpenCV missing)")
        return result

    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    total_regions = 0

    for page_num in range(len(doc)):
        page = doc[page_num]
        pix = page.get_pixmap(dpi=dpi)
        img_array = np.frombuffer(pix.samples, dtype=np.uint8).reshape(
            pix.height, pix.width, pix.n
        )

        if pix.n == 4:
            img_array = cv2.cvtColor(img_array, cv2.COLOR_RGBA2GRAY)
        elif pix.n == 3:
            img_array = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)

        page_area = pix.width * pix.height

        # Adaptive threshold to isolate ink strokes
        blurred = cv2.GaussianBlur(img_array, (5, 5), 0)
        thresh = cv2.adaptiveThreshold(
            blurred, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY_INV, 31, 2
        )

        # Find contours
        contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

        for cnt in contours:
            is_sig, conf, area_pct = _is_signature_candidate(cnt, page_area)
            if is_sig:
                x, y, w, h = cv2.boundingRect(cnt)
                result.signature_regions.append(SignatureRegion(
                    page=page_num + 1,
                    bounding_box=(x, y, w, h),
                    confidence=round(conf, 3),
                    area_pct=round(area_pct, 2),
                ))
                total_regions += 1

    doc.close()
    result.image_count = total_regions
    result.has_signatures = total_regions > 0
    if result.signature_regions:
        result.max_confidence = max(r.confidence for r in result.signature_regions)
        result.signature_score = 0.0  # No risk from having a signature
        result.findings.append(
            f"Detected {total_regions} signature-like region(s) "
            f"(max confidence: {result.max_confidence:.1%})"
        )
    else:
        result.signature_score = 0.0
        result.findings.append("No signature regions detected in document images")

    # ── ORB cross-comparison across pages ──────────────────────────────
    if total_regions >= 2 and CV2_AVAILABLE:
        orb_comparison = _compare_signature_regions(result.signature_regions, doc, dpi)
        result.findings.extend(orb_comparison["findings"])

    logger.info("SIGNATURE_ANALYSIS_COMPLETE",
                regions=total_regions,
                max_confidence=result.max_confidence)

    return result


def _compare_signature_regions(
    regions: List[SignatureRegion], doc, dpi: int
) -> dict:
    """Compare all detected signature regions using ORB keypoint matching.
    
    Returns dict with match pairs and clone/forgery findings.
    """
    findings = []
    matches = []

    if len(regions) < 2:
        return {"matches": [], "findings": findings}

    try:
        orb = cv2.ORB_create(nfeatures=500)
        FLANN_INDEX_LOWE = 1
        index_params = dict(algorithm=FLANN_INDEX_LOWE, trees=5)
        search_params = dict(checks=50)
        flann = cv2.FlannBasedMatcher(index_params, search_params)

        # Extract image patches for each region
        patches = []
        for reg in regions:
            page = doc[reg.page - 1]
            pix = page.get_pixmap(dpi=dpi)
            img = np.frombuffer(pix.samples, dtype=np.uint8).reshape(
                pix.height, pix.width, pix.n
            )
            if pix.n == 4:
                gray = cv2.cvtColor(img, cv2.COLOR_RGBA2GRAY)
            elif pix.n == 3:
                gray = cv2.cvtColor(img, cv2.COLOR_RGB2GRAY)
            else:
                gray = img
            x, y, w, h = reg.bounding_box
            patch = gray[y : y + h, x : x + w]
            patches.append(patch)

        # Cross-compare all pairs
        for i in range(len(patches)):
            for j in range(i + 1, len(patches)):
                kp1, des1 = orb.detectAndCompute(patches[i], None)
                kp2, des2 = orb.detectAndCompute(patches[j], None)

                if des1 is None or des2 is None or len(kp1) < 3 or len(kp2) < 3:
                    continue

                flann_matches = flann.knnMatch(des1, des2, k=2)

                # Lowe's ratio test
                good = []
                for pair in flann_matches:
                    if len(pair) == 2:
                        m, n = pair
                        if m.distance < 0.75 * n.distance:
                            good.append(m)

                similarity = len(good) / max(len(kp1), len(kp2)) if max(len(kp1), len(kp2)) > 0 else 0

                matches.append({
                    "region_a": i,
                    "region_b": j,
                    "keypoints_a": len(kp1),
                    "keypoints_b": len(kp2),
                    "good_matches": len(good),
                    "similarity": round(similarity, 3),
                })

                if similarity > 0.85:
                    findings.append(
                        f"Signature clone detected: region {i + 1} and region {j + 1} "
                        f"are {similarity:.0%} similar — possible duplicate/cloned signature"
                    )
                elif similarity < 0.3 and len(kp1) > 10 and len(kp2) > 10:
                    findings.append(
                        f"Signature forgery indicator: region {i + 1} and region {j + 1} "
                        f"only {similarity:.0%} similar — signatures may be from different sources"
                    )

    except Exception as e:
        logger.info("ORB signature comparison not available: %s", str(e))
        findings.append("Signature cross-comparison not available: ORB matching could not be performed")

    return {"matches": matches, "findings": findings}
