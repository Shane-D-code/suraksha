"""
Document Anomaly Heatmap Service

Generates heatmaps for document images by detecting suspicious regions
through visual analysis. Correlates with existing scan results for
context-aware anomaly detection.

Features:
- Text-dense region detection via edge/contrast analysis
- Suspicious pattern classification (forms, logos, URLs)
- Integration with existing scan reasons for context
- Base64-encoded overlay image generation
- PIL-only fallback when OpenCV is unavailable
"""
import base64
import io
import time
import structlog
from typing import List, Optional, Tuple
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageEnhance

from app.models.heatmap import HeatmapRegion

logger = structlog.get_logger(__name__)

try:
    import cv2
    import numpy as np
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False
    logger.info("OpenCV not available — using PIL-only analysis")


class HeatmapService:
    """Generates document anomaly heatmaps with overlay images."""

    def __init__(self, grid_size: int = 40):
        self.grid_size = grid_size

    async def analyze(
        self,
        file_path: str,
        page_number: int = 1,
        threshold: float = 0.5,
        scan_reasons: Optional[List[str]] = None,
    ) -> Tuple[List[HeatmapRegion], str, int, int]:
        """
        Analyze a document image and generate a heatmap overlay.

        Returns:
            Tuple of (regions, base64_overlay, analysis_time_ms, total_pages)
        """
        start = time.time()

        img, total_pages = self._load_image(file_path, page_number)
        if img is None:
            return [], "", 0, 1

        regions = self._detect_regions(img, threshold, scan_reasons or [])

        overlay_b64 = self._generate_overlay(img, regions)

        elapsed = int((time.time() - start) * 1000)
        return regions, overlay_b64, elapsed, total_pages

    # ------------------------------------------------------------------
    # Image loading
    # ------------------------------------------------------------------

    def _load_image(self, file_path: str, page_number: int) -> Tuple[Optional[Image.Image], int]:
        path = Path(file_path)
        if not path.exists():
            logger.warning("Heatmap file not found", path=file_path)
            return None, 1

        try:
            img = Image.open(file_path)
            img = img.convert("RGB")

            frames = 1
            try:
                frames = getattr(img, "n_frames", 1)
            except Exception:
                pass

            if frames > 1 and page_number > 1:
                try:
                    img.seek(page_number - 1)
                except Exception:
                    pass

            return img, frames

        except Exception as e:
            logger.error("Failed to load heatmap image", path=file_path, error=str(e))
            return None, 1

    # ------------------------------------------------------------------
    # Region detection
    # ------------------------------------------------------------------

    def _detect_regions(
        self,
        img: Image.Image,
        threshold: float,
        scan_reasons: List[str],
    ) -> List[HeatmapRegion]:
        # Always run PIL grid analysis for text-dense regions
        regions = self._detect_regions_pil(img, max(threshold * 0.8, 0.2), scan_reasons)

        # When CV2 is available, additionally run contour-based detection
        # for structural elements (forms, logos, buttons)
        if CV2_AVAILABLE:
            cv_regions = self._detect_regions_cv2(img, threshold, scan_reasons)
            regions.extend(cv_regions)

        if scan_reasons:
            self._correlate_with_reasons(regions, scan_reasons)

        regions = self._merge_overlapping(regions)
        regions.sort(key=lambda r: r.confidence, reverse=True)
        return regions

    # ---- PIL-only path -------------------------------------------------

    def _detect_regions_pil(
        self,
        img: Image.Image,
        threshold: float,
        scan_reasons: List[str],
    ) -> List[HeatmapRegion]:
        width, height = img.size
        gs = self.grid_size

        gray = img.convert("L")
        edges = self._pil_edge_detect(gray)

        cell_scores: dict = {}
        for y in range(0, height, gs):
            for x in range(0, width, gs):
                cw = min(gs, width - x)
                ch = min(gs, height - y)

                cell = edges.crop((x, y, x + cw, y + ch))
                px = list(cell.getdata())
                edge_density = sum(1 for p in px if p > 128) / max(len(px), 1)

                gc = gray.crop((x, y, x + cw, y + ch))
                gv = list(gc.getdata())
                variance = 0.0
                if len(gv) > 1:
                    m = sum(gv) / len(gv)
                    variance = sum((v - m) ** 2 for v in gv) / len(gv)

                score = (edge_density * 0.6 + min(variance / 5000, 1.0) * 0.4)
                if score > threshold:
                    cell_scores[(x, y)] = score

        regions = self._cluster_cells(cell_scores, width, height, gs)
        return regions

    @staticmethod
    def _pil_edge_detect(gray: Image.Image) -> Image.Image:
        edges = gray.filter(ImageFilter.FIND_EDGES)
        enhancer = ImageEnhance.Contrast(edges)
        return enhancer.enhance(2.0)

    # ---- OpenCV path ---------------------------------------------------

    def _detect_regions_cv2(
        self,
        img: Image.Image,
        threshold: float,
        scan_reasons: List[str],
    ) -> List[HeatmapRegion]:
        cv_img = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
        gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
        height, width = gray.shape
        gs = self.grid_size

        edges = cv2.Canny(gray, 50, 150)
        kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (5, 5))
        closed = cv2.morphologyEx(edges, cv2.MORPH_CLOSE, kernel)

        contours, _ = cv2.findContours(closed, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        regions: List[HeatmapRegion] = []
        total_area = width * height

        for cnt in contours:
            x, y, w, h = cv2.boundingRect(cnt)
            if w < 15 or h < 15:
                continue
            area = w * h
            if area / total_area > 0.8:
                continue

            roi = edges[y:y + h, x:x + w]
            edge_density = float(np.sum(roi > 0)) / max(roi.size, 1)
            confidence = min(edge_density * (1 + (area / total_area) * 2), 1.0)

            if confidence > threshold:
                rtype, reason = self._classify_region_cv2(w, h, area / total_area)
                regions.append(HeatmapRegion(
                    x=x, y=y, width=w, height=h,
                    confidence=round(confidence, 3),
                    reason=reason, region_type=rtype,
                ))

        # Also run grid-based detection for text-dense patches
        cell_scores: dict = {}
        for y in range(0, height, gs):
            for x in range(0, width, gs):
                cw = min(gs, width - x)
                ch = min(gs, height - y)
                roi = edges[y:y + ch, x:x + cw]
                score = float(np.sum(roi > 0)) / max(roi.size, 1)
                if score > threshold:
                    cell_scores[(x, y)] = score

        grid_regions = self._cluster_cells(cell_scores, width, height, gs)
        regions.extend(grid_regions)

        return self._merge_overlapping(regions)

    @staticmethod
    def _classify_region_cv2(w: int, h: int, area_ratio: float) -> Tuple[str, str]:
        aspect = w / max(h, 1)
        if 2.5 < aspect < 8 and area_ratio < 0.05:
            return "form", "Form-like input field detected"
        if 0.5 < aspect < 2.0 and area_ratio < 0.08:
            return "logo", "Potential brand logo area"
        if w > 60 and h > 15 and aspect > 1.5:
            return "text", "High-density text region with suspicious patterns"
        return "suspicious", "Anomalous visual region detected"

    # ---- Shared helpers ------------------------------------------------

    @staticmethod
    def _cluster_cells(
        cell_scores: dict,
        img_width: int,
        img_height: int,
        grid_size: int,
    ) -> List[HeatmapRegion]:
        if not cell_scores:
            return []

        visited = set()
        regions: List[HeatmapRegion] = []
        cells = list(cell_scores.keys())

        def neighbors(cx, cy):
            for dx, dy in [(grid_size, 0), (-grid_size, 0), (0, grid_size), (0, -grid_size)]:
                yield (cx + dx, cy + dy)

        for cell in cells:
            if cell in visited:
                continue

            cluster = []
            queue = [cell]
            visited.add(cell)
            while queue:
                cur = queue.pop(0)
                cluster.append(cur)
                for nb in neighbors(*cur):
                    if nb in cell_scores and nb not in visited:
                        visited.add(nb)
                        queue.append(nb)

            if not cluster:
                continue

            xs = [c[0] for c in cluster]
            ys = [c[1] for c in cluster]
            min_x = min(xs)
            min_y = min(ys)
            max_x = max(xs) + grid_size
            max_y = max(ys) + grid_size

            avg_conf = sum(cell_scores[c] for c in cluster) / len(cluster)
            rtype = "suspicious"
            reason = "Suspicious content region detected"
            if avg_conf > 0.7:
                reason = "High-density suspicious text region"

            regions.append(HeatmapRegion(
                x=min_x, y=min_y,
                width=min(max_x, img_width) - min_x,
                height=min(max_y, img_height) - min_y,
                confidence=round(min(avg_conf, 1.0), 3),
                reason=reason, region_type=rtype,
            ))

        return regions

    @staticmethod
    def _correlate_with_reasons(
        regions: List[HeatmapRegion],
        scan_reasons: List[str],
    ):
        text = " ".join(scan_reasons).lower()
        for r in regions:
            if any(kw in text for kw in ["brand", "impersonation", "logo"]):
                if r.region_type == "logo":
                    r.confidence = min(r.confidence + 0.25, 1.0)
                    r.reason = "Brand impersonation — suspicious logo region"
            if any(kw in text for kw in ["form", "login", "credential", "password"]):
                if r.region_type == "form":
                    r.confidence = min(r.confidence + 0.3, 1.0)
                    r.reason = "Credential harvesting — suspicious form field"
            if any(kw in text for kw in ["urgent", "social engineering", "urgency"]):
                if r.region_type == "text":
                    r.confidence = min(r.confidence + 0.2, 1.0)
                    r.reason = "Social engineering — urgent messaging region"
            if any(kw in text for kw in ["suspicious tld", "url", "domain"]):
                if r.region_type == "text" and r.width > 80:
                    r.confidence = min(r.confidence + 0.15, 1.0)
                    r.reason = "Suspicious URL-like text region"

    @staticmethod
    def _merge_overlapping(regions: List[HeatmapRegion]) -> List[HeatmapRegion]:
        if not regions:
            return []
        sorted_r = sorted(regions, key=lambda r: r.confidence, reverse=True)
        used = [False] * len(sorted_r)
        merged: List[HeatmapRegion] = []
        for i, r1 in enumerate(sorted_r):
            if used[i]:
                continue
            used[i] = True
            for j in range(i + 1, len(sorted_r)):
                if used[j]:
                    continue
                if HeatmapService._intersect(r1, sorted_r[j]) > 0:
                    used[j] = True
            merged.append(r1)
        return merged

    @staticmethod
    def _intersect(a: HeatmapRegion, b: HeatmapRegion) -> int:
        x = max(0, min(a.x + a.width, b.x + b.width) - max(a.x, b.x))
        y = max(0, min(a.y + a.height, b.y + b.height) - max(a.y, b.y))
        return x * y

    # ------------------------------------------------------------------
    # Overlay generation
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_overlay(img: Image.Image, regions: List[HeatmapRegion]) -> str:
        if not regions:
            blank = Image.new("RGBA", img.size, (0, 0, 0, 0))
            buf = io.BytesIO()
            blank.save(buf, format="PNG")
            return base64.b64encode(buf.getvalue()).decode()

        overlay = img.convert("RGBA")
        draw = ImageDraw.Draw(overlay)

        for r in regions:
            if r.confidence >= 0.7:
                fill = (255, 0, 0, 60)
                outline = (255, 0, 0, 220)
            elif r.confidence >= 0.5:
                fill = (255, 165, 0, 50)
                outline = (255, 165, 0, 200)
            else:
                fill = (255, 255, 0, 40)
                outline = (255, 255, 0, 180)

            bbox = [r.x, r.y, r.x + r.width, r.y + r.height]
            draw.rectangle(bbox, fill=fill, outline=outline, width=2)
            draw.text((r.x + 2, r.y + 2), f"{r.confidence:.0%}", fill=outline)

        blended = Image.alpha_composite(img.convert("RGBA"), overlay)
        buf = io.BytesIO()
        blended.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()


# Module-level instance
_heatmap_service: Optional[HeatmapService] = None


def get_heatmap_service() -> HeatmapService:
    global _heatmap_service
    if _heatmap_service is None:
        _heatmap_service = HeatmapService()
    return _heatmap_service
