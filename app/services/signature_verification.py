"""
Signature Verification Service using a Siamese approach.

Extracts feature embeddings from signature images using a pretrained
CNN (ResNet18) and compares them via cosine similarity. A low similarity
score relative to the learned threshold indicates a likely forgery.

Architecture (shared-weights Siamese):
  reference_image ─┐
                   ├── Encoder (ResNet18) ──→ embedding ─┐
  submitted_image ─┘                                      ├── cosine similarity → decision
                                                          │
                                   same encoder (shared) ─┘
"""
import math
import structlog
import time
from typing import Optional, Tuple
from pathlib import Path

from PIL import Image, ImageOps

from app.models.signature import SignatureVerifyResponse

logger = structlog.get_logger(__name__)

# Try to import PyTorch (available in project requirements)
try:
    import torch
    import torch.nn as nn
    import torchvision.transforms as transforms
    import torchvision.models as models
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logger.warning("PyTorch not available — using pixel-level fallback")


# ── Constants ──────────────────────────────────────────────────────────
DEFAULT_THRESHOLD = 0.65        # Below this → forgery
IMG_SIZE = 224
EMBEDDING_DIM = 512


# ── Siamese Encoder ────────────────────────────────────────────────────

class SiameseEncoder:
    """
    Shared-weights feature encoder for signature images.

    Uses a pretrained ResNet18 without the final classification layer,
    producing a 512-dimensional embedding vector for each input image.
    """

    def __init__(self, device: str = "cpu"):
        self.device = device
        self.model = None
        self.transform = None
        self._init_model()

    def _init_model(self):
        if not TORCH_AVAILABLE:
            logger.info("Torch unavailable — SiameseEncoder disabled")
            return

        try:
            resnet = models.resnet18(weights=models.ResNet18_Weights.IMAGENET1K_V1)
            self.model = nn.Sequential(*list(resnet.children())[:-1])
            self.model.eval()
            self.model.to(self.device)

            self.transform = transforms.Compose([
                transforms.Resize((IMG_SIZE, IMG_SIZE)),
                transforms.ToTensor(),
                transforms.Normalize(
                    mean=[0.485, 0.456, 0.406],
                    std=[0.229, 0.224, 0.225],
                ),
            ])

            logger.info("ResNet18 Siamese encoder initialised", device=self.device)
        except Exception as e:
            logger.warning("Failed to load ResNet18 encoder", error=str(e))
            self.model = None

    def encode(self, pil_image: Image.Image) -> Optional[list]:
        """
        Encode a single PIL image into a 512-D embedding.

        Returns a flat Python list, or None on failure.
        """
        if self.model is None or self.transform is None:
            return None

        try:
            img = pil_image.convert("RGB")
            tensor = self.transform(img).unsqueeze(0).to(self.device)

            with torch.no_grad():
                embedding = self.model(tensor)

            return embedding.squeeze().cpu().tolist()
        except Exception as e:
            logger.warning("Siamese encoding failed", error=str(e))
            return None


# ── Pixel-level fallback ───────────────────────────────────────────────

def _pixel_similarity(a: Image.Image, b: Image.Image) -> float:
    """
    Simple pixel-level structural similarity for when Torch is unavailable.

    Resizes both images to IMG_SIZE², converts to grayscale, and computes
    the normalised correlation coefficient.
    """
    try:
        a = a.convert("L").resize((IMG_SIZE, IMG_SIZE))
        b = b.convert("L").resize((IMG_SIZE, IMG_SIZE))

        pa = list(a.getdata())
        pb = list(b.getdata())
        n = len(pa)

        if n == 0:
            return 0.0

        ma = sum(pa) / n
        mb = sum(pb) / n

        num = sum((pa[i] - ma) * (pb[i] - mb) for i in range(n))
        da = math.sqrt(sum((pa[i] - ma) ** 2 for i in range(n)))
        db = math.sqrt(sum((pb[i] - mb) ** 2 for i in range(n)))

        if da == 0 or db == 0:
            return 1.0 if num == 0 else 0.0

        r = num / (da * db)
        return max(0.0, min(1.0, (r + 1.0) / 2.0))
    except Exception as e:
        logger.warning("Pixel similarity fallback failed", error=str(e))
        return 0.5


# ── Helper ─────────────────────────────────────────────────────────────

def _load_image(path: str) -> Optional[Image.Image]:
    p = Path(path)
    if not p.exists():
        logger.warning("Signature image not found", path=path)
        return None
    try:
        return Image.open(p).convert("RGB")
    except Exception as e:
        logger.warning("Failed to open signature image", path=path, error=str(e))
        return None


def _compute_confidence(similarity: float, threshold: float) -> float:
    """
    Confidence is proportional to the distance from the decision boundary.
    1.0 = far from boundary, 0.5 = right on boundary, 0.0 = extremely close.
    """
    dist = abs(similarity - threshold)
    return min(1.0, 0.5 + dist * 1.5)


# ── Public API ─────────────────────────────────────────────────────────

_encoder: Optional[SiameseEncoder] = None


def get_encoder() -> SiameseEncoder:
    """Module-level singleton encoder (shared weights)."""
    global _encoder
    if _encoder is None:
        _encoder = SiameseEncoder()
    return _encoder


def verify(
    reference_path: str,
    submitted_path: str,
    threshold: float = DEFAULT_THRESHOLD,
) -> SignatureVerifyResponse:
    """
    Verify a submitted signature against a reference.

    Steps
    1. Load both images.
    2. Encode both into embeddings using the Siamese encoder.
    3. Compute cosine similarity between embeddings.
    4. Classify as forgery if similarity < threshold.
    5. Compute confidence from distance to boundary.

    Falls back to pixel-level correlation when Torch is unavailable.
    """
    start = time.time()

    ref_img = _load_image(reference_path)
    sub_img = _load_image(submitted_path)

    if ref_img is None or sub_img is None:
        return SignatureVerifyResponse(
            status="error",
            similarity_score=0.0,
            confidence=0.0,
            is_forgery=True,
            threshold_used=threshold,
            analysis_time_ms=int((time.time() - start) * 1000),
            embedding_dim=0,
            model_used="",
            error="One or both signature images could not be loaded",
        )

    encoder = get_encoder()
    emb_ref = encoder.encode(ref_img)
    emb_sub = encoder.encode(sub_img)

    # ── Torch path ─────────────────────────────────────────────────
    if emb_ref is not None and emb_sub is not None:
        import numpy as np

        a = np.array(emb_ref, dtype=np.float64)
        b = np.array(emb_sub, dtype=np.float64)

        norm_a = np.linalg.norm(a)
        norm_b = np.linalg.norm(b)

        if norm_a < 1e-8 or norm_b < 1e-8:
            similarity = 0.5
        else:
            similarity = float(np.dot(a, b) / (norm_a * norm_b))
            similarity = max(0.0, min(1.0, (similarity + 1.0) / 2.0))

        model_name = f"resnet18_siamese_{EMBEDDING_DIM}d"
        embedding_dim = EMBEDDING_DIM

    # ── Fallback path ──────────────────────────────────────────────
    else:
        logger.info("Using pixel-level fallback for signature comparison")
        similarity = _pixel_similarity(ref_img, sub_img)
        model_name = "pixel_correlation_fallback"
        embedding_dim = IMG_SIZE * IMG_SIZE

    is_forgery = similarity < threshold
    confidence = _compute_confidence(similarity, threshold)
    elapsed = int((time.time() - start) * 1000)

    logger.info(
        "Signature verification complete",
        similarity=round(similarity, 4),
        confidence=round(confidence, 4),
        is_forgery=is_forgery,
        model=model_name,
        elapsed_ms=elapsed,
    )

    return SignatureVerifyResponse(
        status="completed",
        similarity_score=round(similarity, 4),
        confidence=round(confidence, 4),
        is_forgery=is_forgery,
        threshold_used=threshold,
        analysis_time_ms=elapsed,
        embedding_dim=embedding_dim,
        model_used=model_name,
    )
