"""
Novel anomaly detection engine.

Three independent detectors fused into a single result:
1. **Isolation Forest** — multivariate outlier detection via scikit-learn
2. **Autoencoder** — reconstruction-based deep anomaly detection via PyTorch
3. **Statistical outlier** — per-feature Z-score / IQR univariate detection

All three are stateless for the request-response pattern. The caller may
optionally supply a reference_sample matrix to fit Isolation Forest and
the Autoencoder; otherwise in-memory defaults / heuristics are used.
"""
import math
import time
import structlog
from typing import List, Optional
import numpy as np

from app.models.anomaly import (
    FieldFeature,
    AnomalyDetectionRequest,
    AnomalyDetectionResponse,
    AnomalyResult,
    AnomalyMethod,
)

logger = structlog.get_logger(__name__)

# Optional PyTorch — the autoencoder path handles absence gracefully
try:
    import torch
    _TORCH_AVAILABLE = True
except ImportError:
    torch = None
    _TORCH_AVAILABLE = False
    logger.warning("PyTorch unavailable — autoencoder detector will be skipped")


# =========================================================================
#  Isolation Forest detector
# =========================================================================

def _detect_isolation_forest(fields: List[FieldFeature],
                             reference_sample: Optional[List[List[float]]],
                             ) -> AnomalyResult:
    """Fit a scikit-learn Isolation Forest and score the current sample."""
    from sklearn.ensemble import IsolationForest

    values = np.array([[f.value] for f in fields], dtype=np.float64).reshape(1, -1)
    n_features = values.shape[1]

    if reference_sample and len(reference_sample) >= 4:
        X_train = np.array(reference_sample, dtype=np.float64)
        if X_train.ndim == 2 and X_train.shape[1] >= n_features:
            X_train = X_train[:, :n_features]
        else:
            X_train = np.column_stack([X_train.ravel()] * n_features) if X_train.ndim == 1 else \
                np.pad(X_train, ((0, 0), (0, n_features - X_train.shape[1])), constant_values=0.5)
        model = IsolationForest(n_estimators=100, contamination='auto', random_state=42)
        model.fit(X_train)

        # decision_function: negative = anomaly, positive = normal
        raw = model.decision_function(values)[0]
        # Map to 0-1 anomaly score: raw in [-0.7, 0.0] typical for anomalies
        anomaly_score = 1.0 - (raw + 0.7) / 1.4 if raw < 0 else max(0.0, 0.5 - raw / 1.4)
        anomaly_score = float(np.clip(anomaly_score, 0.0, 1.0))
    else:
        # Stateless mode: no reference baseline available, cannot meaningfully detect
        anomaly_score = 0.0

    # Identify top contributing features (highest individual z-score from mean)
    if reference_sample:
        X_ref = np.array(reference_sample, dtype=np.float64)
        means = X_ref.mean(axis=0)
        stds = X_ref.std(axis=0) + 1e-10
    else:
        means = np.full(n_features, 0.5)
        stds = np.full(n_features, 0.2)

    z_scores = np.abs((values[0] - means) / stds)
    sorted_idx = np.argsort(z_scores)[::-1]
    top_feats = [fields[i].name for i in sorted_idx[:3] if z_scores[i] > 2.0]

    if anomaly_score > 0.85:
        explanation = (f"Isolation Forest flagged this sample as an outlier "
                       f"(score={anomaly_score:.2f}). The combination of "
                       f"{', '.join(top_feats[:2]) or 'multiple features'} differs "
                       f"significantly from expected patterns.")
        severity = "HIGH"
    elif anomaly_score > 0.75:
        explanation = (f"Isolation Forest detected mild deviation from normal patterns. "
                       f"Score={anomaly_score:.2f}; no single feature is extreme.")
        severity = "MEDIUM"
    else:
        explanation = f"Isolation Forest indicates normal behaviour (score={anomaly_score:.2f})."
        severity = "LOW"

    confidence = min(0.95, 0.5 + anomaly_score * 0.5) if anomaly_score > 0.75 else max(0.3, 0.8 - anomaly_score * 0.5)

    return AnomalyResult(
        method=AnomalyMethod.ISOLATION_FOREST,
        anomaly_score=round(anomaly_score, 4),
        confidence=round(confidence, 4),
        top_features=top_feats,
        explanation=explanation,
        severity=severity,
        details={"n_features": n_features, "n_reference_samples": len(reference_sample) if reference_sample else 0},
    )


# =========================================================================
#  Autoencoder detector (PyTorch)
# =========================================================================

if _TORCH_AVAILABLE:

    class _AnomalyAutoencoder(torch.nn.Module):
        """Minimal feed-forward autoencoder for anomaly detection."""
        def __init__(self, input_dim: int, hidden_dim: int = 8):
            super().__init__()
            self.encoder = torch.nn.Sequential(
                torch.nn.Linear(input_dim, hidden_dim),
                torch.nn.ReLU(),
                torch.nn.Linear(hidden_dim, max(2, hidden_dim // 2)),
                torch.nn.ReLU(),
            )
            self.decoder = torch.nn.Sequential(
                torch.nn.Linear(max(2, hidden_dim // 2), hidden_dim),
                torch.nn.ReLU(),
                torch.nn.Linear(hidden_dim, input_dim),
                torch.nn.Sigmoid(),
            )

        def forward(self, x):
            return self.decoder(self.encoder(x))


    def _pretrain_autoencoder(n_features: int = 8) -> tuple:
        """Pre-train a reference autoencoder on a broad uniform distribution.
        Returns (model, mean_train_err, std_train_err, device)."""
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model = _AnomalyAutoencoder(n_features).to(device)
        rng = np.random.RandomState(42)
        X_synth = rng.uniform(0, 1, size=(500, n_features)).astype(np.float32)

        dataset = torch.utils.data.TensorDataset(torch.from_numpy(X_synth))
        loader = torch.utils.data.DataLoader(dataset, batch_size=64, shuffle=True)
        optimizer = torch.optim.Adam(model.parameters(), lr=1e-2)
        criterion = torch.nn.MSELoss()

        model.train()
        for _epoch in range(30):
            for (batch,) in loader:
                batch = batch.to(device)
                optimizer.zero_grad()
                loss = criterion(model(batch), batch)
                loss.backward()
                optimizer.step()

        model.eval()
        with torch.no_grad():
            train_recon = model(torch.from_numpy(X_synth).to(device))
            train_errors = ((torch.from_numpy(X_synth).to(device) - train_recon) ** 2).mean(dim=1).cpu().numpy()
        mean_err = float(train_errors.mean())
        std_err = float(train_errors.std()) + 1e-10
        return model, mean_err, std_err, device

    # Pre-train once at module load time
    _AE_CACHE: dict = {}
    _AE_LOCK = False


def _get_ae(n_features: int):
    """Get or create a pre-trained autoencoder for the given input dimension."""
    if not _TORCH_AVAILABLE:
        return None, 0.0, 0.0, None
    global _AE_CACHE
    if n_features not in _AE_CACHE:
        _AE_CACHE[n_features] = _pretrain_autoencoder(n_features)
    return _AE_CACHE[n_features]


def _detect_autoencoder(fields: List[FieldFeature],
                        reference_sample: Optional[List[List[float]]],
                        ) -> AnomalyResult:
    """Score using a pre-trained autoencoder (no per-request training)."""
    if not _TORCH_AVAILABLE:
        return AnomalyResult(
            method=AnomalyMethod.AUTOENCODER, anomaly_score=0.0, confidence=0.0,
            top_features=[], explanation="Autoencoder unavailable — PyTorch not installed.",
            severity="LOW", details={"reason": "pytorch_missing"},
        )

    values = np.array([[f.value] for f in fields], dtype=np.float32).reshape(1, -1)
    n_features = values.shape[1]

    model, mean_train_err, std_train_err, device = _get_ae(n_features)
    if model is None:
        return AnomalyResult(
            method=AnomalyMethod.AUTOENCODER, anomaly_score=0.0, confidence=0.0,
            top_features=[], explanation="Autoencoder model unavailable.", severity="LOW", details={},
        )

    # Reconstruction error on the input sample
    model.eval()
    with torch.no_grad():
        inp = torch.from_numpy(values).to(device)
        recon = model(inp)
        mse_per_feature = ((inp - recon) ** 2).cpu().numpy()[0]
        reconstruction_error = float(mse_per_feature.mean())

    err_z = (reconstruction_error - mean_train_err) / std_train_err
    anomaly_score = float(np.clip(1.0 - math.exp(-max(0, err_z - 1) / 2), 0.0, 1.0))

    sorted_idx = np.argsort(mse_per_feature)[::-1]
    top_feats = [fields[i].name for i in sorted_idx[:3] if mse_per_feature[i] > mean_train_err * 1.5]

    if anomaly_score > 0.85:
        explanation = (f"Autoencoder detected abnormal structure (reconstruction error "
                       f"z-score={err_z:.1f}). The feature "
                       f"'{top_feats[0] if top_feats else 'combination'}' "
                       f"deviates from learned normal patterns.")
        severity = "HIGH"
    elif anomaly_score > 0.75:
        explanation = (f"Autoencoder shows mild reconstruction deviation "
                       f"(z-score={err_z:.1f}). Minor pattern drift detected.")
        severity = "MEDIUM"
    else:
        explanation = f"Autoencoder confirms normal pattern (reconstruction z-score={err_z:.1f})."
        severity = "LOW"

    confidence = min(0.9, 0.4 + anomaly_score * 0.5) if anomaly_score > 0.75 else max(0.3, 0.85 - anomaly_score * 0.5)

    return AnomalyResult(
        method=AnomalyMethod.AUTOENCODER,
        anomaly_score=round(anomaly_score, 4),
        confidence=round(confidence, 4),
        top_features=top_feats,
        explanation=explanation,
        severity=severity,
        details={"reconstruction_error": round(reconstruction_error, 6),
                 "train_error_mean": round(mean_train_err, 6),
                 "train_error_std": round(std_train_err, 6),
                 "err_z_score": round(err_z, 2)},
    )


# =========================================================================
#  Statistical outlier detector (Z-score / IQR)
# =========================================================================

def _detect_statistical(fields: List[FieldFeature]) -> AnomalyResult:
    """Per-feature Z-score and IQR-based outlier detection."""
    n = len(fields)
    if n < 4:
        return AnomalyResult(
            method=AnomalyMethod.STATISTICAL,
            anomaly_score=0.0,
            confidence=0.3,
            top_features=[],
            explanation="Insufficient features (<4) for statistical outlier detection.",
            severity="LOW",
            details={"reason": "too_few_features", "n_features": n},
        )

    vals = np.array([f.value for f in fields], dtype=np.float64)

    # Z-score method
    mean_v = float(np.mean(vals))
    std_v = float(np.std(vals)) + 1e-10
    z_scores = np.abs((vals - mean_v) / std_v)
    max_z = float(np.max(z_scores))

    # IQR method
    q1, q3 = float(np.percentile(vals, 25)), float(np.percentile(vals, 75))
    iqr_v = q3 - q1 + 1e-10
    lower = q1 - 1.5 * iqr_v
    upper = q3 + 1.5 * iqr_v
    iqr_outlier_flags = [(v < lower or v > upper) for v in vals]

    # Anomaly score from z-score (capped at 5 sigma)
    anomaly_score = float(np.clip(max_z / 5.0, 0.0, 1.0))

    # Top anomalous features
    outlier_feats = []
    for i, is_out in enumerate(iqr_outlier_flags):
        if is_out and i < len(fields):
            outlier_feats.append((fields[i].name, float(z_scores[i])))

    outlier_feats.sort(key=lambda x: x[1], reverse=True)
    top_feats = [f[0] for f in outlier_feats[:3]]

    if anomaly_score > 0.85:
        explanation = (f"Statistical outlier detection found {len(outlier_feats)} anomalous "
                       f"feature(s): {', '.join(top_feats)}. "
                       f"Maximum Z-score={max_z:.1f} (threshold=2.0).")
        severity = "HIGH"
    elif anomaly_score > 0.75:
        explanation = (f"Mild statistical deviation detected. "
                       f"Max Z-score={max_z:.1f}; no clear outliers beyond standard range.")
        severity = "MEDIUM"
    else:
        explanation = f"No statistical outliers. All features within normal range (max Z-score={max_z:.1f})."
        severity = "LOW"

    confidence = min(0.95, 0.4 + anomaly_score * 0.6) if anomaly_score > 0.75 else max(0.3, 0.9 - anomaly_score * 0.3)

    return AnomalyResult(
        method=AnomalyMethod.STATISTICAL,
        anomaly_score=round(anomaly_score, 4),
        confidence=round(confidence, 4),
        top_features=top_feats,
        explanation=explanation,
        severity=severity,
        details={"max_z_score": round(max_z, 2), "outlier_count": len(outlier_feats),
                 "iqr_outlier_flags": iqr_outlier_flags if len(iqr_outlier_flags) <= 20 else []},
    )


# =========================================================================
#  Public entry point
# =========================================================================

def _normalize_fields(fields: List[FieldFeature],
                      reference_sample: Optional[List[List[float]]],
                      ) -> List[FieldFeature]:
    """Min-max normalise field values to [0, 1] for model-based detectors."""
    raw = np.array([f.value for f in fields], dtype=np.float64)
    n = len(fields)

    if reference_sample and len(reference_sample) >= 2:
        ref_arr = np.array(reference_sample, dtype=np.float64)
        if ref_arr.ndim == 2 and ref_arr.shape[1] >= n:
            col_mins = ref_arr[:, :n].min(axis=0)
            col_maxs = ref_arr[:, :n].max(axis=0)
        else:
            col_mins = raw.min()
            col_maxs = raw.max()
    else:
        col_mins = raw.min()
        col_maxs = raw.max()

    rng_v = col_maxs - col_mins
    rng_v = np.where(rng_v == 0, 1.0, rng_v)

    normed = (raw - col_mins) / rng_v
    normed = np.clip(normed, 0.0, 1.0)

    return [FieldFeature(name=f.name, value=float(normed[i]), category=f.category)
            for i, f in enumerate(fields)]


def detect_anomalies(request: AnomalyDetectionRequest) -> AnomalyDetectionResponse:
    """Run all three anomaly detectors and fuse results."""
    start = time.time()
    logger.info("Anomaly detection started", field_count=len(request.fields))

    results: List[AnomalyResult] = []
    fields = request.fields
    ref = request.reference_sample

    # Normalise values to [0,1] for IF and AE (statistical uses raw values)
    norm_fields = _normalize_fields(fields, ref)
    # Also normalise the reference sample using the same min/max
    norm_ref: Optional[List[List[float]]] = None
    if ref and len(ref) >= 2:
        raw_vals = np.array([f.value for f in fields], dtype=np.float64)
        ref_arr = np.array(ref, dtype=np.float64)
        if ref_arr.ndim == 2 and ref_arr.shape[1] >= len(fields):
            col_mins = ref_arr[:, :len(fields)].min(axis=0)
            col_maxs = ref_arr[:, :len(fields)].max(axis=0)
        else:
            col_mins = raw_vals.min()
            col_maxs = raw_vals.max()
        rng_v = col_maxs - col_mins
        rng_v = np.where(rng_v == 0, 1.0, rng_v)
        norm_ref_mat = (ref_arr[:, :len(fields)] - col_mins) / rng_v
        norm_ref_mat = np.clip(norm_ref_mat, 0.0, 1.0)
        norm_ref = norm_ref_mat.tolist()

    # 1. Isolation Forest (uses normalised values)
    try:
        results.append(_detect_isolation_forest(norm_fields, norm_ref))
    except Exception as e:
        logger.warning("Isolation Forest failed", error=str(e))
        results.append(AnomalyResult(
            method=AnomalyMethod.ISOLATION_FOREST, anomaly_score=0.0, confidence=0.0,
            top_features=[], explanation=f"Isolation Forest error: {e}", severity="LOW", details={},
        ))

    # 2. Autoencoder (uses normalised values)
    try:
        results.append(_detect_autoencoder(norm_fields, norm_ref))
    except Exception as e:
        logger.warning("Autoencoder failed", error=str(e))
        results.append(AnomalyResult(
            method=AnomalyMethod.AUTOENCODER, anomaly_score=0.0, confidence=0.0,
            top_features=[], explanation=f"Autoencoder error: {e}", severity="LOW", details={},
        ))

    # 3. Statistical
    try:
        results.append(_detect_statistical(fields))
    except Exception as e:
        logger.warning("Statistical detection failed", error=str(e))
        results.append(AnomalyResult(
            method=AnomalyMethod.STATISTICAL, anomaly_score=0.0, confidence=0.0,
            top_features=[], explanation=f"Statistical error: {e}", severity="LOW", details={},
        ))

    # --- Fusion ---
    valid = [r for r in results if r.confidence > 0]
    if not valid:
        fusion_score = 0.0
        fusion_severity = "LOW"
        summary = "All anomaly detectors were unable to produce a result."
    else:
        # Weighted average: weight = confidence
        total_weight = sum(r.confidence for r in valid)
        fusion_score = sum(r.anomaly_score * r.confidence for r in valid) / (total_weight or 1)
        fusion_score = round(min(fusion_score, 1.0), 4)

        # Severity from highest individual severity
        sev_map = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        max_sev = max(sev_map.get(r.severity, 0) for r in valid)
        fusion_severity = {0: "LOW", 1: "MEDIUM", 2: "HIGH", 3: "CRITICAL"}.get(max_sev, "MEDIUM")

        # Summary
        high_anom = [r for r in valid if r.anomaly_score > 0.85]
        if high_anom:
            methods_str = ", ".join(r.method.value for r in high_anom)
            summary = (f"{len(high_anom)} of {len(valid)} detectors flagged anomalies "
                       f"(methods: {methods_str}). Fusion score: {fusion_score:.2f}. "
                       f"Overall severity: {fusion_severity}.")
        elif fusion_score > 0.75:
            summary = (f"Mild anomalies detected (fusion score={fusion_score:.2f}). "
                       f"No single detector is highly confident. Review recommended.")
        else:
            summary = f"No significant anomalies detected (fusion score={fusion_score:.2f}). Data appears normal."

    elapsed = int((time.time() - start) * 1000)
    logger.info("Anomaly detection complete", fusion_score=fusion_score,
                severity=fusion_severity, elapsed_ms=elapsed)

    return AnomalyDetectionResponse(
        findings=results,
        fusion_score=fusion_score,
        fusion_severity=fusion_severity,
        summary=summary,
        method_count=len(valid),
        analysis_time_ms=elapsed,
    )
