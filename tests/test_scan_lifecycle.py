from datetime import datetime
from types import SimpleNamespace

import numpy as np
import pytest

from app.models.db import RiskLevelEnum
from app.services.embedding_service import EMBEDDING_DIM
from app.services.scan_processing import scan_to_detail, scan_to_recent
from app.services.similarity_service import SimilarityService
from app.tasks.celery_app import celery_app
import app.tasks.scans  # noqa: F401


def test_pending_scan_is_retrievable_from_database_shape():
    created_at = datetime(2026, 6, 10, 12, 0, 0)
    scan = SimpleNamespace(
        scan_id="scan-123",
        url="https://example.com",
        graph_score=0.0,
        model_score=0.0,
        risk=RiskLevelEnum.LOW,
        created_at=created_at,
        meta={
            "status": "pending",
            "scan_type": "url",
            "risk_score": 0.0,
            "threat_level": "low",
            "results": [],
            "threats": [],
        },
    )

    detail = scan_to_detail(scan)
    recent = scan_to_recent(scan)

    assert detail["scan_id"] == "scan-123"
    assert detail["status"] == "pending"
    assert detail["created_at"] == created_at.isoformat()
    assert recent["status"] == "pending"


def test_similarity_service_enforces_model_embedding_dimension():
    assert EMBEDDING_DIM == 64
    assert SimilarityService._validate_embedding(np.zeros(64), "example.com").shape == (64,)

    with pytest.raises(ValueError, match="expected 64, got 32"):
        SimilarityService._validate_embedding(np.zeros(32), "example.com")


def test_scan_task_is_registered_on_consumed_queue():
    assert "app.tasks.scans.process_scan" in celery_app.tasks
    assert celery_app.conf.task_default_queue == "celery"
    assert celery_app.conf.task_routes["app.tasks.scans.process_scan"]["queue"] == "celery"
