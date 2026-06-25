"""
Pipeline Timeline Recorder.

Records start time, end time, and duration for each pipeline stage.
Returns a list of stage timings for diagnostic and frontend animation use.
"""
import time
import structlog
from typing import Any, Dict, List, Optional

logger = structlog.get_logger(__name__)

STAGE_NAMES = [
    "Upload",
    "Metadata",
    "OCR",
    "Authenticity",
    "Financial",
    "AML",
    "Compliance",
    "Risk",
    "Decision",
]


class TimelineRecorder:
    """Simple context-manager-friendly timeline recorder."""

    def __init__(self) -> None:
        self._stages: List[Dict[str, Any]] = []
        self._current: Optional[Dict[str, Any]] = None
        self._warnings: Dict[str, List[str]] = {}
        self._errors: Dict[str, List[str]] = {}

    def start_stage(self, name: str) -> None:
        """Start timing a pipeline stage."""
        self._current = {
            "name": name,
            "start": time.time(),
            "status": "RUNNING",
        }
        # Initialize tracking for this stage
        self._warnings.setdefault(name, [])
        self._errors.setdefault(name, [])

    def end_stage(self, status: str = "SUCCESS") -> None:
        """End timing for the current stage."""
        if self._current is None:
            return
        end = time.time()
        duration_ms = round((end - self._current["start"]) * 1000, 2)
        name = self._current["name"]
        self._stages.append({
            "name": name,
            "duration_ms": duration_ms,
            "status": status,
        })
        self._current = None

    def fail_stage(self) -> None:
        """Mark the current stage as failed."""
        self.end_stage(status="FAILED")

    def record_warning(self, stage: str, warning: str) -> None:
        """Record a non-fatal warning for a stage."""
        self._warnings.setdefault(stage, []).append(warning)

    def record_error(self, stage: str, error: str) -> None:
        """Record an error for a stage."""
        self._errors.setdefault(stage, []).append(error)

    @property
    def stages(self) -> List[Dict[str, Any]]:
        return list(self._stages)

    def get_timeline(self) -> List[Dict[str, Any]]:
        """Return the ordered timeline of stages."""
        return self._stages

    def get_module_health(self) -> List[Dict[str, Any]]:
        """Return module health report (diagnostic view)."""
        return [
            {
                "name": s["name"],
                "status": "PASS" if s["status"] == "SUCCESS" else "FAIL",
                "time_ms": s["duration_ms"],
                "warnings": len(self._warnings.get(s["name"], [])),
                "errors": (0 if s["status"] == "SUCCESS" else 1) + len(self._errors.get(s["name"], [])),
            }
            for s in self._stages
        ]

    def record_stage_metrics(self, name: str, warnings: int = 0, errors: int = 0) -> None:
        """Convenience to record warning/error counts for a stage."""
        if warnings:
            self._warnings.setdefault(name, []).append(f"{warnings} warning(s)")
        if errors:
            self._errors.setdefault(name, []).append(f"{errors} error(s)")

    def get_pipeline_progress(self) -> List[Dict[str, Any]]:
        """Return pipeline progress metadata for frontend animation."""
        completed_names = {s["name"] for s in self._stages}
        return [
            {
                "name": name,
                "completed": name in completed_names,
                "status": next(
                    (s["status"] for s in self._stages if s["name"] == name),
                    "PENDING",
                ),
            }
            for name in STAGE_NAMES
        ]


def create_timeline_recorder() -> TimelineRecorder:
    """Factory function for TimelineRecorder."""
    return TimelineRecorder()
