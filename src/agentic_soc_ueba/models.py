from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class GeoPoint:
    country: str
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None

    @property
    def label(self) -> str:
        if self.city:
            return f"{self.country}:{self.city}"
        return self.country


@dataclass
class UEBAEvent:
    event_id: str
    timestamp: datetime
    user_id: str
    action: str
    resource: str
    status: str
    source_ip: str | None = None
    device_id: str | None = None
    geo: GeoPoint | None = None
    labels: dict[str, str] = field(default_factory=dict)
    numeric_metrics: dict[str, float] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskReason:
    code: str
    score: float
    description: str
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionAlert:
    event_id: str
    user_id: str
    score: float
    severity: str
    reasons: list[RiskReason]
    created_at: datetime
