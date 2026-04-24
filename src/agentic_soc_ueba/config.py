from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class UEBAConfig:
    minimum_history_events: int = 5
    alert_threshold: float = 65.0
    high_severity_threshold: float = 85.0
    critical_severity_threshold: float = 110.0
    impossible_travel_kmph: float = 900.0
    rare_observation_floor: int = 2
    off_hours_penalty: float = 14.0
    new_entity_penalty: float = 12.0
    impossible_travel_penalty: float = 35.0
    failure_penalty: float = 10.0
    rare_action_penalty: float = 10.0
    rare_resource_penalty: float = 10.0
    metric_anomaly_weight: float = 8.0
    warmup_penalty_scale: float = 0.45
    max_reasons: int = 8
    tracked_numeric_metrics: tuple[str, ...] = field(default_factory=lambda: ("bytes_in", "bytes_out", "records_read"))
