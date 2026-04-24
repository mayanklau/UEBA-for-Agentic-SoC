from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from datetime import datetime, timezone

from .baseline import BaselineStore, UserBaseline
from .config import UEBAConfig
from .models import DetectionAlert, GeoPoint, RiskReason, UEBAEvent

logger = logging.getLogger(__name__)


def _haversine_km(first: GeoPoint, second: GeoPoint) -> float | None:
    if None in (first.latitude, first.longitude, second.latitude, second.longitude):
        return None

    lat1 = math.radians(first.latitude)
    lon1 = math.radians(first.longitude)
    lat2 = math.radians(second.latitude)
    lon2 = math.radians(second.longitude)

    d_lat = lat2 - lat1
    d_lon = lon2 - lon1

    a = math.sin(d_lat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(d_lon / 2) ** 2
    return 6371.0 * 2 * math.asin(math.sqrt(a))


@dataclass
class EvaluationResult:
    event: UEBAEvent
    score: float
    reasons: list[RiskReason]
    alert: DetectionAlert | None


class UEBAEngine:
    def __init__(self, config: UEBAConfig, baseline_store: BaselineStore | None = None) -> None:
        self.config = config
        self.baselines = baseline_store or BaselineStore()

    def train(self, events: list[UEBAEvent]) -> None:
        for event in sorted(events, key=lambda item: item.timestamp):
            self.baselines.observe(event)

    def evaluate_event(self, event: UEBAEvent, learn_after: bool = True) -> EvaluationResult:
        baseline = self.baselines.get_or_create(event.user_id)
        reasons = self._score_event(event, baseline)
        score = round(sum(reason.score for reason in reasons), 2)
        alert = None

        if score >= self.config.alert_threshold:
            alert = DetectionAlert(
                event_id=event.event_id,
                user_id=event.user_id,
                score=score,
                severity=self._severity(score),
                reasons=reasons[: self.config.max_reasons],
                created_at=datetime.now(timezone.utc),
            )

        if learn_after:
            self.baselines.observe(event)

        return EvaluationResult(event=event, score=score, reasons=reasons, alert=alert)

    def snapshot(self, path: str) -> None:
        self.baselines.snapshot(path)

    @classmethod
    def from_snapshot(cls, config: UEBAConfig, path: str) -> "UEBAEngine":
        return cls(config=config, baseline_store=BaselineStore.load(path))

    def _severity(self, score: float) -> str:
        if score >= self.config.critical_severity_threshold:
            return "critical"
        if score >= self.config.high_severity_threshold:
            return "high"
        return "medium"

    def _score_event(self, event: UEBAEvent, baseline: UserBaseline) -> list[RiskReason]:
        reasons: list[RiskReason] = []
        warm = baseline.event_count >= self.config.minimum_history_events
        scale = 1.0 if warm else self.config.warmup_penalty_scale

        reasons.extend(self._score_novel_entities(event, baseline, scale))
        reasons.extend(self._score_time_anomalies(event, baseline, scale))
        reasons.extend(self._score_behavior_anomalies(event, baseline, scale))
        reasons.extend(self._score_metric_anomalies(event, baseline, scale))
        reasons.extend(self._score_failure_anomalies(event, baseline, scale))

        reasons.sort(key=lambda item: item.score, reverse=True)
        return reasons

    def _score_novel_entities(self, event: UEBAEvent, baseline: UserBaseline, scale: float) -> list[RiskReason]:
        reasons: list[RiskReason] = []

        if event.source_ip and baseline.event_count and event.source_ip not in baseline.ips:
            reasons.append(
                RiskReason(
                    code="new_ip",
                    score=self.config.new_entity_penalty * scale,
                    description=f"User logged in from a new IP address: {event.source_ip}.",
                    context={"source_ip": event.source_ip},
                )
            )

        if event.device_id and baseline.event_count and event.device_id not in baseline.devices:
            reasons.append(
                RiskReason(
                    code="new_device",
                    score=self.config.new_entity_penalty * scale,
                    description=f"User used a new device: {event.device_id}.",
                    context={"device_id": event.device_id},
                )
            )

        if event.geo and baseline.event_count and event.geo.label not in baseline.geos:
            reasons.append(
                RiskReason(
                    code="new_geo",
                    score=self.config.new_entity_penalty * scale,
                    description=f"User activity originated from a new geography: {event.geo.label}.",
                    context={"geo": event.geo.label},
                )
            )

        if event.geo and baseline.last_geo and baseline.last_geo_at and baseline.last_geo.label != event.geo.label:
            distance = _haversine_km(baseline.last_geo, event.geo)
            delta_hours = (event.timestamp - baseline.last_geo_at).total_seconds() / 3600
            if distance is not None and delta_hours > 0:
                speed = distance / delta_hours
                if speed > self.config.impossible_travel_kmph:
                    reasons.append(
                        RiskReason(
                            code="impossible_travel",
                            score=self.config.impossible_travel_penalty * scale,
                            description="User would need to travel at an implausible speed between consecutive locations.",
                            context={
                                "from_geo": baseline.last_geo.label,
                                "to_geo": event.geo.label,
                                "distance_km": round(distance, 2),
                                "required_speed_kmph": round(speed, 2),
                            },
                        )
                    )

        return reasons

    def _score_time_anomalies(self, event: UEBAEvent, baseline: UserBaseline, scale: float) -> list[RiskReason]:
        if baseline.event_count < self.config.minimum_history_events:
            return []

        hour_count = baseline.hours.get(event.timestamp.hour, 0)
        weekday_count = baseline.weekdays.get(event.timestamp.weekday(), 0)

        reasons: list[RiskReason] = []
        if hour_count < self.config.rare_observation_floor:
            reasons.append(
                RiskReason(
                    code="off_hours",
                    score=self.config.off_hours_penalty * scale,
                    description=f"User activity occurred in a rarely observed hour: {event.timestamp.hour:02d}:00.",
                    context={"hour": event.timestamp.hour, "observations": hour_count},
                )
            )

        if weekday_count == 0:
            reasons.append(
                RiskReason(
                    code="rare_weekday",
                    score=(self.config.off_hours_penalty - 4.0) * scale,
                    description="User activity occurred on a previously unseen weekday.",
                    context={"weekday": event.timestamp.weekday()},
                )
            )
        return reasons

    def _score_behavior_anomalies(self, event: UEBAEvent, baseline: UserBaseline, scale: float) -> list[RiskReason]:
        reasons: list[RiskReason] = []

        if baseline.event_count >= self.config.minimum_history_events:
            action_count = baseline.actions.get(event.action, 0)
            if action_count < self.config.rare_observation_floor:
                reasons.append(
                    RiskReason(
                        code="rare_action",
                        score=self.config.rare_action_penalty * scale,
                        description=f"User performed a rare action: {event.action}.",
                        context={"action": event.action, "observations": action_count},
                    )
                )

            resource_count = baseline.resources.get(event.resource, 0)
            if resource_count < self.config.rare_observation_floor:
                reasons.append(
                    RiskReason(
                        code="rare_resource",
                        score=self.config.rare_resource_penalty * scale,
                        description=f"User accessed a rare resource: {event.resource}.",
                        context={"resource": event.resource, "observations": resource_count},
                    )
                )
        return reasons

    def _score_metric_anomalies(self, event: UEBAEvent, baseline: UserBaseline, scale: float) -> list[RiskReason]:
        reasons: list[RiskReason] = []
        for metric_name, value in event.numeric_metrics.items():
            stat = baseline.numeric_stats.get(metric_name)
            if stat is None or stat.count < self.config.minimum_history_events:
                continue

            zscore = stat.zscore(value)
            if zscore >= 2.5:
                score = max(0.0, zscore - 2.0) * self.config.metric_anomaly_weight * scale
                reasons.append(
                    RiskReason(
                        code="metric_spike",
                        score=round(score, 2),
                        description=f"User generated an anomalous value for {metric_name}.",
                        context={
                            "metric": metric_name,
                            "value": value,
                            "mean": round(stat.mean, 2),
                            "stddev": round(stat.stddev, 2),
                            "zscore": round(zscore, 2),
                        },
                    )
                )
        return reasons

    def _score_failure_anomalies(self, event: UEBAEvent, baseline: UserBaseline, scale: float) -> list[RiskReason]:
        if event.status.lower() == "success":
            return []

        reasons = [
            RiskReason(
                code="failure_event",
                score=self.config.failure_penalty * scale,
                description="Current activity resulted in a failure.",
                context={"status": event.status},
            )
        ]

        if baseline.event_count >= self.config.minimum_history_events:
            failure_rate = baseline.failure_count / max(1, baseline.event_count)
            if failure_rate < 0.15:
                reasons.append(
                    RiskReason(
                        code="failure_rate_shift",
                        score=(self.config.failure_penalty + 4.0) * scale,
                        description="User has historically low failure rates, making the current failure more suspicious.",
                        context={"historical_failure_rate": round(failure_rate, 4)},
                    )
                )
        return reasons
