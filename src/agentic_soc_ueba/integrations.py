from __future__ import annotations

from .engine import EvaluationResult


def to_detection_payload(result: EvaluationResult) -> dict:
    return {
        "kind": "ueba_detection",
        "event_id": result.event.event_id,
        "user_id": result.event.user_id,
        "score": result.score,
        "triggered": result.alert is not None,
        "severity": result.alert.severity if result.alert else None,
        "reasons": [
            {
                "code": reason.code,
                "score": reason.score,
                "description": reason.description,
                "context": reason.context,
            }
            for reason in result.reasons
        ],
        "event": {
            "action": result.event.action,
            "resource": result.event.resource,
            "status": result.event.status,
            "source_ip": result.event.source_ip,
            "device_id": result.event.device_id,
            "geo": result.event.geo.label if result.event.geo else None,
            "numeric_metrics": result.event.numeric_metrics,
            "labels": result.event.labels,
        },
    }
