# Agentic SOC UEBA

This repository provides a production-oriented User and Entity Behavior Analytics (UEBA) module designed to plug into a detection agent inside an agentic SOC.

## What It Does

- Builds per-user behavioral baselines from historical activity
- Scores new events for anomalous behavior using explainable signals
- Produces detection payloads suitable for a larger detection pipeline
- Supports baseline snapshot persistence for warm restarts
- Stays dependency-light for easier embedding and operational reliability

## Core Detection Signals

- New IP, device, or geography for a user
- Impossible travel based on known geo coordinates and event timing
- Off-hours access relative to a user's historical pattern
- Rare actions or resources for the user
- Elevated failure rate
- Numeric metric anomalies using online statistics

## Quick Start

```python
from datetime import datetime, timedelta, timezone

from agentic_soc_ueba import GeoPoint, UEBAConfig, UEBAEngine, UEBAEvent

engine = UEBAEngine(UEBAConfig())

history = [
    UEBAEvent(
        event_id=f"evt-{i}",
        timestamp=datetime(2026, 4, 20, 9, 0, tzinfo=timezone.utc) + timedelta(hours=i),
        user_id="alice",
        action="login",
        resource="console",
        status="success",
        source_ip="10.0.0.1",
        device_id="laptop-01",
        geo=GeoPoint(country="IN", city="Bengaluru", latitude=12.9716, longitude=77.5946),
    )
    for i in range(10)
]

engine.train(history)

result = engine.evaluate_event(
    UEBAEvent(
        event_id="evt-alert",
        timestamp=datetime(2026, 4, 21, 2, 0, tzinfo=timezone.utc),
        user_id="alice",
        action="download",
        resource="sensitive-bucket",
        status="failure",
        source_ip="203.0.113.10",
        device_id="unknown-device",
        geo=GeoPoint(country="US", city="New York", latitude=40.7128, longitude=-74.0060),
        numeric_metrics={"bytes_out": 25_000_000},
    )
)

if result.alert:
    print(result.alert.score, result.alert.severity)
    for reason in result.alert.reasons:
        print(reason.code, reason.score, reason.description)
```

## Repository Layout

- `src/agentic_soc_ueba/config.py`: runtime tuning and thresholds
- `src/agentic_soc_ueba/models.py`: event and alert schemas
- `src/agentic_soc_ueba/baseline.py`: baseline state and persistence
- `src/agentic_soc_ueba/engine.py`: scoring engine and detection flow
- `src/agentic_soc_ueba/integrations.py`: detection-agent friendly payload conversion
- `tests/`: unit tests for the core detection logic

## Running Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```
