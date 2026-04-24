from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from agentic_soc_ueba import GeoPoint, UEBAConfig, UEBAEngine, UEBAEvent
from agentic_soc_ueba.integrations import to_detection_payload


class UEBAEngineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.config = UEBAConfig(alert_threshold=40.0)
        self.engine = UEBAEngine(self.config)
        self.home_geo = GeoPoint(country="IN", city="Bengaluru", latitude=12.9716, longitude=77.5946)
        self.base_time = datetime(2026, 4, 20, 9, 0, tzinfo=timezone.utc)

        history = []
        for index in range(8):
            history.append(
                UEBAEvent(
                    event_id=f"hist-{index}",
                    timestamp=self.base_time + timedelta(hours=index),
                    user_id="alice",
                    action="login",
                    resource="console",
                    status="success",
                    source_ip="10.0.0.1",
                    device_id="laptop-01",
                    geo=self.home_geo,
                    numeric_metrics={"bytes_out": 1000 + (index * 10)},
                )
            )
        self.engine.train(history)

    def test_flags_high_risk_behavior(self) -> None:
        suspicious = UEBAEvent(
            event_id="evt-1",
            timestamp=self.base_time + timedelta(hours=9),
            user_id="alice",
            action="download",
            resource="finance-bucket",
            status="failure",
            source_ip="198.51.100.25",
            device_id="unknown-device",
            geo=GeoPoint(country="US", city="New York", latitude=40.7128, longitude=-74.0060),
            numeric_metrics={"bytes_out": 9000000},
        )

        result = self.engine.evaluate_event(suspicious, learn_after=False)

        self.assertIsNotNone(result.alert)
        self.assertGreaterEqual(result.score, self.config.alert_threshold)
        self.assertEqual(result.alert.severity, "critical")
        codes = {reason.code for reason in result.reasons}
        self.assertIn("new_ip", codes)
        self.assertIn("new_device", codes)
        self.assertIn("new_geo", codes)
        self.assertIn("impossible_travel", codes)
        self.assertIn("metric_spike", codes)

    def test_snapshot_round_trip(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json") as handle:
            self.engine.snapshot(handle.name)
            loaded = UEBAEngine.from_snapshot(self.config, handle.name)

        event = UEBAEvent(
            event_id="evt-2",
            timestamp=self.base_time + timedelta(days=1, hours=2),
            user_id="alice",
            action="login",
            resource="console",
            status="success",
            source_ip="10.0.0.1",
            device_id="laptop-01",
            geo=self.home_geo,
        )
        result = loaded.evaluate_event(event, learn_after=False)
        self.assertLess(result.score, self.config.alert_threshold)

    def test_detection_payload_shape(self) -> None:
        suspicious = UEBAEvent(
            event_id="evt-3",
            timestamp=self.base_time + timedelta(hours=9),
            user_id="alice",
            action="download",
            resource="finance-bucket",
            status="failure",
            source_ip="198.51.100.25",
            device_id="unknown-device",
            geo=GeoPoint(country="US", city="New York", latitude=40.7128, longitude=-74.0060),
            numeric_metrics={"bytes_out": 9000000},
        )
        result = self.engine.evaluate_event(suspicious, learn_after=False)
        payload = to_detection_payload(result)

        self.assertEqual(payload["kind"], "ueba_detection")
        self.assertTrue(payload["triggered"])
        self.assertEqual(payload["user_id"], "alice")
        self.assertIsInstance(payload["reasons"], list)


if __name__ == "__main__":
    unittest.main()
