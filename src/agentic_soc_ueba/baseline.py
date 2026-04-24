from __future__ import annotations

import json
import math
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from .models import GeoPoint, UEBAEvent


def _normalize_hour(dt: datetime) -> int:
    return dt.hour


def _normalize_weekday(dt: datetime) -> int:
    return dt.weekday()


@dataclass
class RunningStat:
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2

    @property
    def variance(self) -> float:
        if self.count < 2:
            return 0.0
        return self.m2 / (self.count - 1)

    @property
    def stddev(self) -> float:
        return math.sqrt(self.variance)

    def zscore(self, value: float) -> float:
        if self.count < 2 or self.stddev == 0:
            return 0.0
        return (value - self.mean) / self.stddev


@dataclass
class UserBaseline:
    user_id: str
    event_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    hours: Counter[int] = field(default_factory=Counter)
    weekdays: Counter[int] = field(default_factory=Counter)
    ips: Counter[str] = field(default_factory=Counter)
    devices: Counter[str] = field(default_factory=Counter)
    geos: Counter[str] = field(default_factory=Counter)
    actions: Counter[str] = field(default_factory=Counter)
    resources: Counter[str] = field(default_factory=Counter)
    numeric_stats: dict[str, RunningStat] = field(default_factory=dict)
    last_event_at: datetime | None = None
    last_geo: GeoPoint | None = None
    last_geo_at: datetime | None = None

    def observe(self, event: UEBAEvent) -> None:
        self.event_count += 1
        if event.status.lower() == "success":
            self.success_count += 1
        else:
            self.failure_count += 1

        self.hours[_normalize_hour(event.timestamp)] += 1
        self.weekdays[_normalize_weekday(event.timestamp)] += 1
        self.actions[event.action] += 1
        self.resources[event.resource] += 1

        if event.source_ip:
            self.ips[event.source_ip] += 1
        if event.device_id:
            self.devices[event.device_id] += 1
        if event.geo:
            self.geos[event.geo.label] += 1
            self.last_geo = event.geo
            self.last_geo_at = event.timestamp

        for name, value in event.numeric_metrics.items():
            stat = self.numeric_stats.setdefault(name, RunningStat())
            stat.update(value)

        self.last_event_at = event.timestamp

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["hours"] = dict(self.hours)
        payload["weekdays"] = dict(self.weekdays)
        payload["ips"] = dict(self.ips)
        payload["devices"] = dict(self.devices)
        payload["geos"] = dict(self.geos)
        payload["actions"] = dict(self.actions)
        payload["resources"] = dict(self.resources)
        payload["numeric_stats"] = {name: asdict(stat) for name, stat in self.numeric_stats.items()}
        payload["last_event_at"] = self.last_event_at.isoformat() if self.last_event_at else None
        payload["last_geo_at"] = self.last_geo_at.isoformat() if self.last_geo_at else None
        return payload

    @classmethod
    def from_dict(cls, payload: dict) -> "UserBaseline":
        baseline = cls(user_id=payload["user_id"])
        baseline.event_count = payload["event_count"]
        baseline.success_count = payload["success_count"]
        baseline.failure_count = payload["failure_count"]
        baseline.hours = Counter({int(k): v for k, v in payload["hours"].items()})
        baseline.weekdays = Counter({int(k): v for k, v in payload["weekdays"].items()})
        baseline.ips = Counter(payload["ips"])
        baseline.devices = Counter(payload["devices"])
        baseline.geos = Counter(payload["geos"])
        baseline.actions = Counter(payload["actions"])
        baseline.resources = Counter(payload["resources"])
        baseline.numeric_stats = {
            name: RunningStat(**stat_payload) for name, stat_payload in payload["numeric_stats"].items()
        }
        if payload.get("last_event_at"):
            baseline.last_event_at = datetime.fromisoformat(payload["last_event_at"])
        if payload.get("last_geo"):
            baseline.last_geo = GeoPoint(**payload["last_geo"])
        if payload.get("last_geo_at"):
            baseline.last_geo_at = datetime.fromisoformat(payload["last_geo_at"])
        return baseline


@dataclass
class BaselineStore:
    users: dict[str, UserBaseline] = field(default_factory=dict)

    def get_or_create(self, user_id: str) -> UserBaseline:
        baseline = self.users.get(user_id)
        if baseline is None:
            baseline = UserBaseline(user_id=user_id)
            self.users[user_id] = baseline
        return baseline

    def observe(self, event: UEBAEvent) -> UserBaseline:
        baseline = self.get_or_create(event.user_id)
        baseline.observe(event)
        return baseline

    def snapshot(self, path: str | Path) -> None:
        payload = {user_id: baseline.to_dict() for user_id, baseline in self.users.items()}
        Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "BaselineStore":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        store = cls()
        store.users = {user_id: UserBaseline.from_dict(data) for user_id, data in payload.items()}
        return store
