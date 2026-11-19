import math
import re
from threading import Lock

_METRIC_NAME = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")
_LABEL_NAME = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


class MetricsRegistry:
    """Thread-safe process-local Prometheus registry with a strict series cap."""

    def __init__(self, max_series: int = 4096) -> None:
        if isinstance(max_series, bool) or not isinstance(max_series, int) or max_series < 1:
            raise ValueError("Metric series limit must be a positive integer")
        self._max_series = max_series
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], int] = {}
        self._gauges: dict[tuple[str, tuple[tuple[str, str], ...]], int | float] = {}
        self._types: dict[str, str] = {}
        self._overflow_total = 0
        self._lock = Lock()

    @staticmethod
    def _key(
        name: str, labels: dict[str, str] | None,
    ) -> tuple[str, tuple[tuple[str, str], ...]]:
        if not isinstance(name, str) or not _METRIC_NAME.fullmatch(name):
            raise ValueError("Invalid Prometheus metric name")
        normalized = labels or {}
        if not isinstance(normalized, dict) or len(normalized) > 8:
            raise ValueError("Prometheus metrics support at most eight labels")
        items: list[tuple[str, str]] = []
        for key, value in normalized.items():
            if (
                not isinstance(key, str)
                or not _LABEL_NAME.fullmatch(key)
                or key == "__name__"
                or not isinstance(value, str)
                or len(value) > 128
            ):
                raise ValueError("Invalid Prometheus label")
            items.append((key, value))
        return name, tuple(sorted(items))

    def _register_series_locked(
        self,
        key: tuple[str, tuple[tuple[str, str], ...]],
        kind: str,
    ) -> bool:
        name = key[0]
        existing_kind = self._types.get(name)
        if existing_kind is not None and existing_kind != kind:
            raise ValueError(f"Metric {name} cannot be both a counter and a gauge")
        if key in self._counters or key in self._gauges:
            return True
        if len(self._counters) + len(self._gauges) >= self._max_series:
            self._overflow_total += 1
            return False
        self._types[name] = kind
        return True

    def increment(self, name: str, labels: dict[str, str] | None = None) -> None:
        key = self._key(name, labels)
        with self._lock:
            if self._register_series_locked(key, "counter"):
                self._counters[key] = self._counters.get(key, 0) + 1

    def set_gauge(
        self, name: str, value: int | float, labels: dict[str, str] | None = None,
    ) -> None:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            raise ValueError("Gauge value must be a finite number")
        key = self._key(name, labels)
        with self._lock:
            if self._register_series_locked(key, "gauge"):
                self._gauges[key] = value

    def render(self) -> str:
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
            metric_types = dict(self._types)
            overflow_total = self._overflow_total

        lines: list[str] = []
        for name in sorted(metric_types):
            kind = metric_types[name]
            values = counters if kind == "counter" else gauges
            lines.extend([
                f"# HELP {name} OpenShield process metric.",
                f"# TYPE {name} {kind}",
            ])
            entries = sorted(
                (labels, value)
                for (metric_name, labels), value in values.items()
                if metric_name == name
            )
            for labels, value in entries:
                if labels:
                    rendered = ",".join(
                        f'{key}="{self._escape(label_value)}"'
                        for key, label_value in labels
                    )
                    lines.append(f"{name}{{{rendered}}} {value}")
                else:
                    lines.append(f"{name} {value}")

        if overflow_total:
            name = "openshield_metrics_series_overflow_total"
            lines.extend([
                f"# HELP {name} Number of metric series rejected by the registry cap.",
                f"# TYPE {name} counter",
                f"{name} {overflow_total}",
            ])
        return "\n".join(lines) + ("\n" if lines else "")

    @staticmethod
    def _escape(value: str) -> str:
        return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')
