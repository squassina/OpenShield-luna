import math
from collections import Counter
from threading import Lock

DEFAULT_MAX_METRIC_SERIES = 4096
DROPPED_SAMPLES_METRIC = "openshield_metrics_samples_dropped_total"


class MetricsRegistry:
    """Process-local Prometheus counters and gauges with a hard series limit."""

    def __init__(self, *, max_series: int = DEFAULT_MAX_METRIC_SERIES) -> None:
        if (
            isinstance(max_series, bool)
            or not isinstance(max_series, int)
            or max_series < 1
        ):
            raise ValueError("max_series must be a positive integer")
        self._max_series = max_series
        self._counters: Counter[tuple[str, tuple[tuple[str, str], ...]]] = Counter()
        self._gauges: dict[tuple[str, tuple[tuple[str, str], ...]], int | float] = {}
        self._metric_types: dict[str, str] = {}
        self._dropped_samples = 0
        self._lock = Lock()

    def _register_series(
        self,
        name: str,
        labels: dict[str, str] | None,
        metric_type: str,
    ) -> tuple[str, tuple[tuple[str, str], ...]] | None:
        if name == DROPPED_SAMPLES_METRIC:
            raise ValueError(f"{DROPPED_SAMPLES_METRIC} is reserved for registry overflow")
        key = (name, tuple(sorted((labels or {}).items())))
        if key in self._counters or key in self._gauges:
            if self._metric_types[name] != metric_type:
                raise ValueError(
                    f"Metric {name} is already registered as {self._metric_types[name]}"
                )
            return key

        existing_type = self._metric_types.get(name)
        if existing_type is not None and existing_type != metric_type:
            raise ValueError(f"Metric {name} is already registered as {existing_type}")
        if len(self._counters) + len(self._gauges) >= self._max_series:
            self._dropped_samples += 1
            return None

        self._metric_types[name] = metric_type
        return key

    def increment(self, name: str, labels: dict[str, str] | None = None) -> None:
        with self._lock:
            key = self._register_series(name, labels, "counter")
            if key is not None:
                self._counters[key] += 1

    def set_counter(
        self,
        name: str,
        value: int,
        labels: dict[str, str] | None = None,
    ) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("Counter value must be a non-negative integer")
        with self._lock:
            key = self._register_series(name, labels, "counter")
            if key is not None:
                self._counters[key] = value

    def set_gauge(
        self,
        name: str,
        value: float,
        labels: dict[str, str] | None = None,
    ) -> None:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            raise ValueError("Gauge value must be a finite number")
        with self._lock:
            key = self._register_series(name, labels, "gauge")
            if key is not None:
                self._gauges[key] = value

    def render(self) -> str:
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
            metric_types = dict(self._metric_types)
            if self._dropped_samples:
                counters[(DROPPED_SAMPLES_METRIC, ())] = self._dropped_samples
                metric_types[DROPPED_SAMPLES_METRIC] = "counter"

        lines = []
        for name in sorted(metric_types):
            lines.extend(
                [
                    f"# HELP {name} OpenShield process metric.",
                    f"# TYPE {name} {metric_types[name]}",
                ]
            )
            samples = counters if metric_types[name] == "counter" else gauges
            entries = sorted(
                (labels, value)
                for (metric_name, labels), value in samples.items()
                if metric_name == name
            )
            for labels, value in entries:
                if labels:
                    rendered = ",".join(
                        f'{key}="{self._escape(value)}"' for key, value in labels
                    )
                    lines.append(f"{name}{{{rendered}}} {value}")
                else:
                    lines.append(f"{name} {value}")
        return "\n".join(lines) + ("\n" if lines else "")

    @staticmethod
    def _escape(value: str) -> str:
        return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')
