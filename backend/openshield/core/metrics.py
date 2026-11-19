from collections import Counter
import re
from threading import Lock


_METRIC_NAME = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")
_LABEL_NAME = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
_DROPPED_SERIES_METRIC = "openshield_metrics_series_dropped_total"


class MetricsRegistry:
    """Thread-safe Prometheus registry with bounded series and label sizes."""

    def __init__(self, max_series: int = 1024) -> None:
        if max_series < 1:
            raise ValueError("max_series must be positive")
        self.max_series = max_series
        self._counters: Counter[tuple[str, tuple[tuple[str, str], ...]]] = Counter()
        self._gauges: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
        self._types: dict[str, str] = {}
        self._dropped_series = 0
        self._lock = Lock()

    def _key(
        self, name: str, labels: dict[str, str] | None,
    ) -> tuple[str, tuple[tuple[str, str], ...]] | None:
        if not _METRIC_NAME.fullmatch(name):
            return None
        normalized = tuple(sorted((str(key), str(value)) for key, value in (labels or {}).items()))
        if len(normalized) > 8:
            return None
        if any(
            not _LABEL_NAME.fullmatch(key)
            or key.startswith("__")
            or len(value) > 128
            for key, value in normalized
        ):
            return None
        return name, normalized

    def _reserve(
        self,
        key: tuple[str, tuple[tuple[str, str], ...]],
        metric_type: str,
        existing: bool,
    ) -> bool:
        name = key[0]
        current_type = self._types.get(name)
        if current_type is not None and current_type != metric_type:
            self._dropped_series += 1
            return False
        if not existing and len(self._types) + self._series_count() >= self.max_series:
            self._dropped_series += 1
            return False
        self._types[name] = metric_type
        return True

    def _series_count(self) -> int:
        return len(self._counters) + len(self._gauges)

    def increment(self, name: str, labels: dict[str, str] | None = None) -> None:
        key = self._key(name, labels)
        with self._lock:
            if key is None:
                self._dropped_series += 1
                return
            exists = key in self._counters
            if self._reserve(key, "counter", exists):
                self._counters[key] += 1

    def set_counter(
        self, name: str, value: int, labels: dict[str, str] | None = None,
    ) -> None:
        if value < 0:
            raise ValueError("Counter values cannot be negative")
        key = self._key(name, labels)
        with self._lock:
            if key is None:
                self._dropped_series += 1
                return
            exists = key in self._counters
            if self._reserve(key, "counter", exists):
                # A connector may retry/replay the same cumulative counters.
                self._counters[key] = max(self._counters[key], value)

    def set_gauge(
        self, name: str, value: float, labels: dict[str, str] | None = None,
    ) -> None:
        key = self._key(name, labels)
        with self._lock:
            if key is None:
                self._dropped_series += 1
                return
            exists = key in self._gauges
            if self._reserve(key, "gauge", exists):
                self._gauges[key] = float(value)

    def render(self) -> str:
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
            types = dict(self._types)
            dropped = self._dropped_series

        lines: list[str] = []
        for name in sorted(types):
            metric_type = types[name]
            values = counters if metric_type == "counter" else gauges
            lines.extend([
                f"# HELP {name} OpenShield process metric.",
                f"# TYPE {name} {metric_type}",
            ])
            for (metric_name, labels), value in sorted(values.items()):
                if metric_name != name:
                    continue
                if labels:
                    rendered = ",".join(
                        f'{key}="{self._escape(value)}"' for key, value in labels
                    )
                    lines.append(f"{name}{{{rendered}}} {value}")
                else:
                    lines.append(f"{name} {value}")

        if dropped:
            lines.extend([
                f"# HELP {_DROPPED_SERIES_METRIC} Number of metric updates rejected by registry bounds.",
                f"# TYPE {_DROPPED_SERIES_METRIC} counter",
                f"{_DROPPED_SERIES_METRIC} {dropped}",
            ])
        return "\n".join(lines) + ("\n" if lines else "")

    @staticmethod
    def _escape(value: str) -> str:
        return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')
