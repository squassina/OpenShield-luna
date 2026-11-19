from collections import Counter
from threading import Lock

DEFAULT_MAX_METRIC_SERIES = 4096
DROPPED_SERIES_METRIC = "openshield_metrics_series_dropped_total"


class MetricsRegistry:
    """Process-local Prometheus counters with a hard limit on metric series."""

    def __init__(self, *, max_series: int = DEFAULT_MAX_METRIC_SERIES) -> None:
        if isinstance(max_series, bool) or not isinstance(max_series, int) or max_series < 1:
            raise ValueError("max_series must be a positive integer")
        self.max_series = max_series
        self._counters: Counter[tuple[str, tuple[tuple[str, str], ...]]] = Counter()
        self._dropped_series = 0
        self._lock = Lock()

    def increment(self, name: str, labels: dict[str, str] | None = None) -> None:
        if name == DROPPED_SERIES_METRIC:
            raise ValueError(f"{DROPPED_SERIES_METRIC} is reserved for registry overflow")
        key = (name, tuple(sorted((labels or {}).items())))
        with self._lock:
            if key in self._counters:
                self._counters[key] += 1
            elif len(self._counters) < self.max_series:
                self._counters[key] = 1
            else:
                self._dropped_series += 1

    def render(self) -> str:
        with self._lock:
            snapshot = dict(self._counters)
            if self._dropped_series:
                snapshot[(DROPPED_SERIES_METRIC, ())] = self._dropped_series
        metric_names = sorted({name for name, _ in snapshot})
        lines = []
        for name in metric_names:
            lines.extend(
                [
                    f"# HELP {name} OpenShield process counter.",
                    f"# TYPE {name} counter",
                ]
            )
            entries = sorted(
                (labels, value)
                for (metric_name, labels), value in snapshot.items()
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
