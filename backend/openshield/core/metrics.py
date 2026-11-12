from collections import Counter
from threading import Lock


class MetricsRegistry:
    """Small process-local Prometheus text registry with bounded label usage."""

    def __init__(self) -> None:
        self._counters: Counter[tuple[str, tuple[tuple[str, str], ...]]] = Counter()
        self._lock = Lock()

    def increment(self, name: str, labels: dict[str, str] | None = None) -> None:
        key = (name, tuple(sorted((labels or {}).items())))
        with self._lock:
            self._counters[key] += 1

    def render(self) -> str:
        with self._lock:
            snapshot = dict(self._counters)
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
