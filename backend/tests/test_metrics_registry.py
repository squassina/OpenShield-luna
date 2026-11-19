import pytest

from openshield.core.metrics import (
    DROPPED_SERIES_METRIC,
    MetricsRegistry,
)


@pytest.mark.parametrize("max_series", [0, -1, True, 1.5])
def test_metrics_registry_requires_a_positive_integer_series_limit(max_series: object) -> None:
    with pytest.raises(ValueError, match="max_series must be a positive integer"):
        MetricsRegistry(max_series=max_series)  # type: ignore[arg-type]


def test_metrics_registry_caps_new_series_and_reports_drops() -> None:
    metrics = MetricsRegistry(max_series=2)
    metrics.increment("requests_total", {"route": "/a"})
    metrics.increment("requests_total", {"route": "/b"})
    metrics.increment("requests_total", {"route": "/a"})
    metrics.increment("requests_total", {"route": "/c"})
    metrics.increment("another_total")

    rendered = metrics.render()

    assert 'requests_total{route="/a"} 2' in rendered
    assert 'requests_total{route="/b"} 1' in rendered
    assert 'route="/c"' not in rendered
    assert "another_total" not in rendered
    assert f"{DROPPED_SERIES_METRIC} 2" in rendered


def test_metrics_registry_reuses_series_independent_of_label_order() -> None:
    metrics = MetricsRegistry(max_series=1)
    metrics.increment("requests_total", {"method": "GET", "route": "/health"})
    metrics.increment("requests_total", {"route": "/health", "method": "GET"})

    rendered = metrics.render()

    assert 'requests_total{method="GET",route="/health"} 2' in rendered
    assert DROPPED_SERIES_METRIC not in rendered


def test_metrics_registry_protects_internal_overflow_metric_name() -> None:
    metrics = MetricsRegistry()

    with pytest.raises(ValueError, match="reserved for registry overflow"):
        metrics.increment(DROPPED_SERIES_METRIC)
