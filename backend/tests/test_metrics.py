import pytest

from openshield.core.metrics import MetricsRegistry


def test_series_limit_bounds_total_metric_cardinality() -> None:
    metrics = MetricsRegistry(max_series=3)
    metrics.increment("requests_total", {"method": "GET"})
    metrics.increment("requests_total", {"method": "POST"})
    metrics.set_gauge("queue_depth", 2, {"gateway_id": "router-1"})
    metrics.increment("requests_total", {"method": "DELETE"})

    assert metrics._series_count() == 3
    rendered = metrics.render()
    assert 'requests_total{method="GET"} 1' in rendered
    assert 'requests_total{method="POST"} 1' in rendered
    assert "requests_total{method=\"DELETE\"}" not in rendered
    assert "queue_depth{gateway_id=\"router-1\"} 2.0" in rendered
    assert "openshield_metrics_series_dropped_total 1" in rendered


def test_cumulative_counter_updates_are_monotonic() -> None:
    metrics = MetricsRegistry()
    metrics.set_counter("gateway_dropped_total", 12)
    metrics.set_counter("gateway_dropped_total", 7)
    metrics.set_counter("gateway_dropped_total", 15)

    assert "gateway_dropped_total 15" in metrics.render()


def test_registry_rejects_invalid_metric_labels_and_type_conflicts() -> None:
    metrics = MetricsRegistry(max_series=10)
    metrics.increment("valid_total", {"bad label": "value"})
    metrics.increment("valid_total", {"label": "x" * 129})
    metrics.increment("valid_total", {f"label_{i}": str(i) for i in range(9)})
    metrics.increment("mixed_metric", {"result": "ok"})
    metrics.set_gauge("mixed_metric", 1)

    rendered = metrics.render()
    assert "valid_total" not in rendered
    assert "mixed_metric{result=\"ok\"} 1" in rendered
    assert "openshield_metrics_series_dropped_total 5" in rendered


def test_registry_rejects_negative_counter_values() -> None:
    with pytest.raises(ValueError, match="cannot be negative"):
        MetricsRegistry().set_counter("events_total", -1)


def test_registry_requires_positive_series_limit() -> None:
    with pytest.raises(ValueError, match="positive"):
        MetricsRegistry(max_series=0)
