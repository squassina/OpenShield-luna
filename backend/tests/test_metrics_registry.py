import pytest

from openshield.core.metrics import (
    DROPPED_SAMPLES_METRIC,
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
    assert f"{DROPPED_SAMPLES_METRIC} 2" in rendered


def test_metrics_registry_reuses_series_independent_of_label_order() -> None:
    metrics = MetricsRegistry(max_series=1)
    metrics.increment("requests_total", {"method": "GET", "route": "/health"})
    metrics.increment("requests_total", {"route": "/health", "method": "GET"})

    rendered = metrics.render()

    assert 'requests_total{method="GET",route="/health"} 2' in rendered
    assert DROPPED_SAMPLES_METRIC not in rendered


def test_metrics_registry_protects_internal_overflow_metric_name() -> None:
    metrics = MetricsRegistry()

    with pytest.raises(ValueError, match="reserved for registry overflow"):
        metrics.increment(DROPPED_SAMPLES_METRIC)


def test_metrics_registry_renders_gauges_and_persisted_counter_snapshots() -> None:
    metrics = MetricsRegistry()
    labels = {"gateway_id": "home-gateway"}
    metrics.set_gauge("openshield_gateway_spool_pending_events", 12, labels)
    metrics.set_counter("openshield_gateway_spool_dropped_events_total", 3, labels)

    rendered = metrics.render()

    assert (
        '# TYPE openshield_gateway_spool_pending_events gauge\n'
        'openshield_gateway_spool_pending_events{gateway_id="home-gateway"} 12'
    ) in rendered
    assert (
        '# TYPE openshield_gateway_spool_dropped_events_total counter\n'
        'openshield_gateway_spool_dropped_events_total{gateway_id="home-gateway"} 3'
    ) in rendered


def test_metrics_registry_shares_series_limit_between_counters_and_gauges() -> None:
    metrics = MetricsRegistry(max_series=1)
    metrics.set_gauge("spool_pending", 5)
    metrics.set_counter("spool_dropped_total", 1)

    rendered = metrics.render()

    assert "spool_pending 5" in rendered
    assert "spool_dropped_total" not in rendered
    assert f"{DROPPED_SAMPLES_METRIC} 1" in rendered


def test_metrics_registry_rejects_mixed_metric_types() -> None:
    metrics = MetricsRegistry()
    metrics.increment("requests_total")
    with pytest.raises(ValueError, match="already registered as counter"):
        metrics.set_gauge("requests_total", 1)


@pytest.mark.parametrize("value", [-1, True, 1.5])
def test_metrics_registry_rejects_invalid_counter_snapshots(value: object) -> None:
    metrics = MetricsRegistry()
    with pytest.raises(ValueError, match="non-negative integer"):
        metrics.set_counter("spool_dropped_total", value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [True, float("nan"), float("inf")])
def test_metrics_registry_rejects_invalid_gauges(value: object) -> None:
    metrics = MetricsRegistry()
    with pytest.raises(ValueError, match="finite number"):
        metrics.set_gauge("spool_pending", value)  # type: ignore[arg-type]
