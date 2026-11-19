from types import SimpleNamespace

import pytest

from openshield.core.metrics import MetricsRegistry
from openshield.privacy.polling import _base_labels


def test_metrics_registry_caps_new_series_and_counts_overflow() -> None:
    metrics = MetricsRegistry(max_series=2)
    metrics.increment("openshield_test_events_total", {"integration_id": "one"})
    metrics.increment("openshield_test_events_total", {"integration_id": "two"})
    metrics.increment("openshield_test_events_total", {"integration_id": "three"})

    rendered = metrics.render()
    assert 'integration_id="one"' in rendered
    assert 'integration_id="two"' in rendered
    assert 'integration_id="three"' not in rendered
    assert "openshield_metrics_series_overflow_total" in rendered
    assert rendered.endswith("openshield_metrics_series_overflow_total 1\\n")


def test_metrics_registry_renders_gauges_and_escapes_labels() -> None:
    metrics = MetricsRegistry()
    metrics.set_gauge("openshield_queue_depth", 4)
    metrics.increment("openshield_test_total", {"result": 'bad"value'})

    rendered = metrics.render()
    assert "# TYPE openshield_queue_depth gauge" in rendered
    assert "openshield_queue_depth 4" in rendered
    assert 'result="bad\\\\"value"' in rendered


def test_metrics_registry_rejects_invalid_metric_names_and_values() -> None:
    metrics = MetricsRegistry()
    with pytest.raises(ValueError, match="metric name"):
        metrics.increment("invalid metric name")
    with pytest.raises(ValueError, match="finite number"):
        metrics.set_gauge("openshield_invalid", float("inf"))


def test_dns_poll_metrics_do_not_use_integration_id_labels() -> None:
    integration = SimpleNamespace(integration_id="customer-controlled-id", kind="pihole")
    assert _base_labels(integration) == {"provider": "pihole"}
