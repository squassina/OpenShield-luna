from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from openshield.api import main
from openshield.core.secrets import SecretStore

client = TestClient(main.app)


def setup_function() -> None:
    main.store.reset()


def test_prometheus_credentials_are_encrypted_and_diagnostics_are_read_only(monkeypatch):
    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", Fernet.generate_key().decode())
    registered = client.post("/api/v1/integrations", json={
        "integration_id": "prometheus-home",
        "kind": "prometheus",
        "display_name": "Home Prometheus",
        "config": {"base_url": "https://prometheus.example:9090"},
    })
    assert registered.status_code == 201

    saved = client.put("/api/v1/integrations/prometheus-home/prometheus-credentials", json={
        "base_url": "https://prometheus.example:9090",
        "bearer_token": "sensitive-prometheus-token",
    })
    assert saved.status_code == 200
    assert "sensitive-prometheus-token" not in saved.text
    item = next(
        value for value in client.get("/api/v1/integrations").json()
        if value["integration_id"] == "prometheus-home"
    )
    assert item["config"]["auth_configured"] is True
    assert "bearer_token" not in str(item)
    encrypted = main.store.get_integration_secret("prometheus-home")
    assert encrypted and b"sensitive-prometheus-token" not in encrypted
    assert SecretStore(main.store).get("prometheus-home") == {
        "base_url": "https://prometheus.example:9090",
        "bearer_token": "sensitive-prometheus-token",
    }

    class FakePrometheusClient:
        def __init__(self, base_url, bearer_token):
            assert base_url == "https://prometheus.example:9090"
            assert bearer_token == "sensitive-prometheus-token"

        def diagnostics(self):
            return {
                "runtime": {"version": "3.0.0"},
                "targets": [{"health": "up"}],
                "summary": {
                    "targets_available": 1, "targets_up": 1,
                    "targets_down": 0, "targets_limit": 100,
                },
            }

    monkeypatch.setattr(main, "PrometheusClient", FakePrometheusClient)
    diagnostics = client.get("/api/v1/integrations/prometheus-home/prometheus-diagnostics")
    assert diagnostics.status_code == 200
    assert diagnostics.headers["cache-control"] == "no-store"
    assert diagnostics.json()["summary"]["targets_up"] == 1
    check = client.post("/api/v1/integrations/prometheus-home/test")
    assert check.status_code == 200
    assert check.json()["provider"] == "prometheus"
    assert check.json()["imported"] == 0

    assert client.delete(
        "/api/v1/integrations/prometheus-home/prometheus-credentials"
    ).status_code == 204
    assert client.get(
        "/api/v1/integrations/prometheus-home/prometheus-diagnostics"
    ).status_code == 409
