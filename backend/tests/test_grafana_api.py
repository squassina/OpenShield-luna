from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from openshield.api import main
from openshield.core.secrets import SecretStore

client = TestClient(main.app)


def setup_function() -> None:
    main.store.reset()


def test_grafana_credentials_are_encrypted_and_diagnostics_are_read_only(monkeypatch):
    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", Fernet.generate_key().decode())
    registered = client.post("/api/v1/integrations", json={
        "integration_id": "grafana-home",
        "kind": "grafana",
        "display_name": "Home Grafana",
        "config": {"base_url": "https://grafana.example:3000"},
    })
    assert registered.status_code == 201

    saved = client.put("/api/v1/integrations/grafana-home/grafana-credentials", json={
        "base_url": "https://grafana.example:3000",
        "bearer_token": "sensitive-grafana-token",
    })
    assert saved.status_code == 200
    assert "sensitive-grafana-token" not in saved.text
    item = next(
        value for value in client.get("/api/v1/integrations").json()
        if value["integration_id"] == "grafana-home"
    )
    assert item["config"]["auth_configured"] is True
    assert "bearer_token" not in str(item)
    encrypted = main.store.get_integration_secret("grafana-home")
    assert encrypted and b"sensitive-grafana-token" not in encrypted
    assert SecretStore(main.store).get("grafana-home") == {
        "base_url": "https://grafana.example:3000",
        "bearer_token": "sensitive-grafana-token",
    }

    class FakeGrafanaClient:
        def __init__(self, base_url, bearer_token):
            assert base_url == "https://grafana.example:3000"
            assert bearer_token == "sensitive-grafana-token"

        def diagnostics(self):
            return {
                "health": {"database": "ok", "version": "11.2.0", "commit": "abc123"},
                "dashboards": [{"uid": "abc", "title": "Overview", "type": "dash-db"}],
                "summary": {"dashboards_returned": 1, "dashboards_limit": 100},
            }

    monkeypatch.setattr(main, "GrafanaClient", FakeGrafanaClient)
    diagnostics = client.get("/api/v1/integrations/grafana-home/grafana-diagnostics")
    assert diagnostics.status_code == 200
    assert diagnostics.headers["cache-control"] == "no-store"
    assert diagnostics.json()["summary"]["dashboards_returned"] == 1
    check = client.post("/api/v1/integrations/grafana-home/test")
    assert check.status_code == 200
    assert check.json()["provider"] == "grafana"
    assert check.json()["imported"] == 0

    assert client.delete(
        "/api/v1/integrations/grafana-home/grafana-credentials"
    ).status_code == 204
    assert client.get(
        "/api/v1/integrations/grafana-home/grafana-diagnostics"
    ).status_code == 409
