from __future__ import annotations

import json
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

import pytest
from playwright.sync_api import Browser, Page, sync_playwright

ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_DIR = ROOT / "backend" / "openshield"
if not (DASHBOARD_DIR / "dashboard.html").is_file():
    DASHBOARD_DIR = Path("/app/openshield")


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_args: object) -> None:
        return None


@pytest.fixture(scope="session")
def dashboard_url() -> str:
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        partial(QuietHandler, directory=str(DASHBOARD_DIR)),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/dashboard.html"
    server.shutdown()
    thread.join(timeout=2)
    server.server_close()


@pytest.fixture(scope="session")
def browser() -> Browser:
    with sync_playwright() as playwright:
        instance = playwright.chromium.launch()
        yield instance
        instance.close()


@pytest.fixture
def page(browser: Browser) -> Page:
    context = browser.new_context()
    page = context.new_page()
    page.page_errors = []
    page.on("pageerror", lambda error: page.page_errors.append(str(error)))
    yield page
    context.close()


@pytest.fixture
def mock_api():
    def install(page: Page, fail_path: str | None = None) -> dict[str, object]:
        state: dict[str, object] = {
            "integrations": [
                {
                    "integration_id": "pihole-home",
                    "kind": "pihole",
                    "display_name": "Pi-hole",
                    "enabled": True,
                    "capabilities": [],
                    "config": {"base_url": "http://192.0.2.53", "auth_configured": False},
                },
                {
                    "integration_id": "ollama-home",
                    "kind": "ollama",
                    "display_name": "Local Ollama",
                    "enabled": True,
                    "capabilities": [],
                    "config": {"base_url": "http://192.0.2.20:11434", "model": "llama3"},
                },
                {
                    "integration_id": "openai-disabled",
                    "kind": "openai",
                    "display_name": "Disabled OpenAI",
                    "enabled": False,
                    "capabilities": [],
                    "config": {"model": "gpt-4.1-mini"},
                },
                {
                    "integration_id": "router-home",
                    "kind": "openwrt",
                    "display_name": "OpenWrt",
                    "enabled": True,
                    "capabilities": [],
                    "config": {
                        "base_url": "http://192.168.1.1",
                        "rpc_configured": True,
                    },
                },
            ],
            "lists": [],
            "incidents": [
                {
                    "incident_id": "incident-1",
                    "indicator_type": "domain",
                    "indicator_value": "malicious.example",
                    "risk_level": "high",
                    "risk_score": 90,
                    "status": "open",
                    "sources": ["pihole"],
                },
            ],
            "policies": {
                "items": [
                    {
                        "policy_id": "policy-1",
                        "name": "Block malicious domain",
                        "indicator_type": "domain",
                        "indicator_value": "malicious.example",
                        "action": "block_domain",
                        "integration_id": "pihole-home",
                        "min_risk_score": 80,
                        "autonomy_level": 0,
                        "ttl_seconds": 3600,
                        "require_approval": True,
                        "enabled": True,
                    },
                ],
            },
            "decisions": [
                {
                    "decision_id": "decision-1",
                    "incident_id": "incident-1",
                    "policy_id": "policy-1",
                    "status": "pending_approval",
                    "rationale": {"reasons": ["risk threshold met"]},
                },
            ],
            "executions": [],
            "control": {
                "enforcement_enabled": False,
                "active": True,
                "max_autonomy_level": 0,
            },
        }
        requests: list[tuple[str, str]] = []

        def respond(route, payload: object, status: int = 200) -> None:
            route.fulfill(
                status=status,
                content_type="application/json",
                body=json.dumps(payload),
            )

        def handler(route) -> None:
            request = route.request
            parsed = urlparse(request.url)
            path, method = parsed.path, request.method
            requests.append((method, path))
            if fail_path == path and method == "GET":
                respond(route, {"detail": "mock endpoint unavailable"}, 503)
                return

            if path == "/api/v1/privacy/report":
                respond(route, {
                    "totals": {
                        "queries": 12,
                        "blocked": 2,
                        "tracker_queries": 3,
                        "block_rate_percent": 16.7,
                    },
                    "top_domains": [{
                        "domain": "ads.example",
                        "queries": 5,
                        "blocked": 2,
                        "tracker_queries": 1,
                    }],
                    "daily_trends": [{"date": "2026-11-15", "queries": 12}],
                })
                return
            if path == "/api/v1/privacy/sources":
                respond(route, [{
                    "integration_id": "pihole-home",
                    "display_name": "Pi-hole",
                    "status": "healthy",
                    "queries_seen": 12,
                    "last_success_at": "2026-11-15T12:00:00Z",
                    "last_error": None,
                }])
                return
            if path == "/api/v1/sensors":
                respond(route, [{"display_name": "Suricata", "status": "healthy", "events_seen": 2}])
                return
            if path == "/api/v1/privacy/analytics/devices":
                respond(route, [{
                    "client": "192.168.1.20",
                    "queries": 8,
                    "unique_domains": 3,
                    "blocked": 1,
                }])
                return
            if path == "/api/v1/integrations":
                if method == "GET":
                    respond(route, state["integrations"])
                elif method == "POST":
                    item = request.post_data_json
                    state["integrations"].append(item)
                    respond(route, item)
                else:
                    respond(route, {"detail": "unsupported"}, 405)
                return
            if path.startswith("/api/v1/integrations/"):
                parts = [unquote(part) for part in path.split("/") if part]
                integration_id = parts[3] if len(parts) > 3 else ""
                suffix = parts[4:] if len(parts) > 4 else []
                if suffix == ["test"]:
                    respond(route, {
                        "status": "connected",
                        "message": "Router connected",
                        "last_rpc_check": "2026-11-15T12:00:00Z",
                        "router": {
                            "board": {
                                "hostname": "router-home",
                                "model": "Test Router",
                                "system": "OpenWrt",
                                "kernel": "6.6",
                                "release": {"version": "24.10"},
                            },
                            "interfaces": [{"name": "lan", "up": True, "ipv4_address": ["192.168.1.1"]}],
                        },
                    })
                    return
                item = next(
                    (value for value in state["integrations"]
                     if value["integration_id"] == integration_id),
                    None,
                )
                if suffix == ["dns-provider-credentials"] and method == "PUT":
                    respond(route, {"status": "saved"})
                    return
                if suffix == ["openwrt-credentials"] and method == "DELETE":
                    respond(route, {"status": "removed"})
                    return
                if not suffix and method == "PATCH" and item is not None:
                    item.update(request.post_data_json)
                    if "config" in request.post_data_json:
                        item["config"] = request.post_data_json["config"]
                    respond(route, item)
                    return
                if not suffix and method == "DELETE":
                    state["integrations"] = [
                        value for value in state["integrations"]
                        if value["integration_id"] != integration_id
                    ]
                    route.fulfill(status=204, body="")
                    return
                respond(route, {"detail": "not found"}, 404)
                return
            if path == "/api/v1/privacy/lists":
                if method == "GET":
                    respond(route, state["lists"])
                elif method == "POST":
                    item = request.post_data_json
                    state["lists"].append(item)
                    respond(route, item, 201)
                else:
                    respond(route, {"detail": "unsupported"}, 405)
                return
            if path.startswith("/api/v1/privacy/lists/") and method == "DELETE":
                parts = [unquote(part) for part in path.split("/") if part]
                list_type, domain = parts[4], parts[5]
                state["lists"] = [
                    item for item in state["lists"]
                    if not (item["list_type"] == list_type and item["domain"] == domain)
                ]
                route.fulfill(status=204, body="")
                return
            if path == "/api/v1/inventory/devices":
                respond(route, [{
                    "ip_address": "192.168.1.20",
                    "scope": "lan",
                    "observations": 4,
                }])
                return
            if path == "/api/v1/inventory/router-devices":
                respond(route, {
                    "gateways": [{
                        "gateway_id": "router-home",
                        "board": {"hostname": "router-home"},
                        "interfaces": [{"name": "lan", "device": "br-lan", "up": True}],
                    }],
                    "devices": [{
                        "gateway_id": "router-home",
                        "interface": "lan",
                        "name": "desktop",
                        "status": "online",
                        "ip_address": "192.168.1.20",
                        "ipv4_addresses": ["192.168.1.20"],
                        "ipv6_addresses": [],
                        "mac_address": "AA:BB:CC:DD:EE:FF",
                        "last_seen": "2026-11-15T12:00:00Z",
                    }],
                })
                return
            if path == "/api/v1/incidents":
                respond(route, state["incidents"])
                return
            if path.startswith("/api/v1/incidents/"):
                incident_id = (
                    path.split("/")[-2]
                    if path.endswith("/investigate")
                    else path.rsplit("/", 1)[-1]
                )
                incident = next(
                    (item for item in state["incidents"] if item["incident_id"] == incident_id),
                    None,
                )
                if incident is None:
                    respond(route, {"detail": "not found"}, 404)
                elif method == "POST" and path.endswith("/investigate"):
                    respond(route, {
                        "investigation_id": "investigation-1",
                        "incident_id": incident_id,
                        "provider_integration_id": "ollama-home",
                        "provider_kind": "ollama",
                        "model": "llama3",
                        "result": {
                            "summary": "<img src=x onerror=alert(1)> suspicious DNS activity",
                            "confidence": 0.85,
                            "observed_facts": ["Three matching DNS events"],
                            "hypotheses": ["Possible beaconing"],
                            "recommendations": ["Review the affected client"],
                            "caveats": [],
                        },
                    })
                elif method == "PATCH":
                    incident.update(request.post_data_json)
                    respond(route, incident)
                else:
                    respond(route, {**incident, "summary": "Test incident", "timeline": []})
                return
            if path == "/api/v1/policies":
                if method == "GET":
                    respond(route, state["policies"])
                elif method == "POST":
                    item = request.post_data_json
                    state["policies"]["items"].append(item)
                    respond(route, item, 201)
                return
            if path == "/api/v1/policy-decisions":
                respond(route, state["decisions"])
                return
            if path.endswith("/approve") and path.startswith("/api/v1/policy-decisions/"):
                decision_id = path.split("/")[-2]
                decision = next(
                    item for item in state["decisions"]
                    if item["decision_id"] == decision_id
                )
                decision["status"] = "approved"
                respond(route, decision)
                return
            if path == "/api/v1/executions":
                respond(route, state["executions"])
                return
            if path == "/api/v1/control/emergency-stop":
                if method == "POST":
                    state["control"].update(request.post_data_json)
                respond(route, state["control"])
                return

            respond(route, {})

        page.route("**/api/v1/**", handler)
        return {"state": state, "requests": requests}

    return install
