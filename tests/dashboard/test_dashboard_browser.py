from __future__ import annotations

import pytest
from playwright.sync_api import Page, expect


def open_dashboard(page: Page, dashboard_url: str, mock_api, fail_path: str | None = None):
    mock = mock_api(page, fail_path=fail_path)
    page.goto(dashboard_url)
    page.wait_for_function(
        "() => document.querySelector('#notice').textContent.includes('Dashboard')"
        " || document.querySelector('#notice').textContent.includes('dashboard panels')"
    )
    return mock


def test_initial_load_refresh_and_gateway_status(page: Page, dashboard_url: str, mock_api) -> None:
    open_dashboard(page, dashboard_url, mock_api)

    scripts = page.locator("script").all_text_contents()
    for script in scripts:
        page.evaluate("(source) => { new Function(source); }", script)
    expect(page.locator("#queries")).to_have_text("12")
    expect(page.locator("#integrations")).to_contain_text("Pi-hole")
    expect(page.locator("#openwrt-status")).to_contain_text("Router connected")
    expect(page.locator("#router-topology")).to_contain_text("router-home")
    assert page.page_errors == []

    with page.expect_response(
        lambda response: "/api/v1/privacy/report" in response.url and response.request.method == "GET"
    ):
        page.locator("#refresh").click()
    assert page.page_errors == []


@pytest.mark.parametrize(
    ("failed_endpoint", "affected_panel"),
    [
        ("/api/v1/privacy/report", "report-status"),
        ("/api/v1/privacy/sources", "sources"),
        ("/api/v1/sensors", "sensors"),
        ("/api/v1/privacy/analytics/devices", "devices"),
        ("/api/v1/integrations", "integrations"),
        ("/api/v1/privacy/lists", "lists"),
        ("/api/v1/inventory/devices", "inventory"),
        ("/api/v1/inventory/router-devices", "router-topology"),
        ("/api/v1/incidents", "incidents"),
        ("/api/v1/policies", "policies"),
        ("/api/v1/policy-decisions", "policy-decisions"),
        ("/api/v1/executions", "executions"),
        ("/api/v1/control/emergency-stop", "policy-runtime-status"),
    ],
)
def test_api_failures_are_isolated_to_the_affected_panel(
    page: Page,
    dashboard_url: str,
    mock_api,
    failed_endpoint: str,
    affected_panel: str,
) -> None:
    open_dashboard(page, dashboard_url, mock_api, fail_path=failed_endpoint)

    expect(page.locator("#" + affected_panel)).to_contain_text(failed_endpoint)
    expect(page.locator("#" + affected_panel)).to_contain_text("HTTP 503")
    if failed_endpoint == "/api/v1/privacy/report":
        expect(page.locator("#queries")).to_have_text("—")
    else:
        expect(page.locator("#queries")).to_have_text("12")
    if failed_endpoint != "/api/v1/integrations":
        expect(page.locator("#integrations")).to_contain_text("Pi-hole")
    if failed_endpoint != "/api/v1/privacy/analytics/devices":
        expect(page.locator("#devices")).to_contain_text("192.168.1.20")
    assert page.page_errors == []


def test_integration_can_be_edited_and_deleted(page: Page, dashboard_url: str, mock_api) -> None:
    mock = open_dashboard(page, dashboard_url, mock_api)

    integrations = page.locator("#integrations")
    integrations.get_by_role("button", name="Edit").first.click()
    expect(page.locator("#integration-dialog")).to_be_visible()
    page.locator("#edit-display-name").fill("Pi-hole renamed")
    page.locator("#integration-edit-form").get_by_role("button", name="Save changes").click()
    expect(integrations).to_contain_text("Pi-hole renamed")

    page.once("dialog", lambda dialog: dialog.accept())
    integrations.get_by_role("button", name="Delete").first.click()
    expect(integrations).not_to_contain_text("Pi-hole renamed")
    assert any(
        method == "DELETE" and path == "/api/v1/integrations/pihole-home"
        for method, path in mock["requests"]
    )
    assert page.page_errors == []


def test_dns_lists_can_be_created_and_removed(page: Page, dashboard_url: str, mock_api) -> None:
    open_dashboard(page, dashboard_url, mock_api)

    page.locator("#list-domain").fill("blocked.example")
    page.locator("#list-comment").fill("Browser test")
    page.locator("#list-form").get_by_role("button", name="Add entry").click()
    expect(page.locator("#lists")).to_contain_text("blocked.example")

    page.locator("#lists").get_by_role("button", name="Remove").click()
    expect(page.locator("#lists")).not_to_contain_text("blocked.example")
    assert page.page_errors == []


def test_incident_and_policy_actions_work(page: Page, dashboard_url: str, mock_api) -> None:
    open_dashboard(page, dashboard_url, mock_api)

    page.locator("#incidents").get_by_role("button", name="Acknowledge").click()
    expect(page.locator("#incidents")).to_contain_text("acknowledged")

    page.locator("#policy-decisions").get_by_role("button", name="Approve").click()
    expect(page.locator("#policy-decisions")).to_contain_text("approved")
    assert page.page_errors == []



def test_ai_providers_and_investigation_render_safely(
    page: Page, dashboard_url: str, mock_api
) -> None:
    open_dashboard(page, dashboard_url, mock_api)

    providers = page.locator("#ai-provider")
    expect(providers).to_be_enabled()
    expect(providers.locator("option")).to_have_count(2)
    expect(providers).to_contain_text("Local Ollama")
    expect(providers).not_to_contain_text("Disabled OpenAI")

    providers.select_option("ollama-home")
    page.locator("#incidents").get_by_role("button", name="AI investigate").click()

    results = page.locator("#ai-results")
    expect(results).to_contain_text("AI investigation")
    expect(results).to_contain_text("<img src=x onerror=alert(1)> suspicious DNS activity")
    expect(results).to_contain_text("Confidence: 85%")
    expect(results).to_contain_text("Three matching DNS events")
    expect(results).to_contain_text("Possible beaconing")
    expect(results).to_contain_text("Review the affected client")
    expect(results).to_contain_text("Caveats")
    expect(results.locator("img")).to_have_count(0)
    assert page.page_errors == []


def test_ai_provider_selector_handles_no_enabled_ai_providers(
    page: Page, dashboard_url: str, mock_api
) -> None:
    mock = mock_api(page)
    mock["state"]["integrations"] = [
        item for item in mock["state"]["integrations"]
        if item["kind"] not in {"ollama", "openai"}
    ]
    page.goto(dashboard_url)
    page.wait_for_function(
        "() => document.querySelector('#notice').textContent.includes('Dashboard')"
        " || document.querySelector('#notice').textContent.includes('dashboard panels')"
    )

    expect(page.locator("#ai-provider")).to_be_disabled()
    expect(page.locator("#ai-provider")).to_contain_text("No enabled AI providers")
    assert page.page_errors == []
