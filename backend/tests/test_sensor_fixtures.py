import json
from pathlib import Path

from openshield.visibility.normalizers import normalize_sensor_batch


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "sensors"


def load_jsonl(name: str) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in (FIXTURE_DIR / name).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_suricata_eve_fixtures_cover_supported_common_streams() -> None:
    records = load_jsonl("suricata-eve.jsonl")

    events = normalize_sensor_batch("suricata", records, "fixture-suricata")

    assert [event.event_type for event in events] == [
        "network.suricata.alert",
        "network.suricata.flow",
        "network.suricata.dns",
        "network.suricata.http",
        "network.suricata.tls",
    ]
    assert events[0].severity.value == "medium"
    assert events[0].payload["signature"] == "ET TEST Example alert"
    assert "fixture_secret" not in events[0].payload
    assert events[2].payload["dns"]["rrname"] == "example.test"


def test_zeek_json_fixtures_cover_supported_log_streams() -> None:
    records = load_jsonl("zeek-json.jsonl")

    events = normalize_sensor_batch("zeek", records, "fixture-zeek")

    assert [event.event_type for event in events] == [
        "network.zeek.conn",
        "network.zeek.dns",
        "network.zeek.http",
        "network.zeek.ssl",
    ]
    assert events[0].payload["uid"] == "C-fixture-001"
    assert events[1].payload["query"] == "example.test"
    assert "fixture_secret" not in events[0].payload
