from openshield.core.storage import PostgresStore


def provider_privacy_lists(
    store: PostgresStore, integration_id: str,
) -> list[dict[str, object]]:
    """Merge manual entries with provider-scoped P5 entries.

    Provider-scoped entries win duplicate keys because they retain execution ownership.
    """
    merged: dict[tuple[str, str], dict[str, object]] = {}
    for entry in store.list_privacy_lists("openshield-local"):
        merged[(str(entry["list_type"]), str(entry["domain"]))] = entry
    for entry in store.list_privacy_lists(integration_id):
        merged[(str(entry["list_type"]), str(entry["domain"]))] = entry
    return [merged[key] for key in sorted(merged)]
