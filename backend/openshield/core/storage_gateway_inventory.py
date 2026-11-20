from datetime import datetime

from psycopg.types.json import Jsonb


class PostgresGatewayInventoryStoreMixin:
    """Gateway discovery snapshot and device inventory persistence."""

    def record_gateway_discovery(
        self, gateway_id: str, payload: dict[str, object], observed_at: datetime
    ) -> None:
        snapshot = {
            "board": payload.get("board", {}),
            "interfaces": payload.get("interfaces", []),
            "device_discovery": payload.get("device_discovery", {}),
        }
        devices = payload.get("devices", [])
        if not isinstance(devices, list):
            devices = []
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO gateway_discovery_snapshots (gateway_id, payload, observed_at)
                VALUES (%s, %s, %s)
                ON CONFLICT (gateway_id) DO UPDATE
                SET payload = CASE
                        WHEN EXCLUDED.observed_at >= gateway_discovery_snapshots.observed_at
                        THEN EXCLUDED.payload ELSE gateway_discovery_snapshots.payload END,
                    observed_at = GREATEST(
                        gateway_discovery_snapshots.observed_at, EXCLUDED.observed_at
                    )
                """,
                (gateway_id, Jsonb(snapshot), observed_at),
            )
            for device in devices:
                if not isinstance(device, dict):
                    continue
                mac = device.get("mac_address")
                if not isinstance(mac, str) or not re.fullmatch(
                    r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac
                ):
                    continue
                if not _has_valid_device_address(device):
                    continue
                normalized_mac = mac.lower()
                cursor.execute(
                    """
                    INSERT INTO network_devices (
                        gateway_id, mac_address, payload, first_seen_at, last_seen_at
                    ) VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (gateway_id, mac_address) DO UPDATE
                    SET payload = CASE
                            WHEN EXCLUDED.last_seen_at >= network_devices.last_seen_at
                            THEN EXCLUDED.payload ELSE network_devices.payload END,
                        last_seen_at = GREATEST(
                            network_devices.last_seen_at, EXCLUDED.last_seen_at
                        )
                    """,
                    (gateway_id, normalized_mac, Jsonb(device), observed_at, observed_at),
                )
                address_evidence = device.get("address_evidence")
                if not isinstance(address_evidence, dict):
                    address_evidence = {}
                    for field in ("ipv4_addresses", "ipv6_addresses"):
                        addresses = device.get(field, [])
                        if isinstance(addresses, list):
                            for address in addresses:
                                if isinstance(address, str):
                                    address_evidence.setdefault(address, []).append({
                                        "source": "luci_host_hints",
                                        "confidence": "medium",
                                    })
                for address, evidence_items in address_evidence.items():
                    if not isinstance(address, str) or not isinstance(evidence_items, list):
                        continue
                    try:
                        parsed_address = ipaddress.ip_address(address)
                    except ValueError:
                        continue
                    if (
                        parsed_address.is_unspecified
                        or parsed_address.is_multicast
                        or parsed_address.is_loopback
                    ):
                        continue
                    for evidence in evidence_items:
                        if not isinstance(evidence, dict):
                            continue
                        source = evidence.get("source")
                        confidence = evidence.get("confidence")
                        if source not in {"luci_host_hints", "dhcp_lease"}:
                            continue
                        expected_confidence = (
                            "high" if source == "dhcp_lease" else "medium"
                        )
                        if confidence != expected_confidence:
                            confidence = expected_confidence
                        cursor.execute(
                            """
                            INSERT INTO network_device_address_observations (
                                gateway_id, mac_address, ip_address, source, confidence,
                                first_seen_at, last_seen_at
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (gateway_id, mac_address, ip_address, source)
                            DO UPDATE SET
                                confidence = EXCLUDED.confidence,
                                last_seen_at = GREATEST(
                                    network_device_address_observations.last_seen_at,
                                    EXCLUDED.last_seen_at
                                )
                            """,
                            (
                                gateway_id, normalized_mac, str(parsed_address), source,
                                confidence, observed_at, observed_at,
                            ),
                        )

    def list_gateway_discovery_snapshots(self) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT gateway_id, payload, observed_at FROM gateway_discovery_snapshots "
                "ORDER BY observed_at DESC, gateway_id"
            )
            rows = cursor.fetchall()
        return [
            {"gateway_id": row[0], "payload": row[1], "observed_at": row[2]}
            for row in rows
        ]

    def list_gateway_devices(self, limit: int = 2000) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT gateway_id, mac_address, payload, first_seen_at, last_seen_at
                FROM network_devices
                ORDER BY last_seen_at DESC, gateway_id, mac_address
                LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [
            {
                "gateway_id": row[0], "mac_address": row[1], "payload": row[2],
                "first_seen_at": row[3], "last_seen_at": row[4],
            }
            for row in rows
        ]
    def list_device_identity_observations(
        self, limit: int = 10000
    ) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT gateway_id, mac_address, ip_address, source, confidence,
                       first_seen_at, last_seen_at
                FROM network_device_address_observations
                WHERE last_seen_at >= NOW() - INTERVAL '30 days'
                ORDER BY ip_address, last_seen_at DESC, gateway_id, mac_address, source
                LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [
            {
                "gateway_id": row[0],
                "mac_address": row[1],
                "ip_address": row[2],
                "source": row[3],
                "confidence": row[4],
                "first_seen_at": row[5],
                "last_seen_at": row[6],
            }
            for row in rows
        ]

