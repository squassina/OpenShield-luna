import ipaddress
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Query

from openshield.core.storage import PostgresStore


def _classify_ip(value: object) -> tuple[str, str] | None:
    if not isinstance(value, str):
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if address.is_unspecified or address.is_multicast:
        return None
    if address.is_loopback:
        scope = "loopback"
    elif address.is_link_local:
        scope = "link_local"
    elif address.is_private:
        scope = "private"
    elif address.is_global:
        scope = "public"
    else:
        scope = "reserved"
    return str(address), scope


def _identity_index(
    store: PostgresStore, now: datetime
) -> dict[str, dict[str, object]]:
    candidates: dict[str, list[dict[str, object]]] = {}
    for item in store.list_device_identity_observations():
        address = _classify_ip(item["ip_address"])
        if address is None:
            continue
        candidates.setdefault(address[0], []).append(item)

    result: dict[str, dict[str, object]] = {}
    for address, observations in candidates.items():
        by_device: dict[tuple[str, str], dict[str, object]] = {}
        for item in observations:
            key = (str(item["gateway_id"]), str(item["mac_address"]))
            candidate = by_device.setdefault(key, {
                "gateway_id": item["gateway_id"],
                "mac_address": item["mac_address"],
                "first_seen": item["first_seen_at"],
                "last_seen": item["last_seen_at"],
                "sources": set(),
                "confidence": "low",
            })
            candidate["sources"].add(item["source"])
            if item["confidence"] == "high" or (
                item["confidence"] == "medium" and candidate["confidence"] == "low"
            ):
                candidate["confidence"] = item["confidence"]
            candidate["first_seen"] = min(candidate["first_seen"], item["first_seen_at"])
            candidate["last_seen"] = max(candidate["last_seen"], item["last_seen_at"])

        normalized = []
        for candidate in by_device.values():
            last_seen = candidate["last_seen"]
            normalized.append({
                **candidate,
                "sources": sorted(candidate["sources"]),
                "first_seen": candidate["first_seen"].isoformat(),
                "last_seen": last_seen.isoformat(),
                "status": "current" if now - last_seen <= timedelta(seconds=90) else "stale",
            })
        current = [item for item in normalized if item["status"] == "current"]
        status = (
            "conflict" if len(current) > 1
            else "identified" if len(current) == 1
            else "stale" if normalized else "unknown"
        )
        result[address] = {
            "identity_status": status,
            "identity_candidates": sorted(
                normalized, key=lambda item: (item["gateway_id"], item["mac_address"])
            ),
            "current_identity": current[0] if len(current) == 1 else None,
        }
    return result


def _network_segments(store: PostgresStore) -> list[dict[str, object]]:
    segments = []
    for snapshot in store.list_gateway_discovery_snapshots():
        interfaces = snapshot["payload"].get("interfaces", [])
        if not isinstance(interfaces, list):
            continue
        for interface in interfaces:
            if not isinstance(interface, dict):
                continue
            subnets = interface.get("subnets", [])
            if not isinstance(subnets, list):
                continue
            for subnet in subnets:
                if not isinstance(subnet, dict) or not isinstance(subnet.get("subnet"), str):
                    continue
                try:
                    network = ipaddress.ip_network(subnet["subnet"], strict=False)
                except ValueError:
                    continue
                vlan_id = interface.get("vlan_id")
                if (
                    not isinstance(vlan_id, int)
                    or isinstance(vlan_id, bool)
                    or not 1 <= vlan_id <= 4094
                ):
                    vlan_id = None
                segments.append({
                    "subnet": str(network),
                    "ip_version": network.version,
                    "prefix_length": network.prefixlen,
                    "gateway_id": snapshot["gateway_id"],
                    "interface": interface.get("name"),
                    "device": interface.get("device"),
                    "vlan_id": vlan_id,
                    "gateway_addresses": interface.get("gateway_addresses", []),
                    "source": "openwrt.network.interface.dump",
                    "confidence": "high",
                })
    return segments


def _node_metadata(
    address: str,
    identities: dict[str, dict[str, object]],
    segments: list[dict[str, object]],
    device_index: dict[tuple[str, str], dict[str, object]],
) -> dict[str, object]:
    identity = identities.get(address, {})
    current = identity.get("current_identity")
    metadata: dict[str, object] = {
        "ip_address": address,
        "scope": _classify_ip(address)[1],
        "ip_version": ipaddress.ip_address(address).version,
        "identity_status": identity.get("identity_status", "unknown"),
        "identity_candidates": identity.get("identity_candidates", []),
    }
    if isinstance(current, dict):
        device = device_index.get((current["gateway_id"], current["mac_address"]), {})
        metadata.update({
            "mac_address": current["mac_address"],
            "hostname": device.get("name"),
            "vendor": device.get("vendor"),
            "gateway_id": current["gateway_id"],
            "interface": device.get("interface"),
            "identity_sources": current["sources"],
            "identity_confidence": current["confidence"],
            "identity_first_seen": current["first_seen"],
            "identity_last_seen": current["last_seen"],
        })
    matching_segments = []
    parsed = ipaddress.ip_address(address)
    for segment in segments:
        try:
            network = ipaddress.ip_network(segment["subnet"], strict=False)
        except ValueError:
            continue
        if parsed in network:
            matching_segments.append(segment)
    metadata["network_segments"] = matching_segments
    return metadata


def create_inventory_router(*, store: PostgresStore) -> APIRouter:
    router = APIRouter()

    @router.get("/api/v1/inventory/router-devices", tags=["inventory"])
    def list_router_devices(
        limit: Annotated[int, Query(ge=1, le=2000)] = 500,
    ) -> dict[str, object]:
        now = datetime.now(UTC)
        snapshots = store.list_gateway_discovery_snapshots()
        devices = []
        for item in store.list_gateway_devices(limit=limit):
            last_seen = item["last_seen_at"]
            devices.append({
                **item["payload"],
                "gateway_id": item["gateway_id"],
                "mac_address": item["mac_address"],
                "first_seen": item["first_seen_at"].isoformat(),
                "last_seen": last_seen.isoformat(),
                "status": "online" if now - last_seen <= timedelta(seconds=90) else "offline",
            })
        return {
            "gateways": [
                {
                    "gateway_id": item["gateway_id"],
                    "observed_at": item["observed_at"].isoformat(),
                    **item["payload"],
                }
                for item in snapshots
            ],
            "devices": devices,
        }

    @router.get("/api/v1/inventory/devices", tags=["inventory"])
    def list_network_devices(
        limit: int = Query(default=500, ge=1, le=2000),
    ) -> list[dict[str, object]]:
        identities = _identity_index(store, datetime.now(UTC))
        segments = _network_segments(store)
        device_index = {
            (item["gateway_id"], item["mac_address"]): item["payload"]
            for item in store.list_gateway_devices()
        }
        result = []
        for item in store.list_inventory_observations(limit=limit):
            classified = _classify_ip(item["ip_address"])
            if classified is None:
                continue
            address, scope = classified
            metadata = _node_metadata(address, identities, segments, device_index)
            result.append({
                **metadata,
                "scope": scope,
                "protocols": sorted(item["protocols"]),
                "first_seen": item["first_seen"].isoformat(),
                "last_seen": item["last_seen"].isoformat(),
                "observations": item["observations"],
            })
        result.sort(key=lambda item: item["observations"], reverse=True)
        return result[:limit]

    @router.get("/api/v1/inventory/topology", tags=["inventory"])
    def get_network_topology(
        limit: Annotated[int, Query(ge=1, le=5000)] = 1000,
    ) -> dict[str, object]:
        identities = _identity_index(store, datetime.now(UTC))
        segments = _network_segments(store)
        device_index = {
            (item["gateway_id"], item["mac_address"]): item["payload"]
            for item in store.list_gateway_devices()
        }
        links: dict[tuple[str, str, str], dict[str, object]] = {}
        node_scopes: dict[str, str] = {}
        for item in store.list_topology_observations(limit=limit):
            source_ip = _classify_ip(item["source"])
            target_ip = _classify_ip(item["target"])
            if source_ip is None or target_ip is None:
                continue
            source, source_scope = source_ip
            target, target_scope = target_ip
            node_scopes[source] = source_scope
            node_scopes[target] = target_scope
            links[(source, target, item["protocol"])] = item

        edges = []
        for (source, target, protocol), item in links.items():
            source_scope = node_scopes[source]
            target_scope = node_scopes[target]
            if source_scope == "private" and target_scope == "public":
                direction = "outbound"
            elif source_scope == "public" and target_scope == "private":
                direction = "inbound"
            elif source_scope == target_scope == "private":
                direction = "internal"
            elif source_scope == target_scope == "public":
                direction = "external"
            else:
                direction = "other"
            edges.append({
                "source": source,
                "target": target,
                "protocol": protocol,
                "observations": item["observations"],
                "direction": direction,
                "relationship": "connection",
                "evidence_type": "observed",
                "confidence": "high",
                "source_integration_ids": item["source_integration_ids"],
                "source_event_types": item["source_event_types"],
                "first_seen": item["first_seen"].isoformat(),
                "last_seen": item["last_seen"].isoformat(),
            })

        for item in store.list_nat_observations(limit=limit):
            source_ip = _classify_ip(item["source"])
            target_ip = _classify_ip(item["target"])
            if source_ip is None or target_ip is None:
                continue
            source, source_scope = source_ip
            target, target_scope = target_ip
            node_scopes[source] = source_scope
            node_scopes[target] = target_scope
            edges.append({
                "source": source,
                "target": target,
                "protocol": item["protocol"],
                "observations": item["observations"],
                "direction": "translation",
                "relationship": "nat_translation",
                "evidence_type": "observed",
                "confidence": "high",
                "source_integration_ids": item["source_integration_ids"],
                "source_event_types": item["source_event_types"],
                "first_seen": item["first_seen"].isoformat(),
                "last_seen": item["last_seen"].isoformat(),
            })

        node_details = [
            _node_metadata(address, identities, segments, device_index)
            for address in sorted(node_scopes)
        ]
        relationships = []
        for detail in node_details:
            for segment in detail["network_segments"]:
                relationships.append({
                    "source": detail["ip_address"],
                    "target": segment["subnet"],
                    "relationship": "network_segment_membership",
                    "evidence_type": "inferred",
                    "confidence": segment["confidence"],
                    "source_integration_ids": [segment["gateway_id"]],
                    "source_event_types": ["gateway.discovery"],
                })
        return {
            "nodes": sorted(node_scopes),
            "node_details": node_details,
            "edges": edges[:limit],
            "segments": segments,
            "relationships": relationships[:limit],
        }

    return router
