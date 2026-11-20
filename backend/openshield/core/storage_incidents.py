from datetime import UTC, datetime

from psycopg.types.json import Jsonb

from openshield.events.models import EventEnvelope


class PostgresIncidentStoreMixin:
    """Incident and investigation persistence for the PostgreSQL store."""

    def create_incident_investigation(
        self, investigation_id: str, incident_id: str, provider_integration_id: str,
        provider_kind: str, model: str, prompt_version: str,
        context_scope: dict[str, object], result: dict[str, object],
    ) -> dict[str, object]:
        created_at = datetime.now(UTC)
        payload = {
            "investigation_id": investigation_id,
            "incident_id": incident_id,
            "provider_integration_id": provider_integration_id,
            "provider_kind": provider_kind,
            "model": model,
            "prompt_version": prompt_version,
            "context_scope": context_scope,
            "result": result,
            "created_at": created_at.isoformat(),
        }
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO incident_investigations
                    (investigation_id, incident_id, provider_integration_id, provider_kind,
                     model, prompt_version, context_scope, result, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    investigation_id, incident_id, provider_integration_id, provider_kind,
                    model, prompt_version, Jsonb(context_scope), Jsonb(result), created_at,
                ),
            )
            self._insert_audit(
                cursor, "incident.investigation.created", None, incident_id,
                {
                    "investigation_id": investigation_id,
                    "provider_integration_id": provider_integration_id,
                    "provider_kind": provider_kind,
                    "model": model,
                    "prompt_version": prompt_version,
                    "context_scope": context_scope,
                },
            )
        return payload


    def list_incident_investigations(
        self, incident_id: str, limit: int = 10
    ) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT investigation_id, incident_id, provider_integration_id,
                       provider_kind, model, prompt_version, context_scope, result, created_at
                FROM incident_investigations
                WHERE incident_id = %s
                ORDER BY created_at DESC LIMIT %s
                """,
                (incident_id, limit),
            )
            rows = cursor.fetchall()
        return [
            {
                "investigation_id": row[0], "incident_id": row[1],
                "provider_integration_id": row[2], "provider_kind": row[3],
                "model": row[4], "prompt_version": row[5],
                "context_scope": row[6], "result": row[7],
                "created_at": row[8].isoformat(),
            }
            for row in rows
        ]


    def upsert_incident(
        self, incident: dict[str, object], event_ids: list[str],
        first_seen_at: datetime, last_seen_at: datetime,
    ) -> dict[str, object]:
        indicator_type = str(incident["indicator_type"])
        indicator_value = str(incident["indicator_value"])
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))",
                (f"{indicator_type}:{indicator_value}",),
            )
            cursor.execute(
                """
                SELECT incident_id, status, payload, first_seen_at, last_seen_at
                FROM incidents
                WHERE indicator_type = %s AND indicator_value = %s
                FOR UPDATE
                """,
                (indicator_type, indicator_value),
            )
            row = cursor.fetchone()
            if row:
                incident_id, status, existing, old_first, old_last = row
                merged_event_ids = sorted(set(existing.get("event_ids", [])) | set(event_ids))
                merged_sources = sorted(set(existing.get("sources", [])) | set(incident.get("sources", [])))
                merged_evidence = {**existing.get("intel_evidence", {}), **incident.get("intel_evidence", {})}
                merged_source_events = {
                    item["event_id"]: item
                    for item in [*existing.get("source_events", []), *incident.get("source_events", [])]
                    if isinstance(item, dict) and isinstance(item.get("event_id"), str)
                }
                payload = {
                    **existing, **incident, "incident_id": incident_id,
                    "status": status, "event_ids": merged_event_ids,
                    "sources": merged_sources, "intel_evidence": merged_evidence,
                    "source_events": list(merged_source_events.values()),
                    "created_at": existing.get("created_at", incident.get("created_at")),
                }
                old_score = int(existing.get("risk_score", 0))
                if old_score > int(incident["risk_score"]):
                    payload["risk_score"] = old_score
                    payload["risk_level"] = existing.get("risk_level", incident.get("risk_level"))
                    payload["risk_factors"] = existing.get("risk_factors", incident.get("risk_factors", []))
                if status == "closed" and set(event_ids) - set(existing.get("event_ids", [])):
                    status = "open"
                    payload["status"] = status
                first_seen = min(old_first, first_seen_at)
                last_seen = max(old_last, last_seen_at)
                cursor.execute(
                    """
                    UPDATE incidents SET status = %s, risk_score = %s, payload = %s,
                        first_seen_at = %s, last_seen_at = %s, updated_at = NOW()
                    WHERE incident_id = %s
                    """,
                    (status, int(payload["risk_score"]), Jsonb(payload), first_seen, last_seen, incident_id),
                )
                action = "incident.updated"
            else:
                incident_id = str(incident["incident_id"])
                status = str(incident.get("status", "open"))
                payload = {**incident, "incident_id": incident_id, "status": status,
                           "event_ids": sorted(set(event_ids))}
                first_seen, last_seen = first_seen_at, last_seen_at
                cursor.execute(
                    """
                    INSERT INTO incidents
                        (incident_id, indicator_type, indicator_value, status, risk_score,
                         payload, first_seen_at, last_seen_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (incident_id, indicator_type, indicator_value, status,
                     int(payload["risk_score"]), Jsonb(payload), first_seen, last_seen),
                )
                action = "incident.created"
            for event_id in event_ids:
                cursor.execute(
                    """
                    INSERT INTO incident_events (incident_id, event_id)
                    VALUES (%s, %s) ON CONFLICT DO NOTHING
                    """,
                    (incident_id, event_id),
                )
            self._insert_audit(
                cursor, action, None, incident_id,
                {"indicator_type": indicator_type, "indicator_value": indicator_value,
                 "risk_score": int(payload["risk_score"]), "event_count": len(payload["event_ids"])},
            )
        return payload

    def list_incidents(
        self, limit: int = 100, status: str | None = None
    ) -> list[dict[str, object]]:
        filters = "WHERE status = %s" if status else ""
        params = (status, limit) if status else (limit,)
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"SELECT payload FROM incidents {filters} "
                "ORDER BY risk_score DESC, last_seen_at DESC LIMIT %s",
                params,
            )
            rows = cursor.fetchall()
        return [row[0] for row in rows]

    def get_incident(self, incident_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM incidents WHERE incident_id = %s", (incident_id,)
            )
            row = cursor.fetchone()
        return row[0] if row else None

    def get_incident_events(self, incident_id: str) -> list[EventEnvelope]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT e.payload FROM incident_events ie
                JOIN events e ON e.event_id = ie.event_id
                WHERE ie.incident_id = %s
                ORDER BY e.received_at ASC, e.event_id ASC
                """,
                (incident_id,),
            )
            rows = cursor.fetchall()
        return [EventEnvelope.model_validate(row[0]) for row in rows]

    def update_incident_status(
        self, incident_id: str, status: str, reason: str = ""
    ) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM incidents WHERE incident_id = %s FOR UPDATE",
                (incident_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            payload = {**row[0], "status": status, "status_reason": reason}
            cursor.execute(
                """
                UPDATE incidents SET status = %s, payload = %s, updated_at = NOW()
                WHERE incident_id = %s
                """,
                (status, Jsonb(payload), incident_id),
            )
            self._insert_audit(
                cursor, "incident.status.updated", None, incident_id,
                {"status": status, "reason": reason[:200]},
            )
        return payload

