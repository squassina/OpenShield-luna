from datetime import UTC, datetime

from psycopg.types.json import Jsonb


class PostgresPolicyStoreMixin:
    """Policy and decision persistence shared by the PostgreSQL store."""

    def create_policy(self, policy: dict[str, object]) -> dict[str, object]:
        created_at = datetime.now(UTC)
        payload = {
            **policy,
            "created_at": created_at.isoformat(),
            "updated_at": created_at.isoformat(),
        }
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO policies
                    (policy_id, name, enabled, indicator_type, indicator_value, action,
                     integration_id, min_risk_score, autonomy_level, ttl_seconds,
                     require_approval, direction)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    policy["policy_id"], policy["name"], policy.get("enabled", True),
                    policy["indicator_type"], policy["indicator_value"], policy["action"],
                    policy["integration_id"], policy["min_risk_score"], policy["autonomy_level"],
                    policy["ttl_seconds"], policy.get("require_approval", True),
                    policy.get("direction", "destination"),
                ),
            )
            self._insert_audit(
                cursor, "policy.created", None, str(policy["policy_id"]),
                {"action": policy["action"], "integration_id": policy["integration_id"],
                 "autonomy_level": policy["autonomy_level"], "ttl_seconds": policy["ttl_seconds"]},
            )
        return payload

    def list_policies(self, enabled_only: bool = False) -> list[dict[str, object]]:
        where = "WHERE enabled = TRUE" if enabled_only else ""
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"SELECT policy_id, name, enabled, indicator_type, indicator_value, action, "
                f"integration_id, min_risk_score, autonomy_level, ttl_seconds, require_approval, "
                f"direction, created_at, updated_at FROM policies {where} ORDER BY name"
            )
            rows = cursor.fetchall()
        return [
            {
                "policy_id": row[0], "name": row[1], "enabled": row[2],
                "indicator_type": row[3], "indicator_value": row[4], "action": row[5],
                "integration_id": row[6], "min_risk_score": row[7], "autonomy_level": row[8],
                "ttl_seconds": row[9], "require_approval": row[10], "direction": row[11],
                "created_at": row[12].isoformat(), "updated_at": row[13].isoformat(),
            }
            for row in rows
        ]

    def get_policy(self, policy_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT policy_id, name, enabled, indicator_type, indicator_value, action,
                       integration_id, min_risk_score, autonomy_level, ttl_seconds,
                       require_approval, direction, created_at, updated_at
                FROM policies WHERE policy_id = %s
                """,
                (policy_id,),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return {
            "policy_id": row[0], "name": row[1], "enabled": row[2],
            "indicator_type": row[3], "indicator_value": row[4], "action": row[5],
            "integration_id": row[6], "min_risk_score": row[7], "autonomy_level": row[8],
            "ttl_seconds": row[9], "require_approval": row[10], "direction": row[11],
            "created_at": row[12].isoformat(), "updated_at": row[13].isoformat(),
        }

    def update_policy(self, policy_id: str, changes: dict[str, object]) -> dict[str, object] | None:
        allowed = {
            "name", "enabled", "min_risk_score", "autonomy_level", "ttl_seconds",
            "require_approval", "direction",
        }
        updates = {key: value for key, value in changes.items() if key in allowed}
        if not updates:
            return self.get_policy(policy_id)
        assignments = ", ".join(f"{key} = %s" for key in updates)
        values = list(updates.values())
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"UPDATE policies SET {assignments}, updated_at = NOW() WHERE policy_id = %s",
                (*values, policy_id),
            )
            if cursor.rowcount == 0:
                return None
            self._insert_audit(cursor, "policy.updated", None, policy_id, updates)
        return self.get_policy(policy_id)

    def create_policy_decision(
        self, decision_id: str, incident_id: str, policy_id: str,
        status: str, rationale: dict[str, object],
    ) -> dict[str, object]:
        now = datetime.now(UTC)
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO policy_decisions
                    (decision_id, incident_id, policy_id, status, rationale)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (decision_id, incident_id, policy_id, status, Jsonb(rationale)),
            )
            self._insert_audit(
                cursor, "policy.decision.created", None, decision_id,
                {"incident_id": incident_id, "policy_id": policy_id, "status": status},
            )
        return {
            "decision_id": decision_id, "incident_id": incident_id,
            "policy_id": policy_id, "status": status, "rationale": rationale,
            "created_at": now.isoformat(),
        }

    def list_policy_decisions(self, limit: int = 100) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT decision_id, incident_id, policy_id, status, rationale,
                       created_at, updated_at
                FROM policy_decisions ORDER BY created_at DESC LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [
            {
                "decision_id": row[0], "incident_id": row[1], "policy_id": row[2],
                "status": row[3], "rationale": row[4],
                "created_at": row[5].isoformat(), "updated_at": row[6].isoformat(),
            }
            for row in rows
        ]

    def get_policy_decision(self, decision_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT decision_id, incident_id, policy_id, status, rationale,
                       created_at, updated_at
                FROM policy_decisions WHERE decision_id = %s
                """,
                (decision_id,),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return {
            "decision_id": row[0], "incident_id": row[1], "policy_id": row[2],
            "status": row[3], "rationale": row[4],
            "created_at": row[5].isoformat(), "updated_at": row[6].isoformat(),
        }

    def update_policy_decision(
        self, decision_id: str, status: str, rationale: dict[str, object] | None = None
    ) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT rationale FROM policy_decisions WHERE decision_id = %s FOR UPDATE",
                (decision_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            payload = {**row[0], **(rationale or {}), "status": status}
            cursor.execute(
                """
                UPDATE policy_decisions SET status = %s, rationale = %s, updated_at = NOW()
                WHERE decision_id = %s
                """,
                (status, Jsonb(payload), decision_id),
            )
            self._insert_audit(
                cursor, "policy.decision.status.updated", None, decision_id,
                {"status": status, **(rationale or {})},
            )
        return self.get_policy_decision(decision_id)

