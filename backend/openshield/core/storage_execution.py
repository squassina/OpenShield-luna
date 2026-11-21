from datetime import UTC, datetime

from psycopg.types.json import Jsonb


class PostgresExecutionStoreMixin:
    """Response execution, gateway command and emergency-stop persistence."""

    def _insert_response_execution(self, cursor, execution: dict[str, object]) -> None:
        cursor.execute(
            """
            INSERT INTO response_executions
                (execution_id, decision_id, incident_id, policy_id, integration_id,
                 action, indicator_type, indicator_value, direction, status, ttl_seconds,
                 expires_at, adapter_result)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                execution["execution_id"], execution["decision_id"], execution["incident_id"],
                execution["policy_id"], execution["integration_id"], execution["action"],
                execution["indicator_type"], execution["indicator_value"], execution["direction"],
                execution["status"], execution["ttl_seconds"], execution.get("expires_at"),
                Jsonb(execution.get("adapter_result", {})),
            ),
        )
        self._insert_audit(
            cursor, "response.execution.created", None, str(execution["execution_id"]),
            {"action": execution["action"], "indicator_type": execution["indicator_type"],
             "integration_id": execution["integration_id"], "status": execution["status"],
             "ttl_seconds": execution["ttl_seconds"]},
        )

    def create_response_execution(self, execution: dict[str, object]) -> dict[str, object]:
        with self._connect() as connection, connection.cursor() as cursor:
            self._insert_response_execution(cursor, execution)
        return execution

    def create_response_execution_if_absent(self, execution: dict[str, object]) -> bool:
        lock_key = "\x1f".join(
            str(execution[key]) for key in ("integration_id", "indicator_type", "indicator_value")
        )
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (lock_key,),
            )
            cursor.execute(
                """
                SELECT 1 FROM response_executions
                WHERE indicator_type = %s AND indicator_value = %s AND integration_id = %s
                  AND status IN ('pending_gateway', 'active', 'rollback_pending', 'rollback_failed')
                LIMIT 1
                """,
                (execution["indicator_type"], execution["indicator_value"], execution["integration_id"]),
            )
            if cursor.fetchone() is not None:
                return False
            self._insert_response_execution(cursor, execution)
        return True

    @staticmethod
    def _response_execution_from_row(row: tuple[object, ...]) -> dict[str, object]:
        return {
            "execution_id": row[0], "decision_id": row[1], "incident_id": row[2],
            "policy_id": row[3], "integration_id": row[4], "action": row[5],
            "indicator_type": row[6], "indicator_value": row[7], "direction": row[8],
            "status": row[9], "ttl_seconds": row[10],
            "expires_at": row[11].isoformat() if row[11] else None,
            "adapter_result": row[12], "created_at": row[13].isoformat(),
            "rolled_back_at": row[14].isoformat() if row[14] else None,
        }

    def get_response_execution(self, execution_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT execution_id, decision_id, incident_id, policy_id, integration_id,
                       action, indicator_type, indicator_value, direction, status, ttl_seconds,
                       expires_at, adapter_result, created_at, rolled_back_at
                FROM response_executions WHERE execution_id = %s
                """,
                (execution_id,),
            )
            row = cursor.fetchone()
        return self._response_execution_from_row(row) if row is not None else None

    def update_response_execution(
        self, execution_id: str, status: str,
        adapter_result: dict[str, object] | None = None,
        expires_at: datetime | None = None, rolled_back_at: datetime | None = None,
    ) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE response_executions SET status = %s,
                    adapter_result = COALESCE(%s, adapter_result),
                    expires_at = COALESCE(%s, expires_at),
                    rolled_back_at = COALESCE(%s, rolled_back_at)
                WHERE execution_id = %s
                """,
                (
                    status, Jsonb(adapter_result) if adapter_result is not None else None,
                    expires_at, rolled_back_at, execution_id,
                ),
            )
            if cursor.rowcount == 0:
                return None
            self._insert_audit(
                cursor, "response.execution.status.updated", None, execution_id,
                {"status": status, **(adapter_result or {})},
            )
        return self.get_response_execution(execution_id)

    def list_response_executions(self, limit: int = 100) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT execution_id, decision_id, incident_id, policy_id, integration_id,
                       action, indicator_type, indicator_value, direction, status, ttl_seconds,
                       expires_at, adapter_result, created_at, rolled_back_at
                FROM response_executions
                ORDER BY created_at DESC LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [self._response_execution_from_row(row) for row in rows]

    def get_due_response_executions(self) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT execution_id, decision_id, incident_id, policy_id, integration_id,
                       action, indicator_type, indicator_value, direction, status, ttl_seconds,
                       expires_at, adapter_result, created_at, rolled_back_at
                FROM response_executions
                WHERE status IN ('active', 'rollback_failed') AND expires_at IS NOT NULL AND expires_at <= NOW()
                ORDER BY expires_at ASC LIMIT 50
                """
            )
            rows = cursor.fetchall()
        return [self._response_execution_from_row(row) for row in rows]

    def has_active_response_execution(
        self, indicator_type: str, indicator_value: str,
        integration_id: str, exclude_execution_id: str | None = None,
    ) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT 1 FROM response_executions
                WHERE indicator_type = %s AND indicator_value = %s AND integration_id = %s
                  AND status IN ('pending_gateway', 'active', 'rollback_pending', 'rollback_failed')
                  AND (%s::text IS NULL OR execution_id <> %s)
                LIMIT 1
                """,
                (indicator_type, indicator_value, integration_id, exclude_execution_id, exclude_execution_id),
            )
            return cursor.fetchone() is not None

    def enqueue_gateway_command(
        self, command_id: str, gateway_id: str, execution_id: str,
        action: str, payload: dict[str, object],
    ) -> dict[str, object]:
        now = datetime.now(UTC)
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO gateway_commands
                    (command_id, gateway_id, execution_id, action, payload, status)
                VALUES (%s, %s, %s, %s, %s, 'pending')
                """,
                (command_id, gateway_id, execution_id, action, Jsonb(payload)),
            )
            self._insert_audit(
                cursor, "gateway.command.queued", None, command_id,
                {"gateway_id": gateway_id, "execution_id": execution_id, "action": action},
            )
        return {
            "command_id": command_id, "gateway_id": gateway_id, "execution_id": execution_id,
            "action": action, "payload": payload, "status": "pending", "created_at": now.isoformat(),
        }

    def list_pending_gateway_commands(self, gateway_id: str, limit: int = 10) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT command_id, execution_id, action, payload, created_at
                FROM gateway_commands
                WHERE gateway_id = %s AND status = 'pending'
                ORDER BY created_at ASC LIMIT %s
                """,
                (gateway_id, limit),
            )
            rows = cursor.fetchall()
        return [
            {
                "command_id": row[0], "execution_id": row[1],
                "action": row[2], "payload": row[3], "created_at": row[4].isoformat(),
            }
            for row in rows
        ]

    def has_pending_gateway_command(self, execution_id: str, action: str) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT 1 FROM gateway_commands
                WHERE execution_id = %s AND action = %s AND status = 'pending'
                LIMIT 1
                """,
                (execution_id, action),
            )
            return cursor.fetchone() is not None

    def get_gateway_command(self, command_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT command_id, gateway_id, execution_id, action, payload,
                       status, result, created_at
                FROM gateway_commands WHERE command_id = %s
                """,
                (command_id,),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return {
            "command_id": row[0], "gateway_id": row[1], "execution_id": row[2],
            "action": row[3], "payload": row[4], "status": row[5],
            "result": row[6], "created_at": row[7].isoformat(),
        }

    def complete_gateway_command(
        self, command_id: str, status: str, result: dict[str, object]
    ) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT status, result FROM gateway_commands WHERE command_id = %s FOR UPDATE",
                (command_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            if row[0] == "pending":
                cursor.execute(
                    """
                    UPDATE gateway_commands SET status = %s, result = %s, updated_at = NOW()
                    WHERE command_id = %s
                    """,
                    (status, Jsonb(result), command_id),
                )
                self._insert_audit(
                    cursor, "gateway.command.completed", None, command_id,
                    {"status": status, "result_status": result.get("status")},
                )
            elif row[0] != status or row[1] != result:
                return None
        return self.get_gateway_command(command_id)

    def get_emergency_stop(self) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT value FROM runtime_controls WHERE control_key = 'emergency_stop'"
            )
            row = cursor.fetchone()
        return bool(row[0].get("active", True)) if row else True

    def set_emergency_stop(self, active: bool, actor_id: str | None = None) -> None:
        value = {"active": active}
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO runtime_controls (control_key, value)
                VALUES ('emergency_stop', %s)
                ON CONFLICT (control_key) DO UPDATE
                SET value = EXCLUDED.value, updated_at = NOW()
                """,
                (Jsonb(value),),
            )
            self._insert_audit(
                cursor, "response.emergency_stop.updated", actor_id, "emergency_stop", value,
            )

