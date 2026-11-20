from psycopg.types.json import Jsonb


class PostgresIntegrationStoreMixin:
    """Integration, secret and polling-cursor persistence for the PostgreSQL store."""

    def set_integration_secret(self, integration_id: str, encrypted_value: bytes) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO integration_secrets (integration_id, encrypted_value)
                VALUES (%s, %s)
                ON CONFLICT (integration_id) DO UPDATE
                SET encrypted_value = EXCLUDED.encrypted_value, updated_at = NOW()
                """,
                (integration_id, encrypted_value),
            )
            self._insert_audit(
                cursor, "integration.secret.updated", None, integration_id,
                {"encrypted": True},
            )

    def get_integration_secret(self, integration_id: str) -> bytes | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT encrypted_value FROM integration_secrets WHERE integration_id = %s",
                (integration_id,),
            )
            row = cursor.fetchone()
        return bytes(row[0]) if row else None

    def list_integration_secret_ids(self) -> list[str]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT integration_id FROM integration_secrets ORDER BY integration_id"
            )
            rows = cursor.fetchall()
        return [str(row[0]) for row in rows]

    def delete_integration_secret(self, integration_id: str) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM integration_secrets WHERE integration_id = %s RETURNING integration_id",
                (integration_id,),
            )
            deleted = cursor.fetchone() is not None
            if deleted:
                self._insert_audit(
                    cursor, "integration.secret.deleted", None, integration_id, {},
                )
            return deleted

    def insert_integration(
        self, integration: Integration, actor_id: str | None = None
    ) -> None:
        payload = integration.model_dump(mode="json")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO integrations (integration_id, payload)
                VALUES (%s, %s)
                ON CONFLICT (integration_id) DO NOTHING
                RETURNING integration_id
                """,
                (integration.integration_id, Jsonb(payload)),
            )
            if cursor.fetchone() is None:
                raise ValueError("Integration already exists")
            self._insert_audit(
                cursor,
                "integration.registered",
                actor_id,
                integration.integration_id,
                {
                    "kind": integration.kind,
                    "capabilities": [item.value for item in integration.capabilities],
                },
            )

    def get_integration(self, integration_id: str) -> Integration | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM integrations WHERE integration_id = %s",
                (integration_id,),
            )
            row = cursor.fetchone()
        return Integration.model_validate(row[0]) if row else None

    def list_integrations(self) -> list[Integration]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM integrations ORDER BY integration_id"
            )
            rows = cursor.fetchall()
        return [Integration.model_validate(row[0]) for row in rows]

    def update_integration(
        self, integration: Integration, actor_id: str | None = None
    ) -> Integration | None:
        payload = integration.model_dump(mode="json")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE integrations SET payload = %s
                WHERE integration_id = %s
                RETURNING integration_id
                """,
                (Jsonb(payload), integration.integration_id),
            )
            if cursor.fetchone() is None:
                return None
            self._insert_audit(
                cursor, "integration.updated", actor_id, integration.integration_id,
                {"kind": integration.kind},
            )
        return integration

    def delete_integration(
        self, integration_id: str, actor_id: str | None = None
    ) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM integrations WHERE integration_id = %s RETURNING payload",
                (integration_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return False
            integration = Integration.model_validate(row[0])
            self._insert_audit(
                cursor, "integration.deleted", actor_id, integration_id,
                {"kind": integration.kind, "history_preserved": True},
            )
        return True

    def get_integration_poll_cursor(self, integration_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT cursor FROM integration_poll_cursors WHERE integration_id = %s",
                (integration_id,),
            )
            row = cursor.fetchone()
        return row[0] if row else None

    def delete_integration_poll_cursor(self, integration_id: str) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM integration_poll_cursors WHERE integration_id = %s RETURNING integration_id",
                (integration_id,),
            )
            return cursor.fetchone() is not None

    def set_integration_poll_cursor(
        self, integration_id: str, provider_kind: str, value: dict[str, object]
    ) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO integration_poll_cursors (integration_id, provider_kind, cursor)
                VALUES (%s, %s, %s)
                ON CONFLICT (integration_id) DO UPDATE
                SET provider_kind = EXCLUDED.provider_kind,
                    cursor = EXCLUDED.cursor, updated_at = NOW()
                """,
                (integration_id, provider_kind, Jsonb(value)),
            )

    def checkpoint_integration_poll_page(
        self,
        integration_id: str,
        provider_kind: str,
        value: dict[str, object],
        completion_details: dict[str, object],
        rejection_details: dict[str, object] | None = None,
    ) -> None:
        """Atomically persist page diagnostics and advance its provider cursor."""
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO integration_poll_cursors (integration_id, provider_kind, cursor)
                VALUES (%s, %s, %s)
                ON CONFLICT (integration_id) DO UPDATE
                SET provider_kind = EXCLUDED.provider_kind,
                    cursor = EXCLUDED.cursor, updated_at = NOW()
                """,
                (integration_id, provider_kind, Jsonb(value)),
            )
            if rejection_details is not None:
                self._insert_audit(
                    cursor, "privacy.provider_poll.records_rejected", None,
                    integration_id, rejection_details,
                )
            self._insert_audit(
                cursor, "privacy.provider_poll.completed", None,
                integration_id, completion_details,
            )

