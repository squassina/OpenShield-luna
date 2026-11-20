# Gateway spool storage, encryption and recovery

The Gateway Connector stores its durable outbox in a SQLite database at
`/var/lib/openshield/gateway-spool.sqlite3` by default. The database contains
queued normalized events, connector command-result receipts, and durable queue
counters. Event payloads can include sensitive network metadata such as IP
addresses, MAC addresses, hostnames, DNS/security observations, and integration
identifiers. Treat the database as sensitive operational data.

## Accepted Home threat model

The Home deployment model trusts the administrator and the Linux/Docker host
running the connector. The spool is **not encrypted by OpenShield**.

The connector limits accidental access on that host:

- The spool directory is mode `0700`.
- The SQLite database and WAL/SHM sidecars are mode `0600`.
- The runtime process uses UID/GID `10001`, not root.
- SQLite uses WAL and `synchronous=FULL`.

These controls protect against unrelated unprivileged host users and accidental
permissions exposure. They do not protect data from host root, a user with
Docker-daemon access, a compromised connector host, offline disk theft, or
someone who can read the underlying Docker volume or its backups.

This is an explicit boundary for the single-administrator Home deployment, not
a claim of encrypted-at-rest storage or multi-tenant isolation.

## Required host and volume protection

For any deployment where the host, storage medium, snapshot service, or backup
location is outside the trusted Home boundary, put the Docker volume on
encrypted storage before starting the connector:

- Use host block-device encryption (for example, LUKS2) for the filesystem
  holding Docker data, or use an equivalently encrypted block/file system.
- For cloud or managed storage, enable encryption for the underlying volume
  and its snapshots.
- Unlock encrypted storage before Docker starts the connector. Do not put the
  unlock key in the Compose file, container environment, or the same volume.
- Keep key recovery material separate from the encrypted disk and its backups.
- Do not export a plaintext copy of the SQLite database to an unencrypted host
  directory or backup target.

Docker named volumes do not provide application-level encryption themselves.
Encrypting only the Node database or setting restrictive file permissions does
not encrypt the connector's separate SQLite volume.

OpenShield does not add SQLCipher or custom file encryption to this spool. An
application-encrypted spool would require a separately designed key lifecycle,
rotation/recovery behavior, and compatibility testing; do not improvise
encryption by wrapping SQLite pages or storing a key beside the database.

## Consistent backup

Do not copy only `gateway-spool.sqlite3` while the connector is running. SQLite
WAL may contain committed transactions that have not yet been checkpointed
into the main database file.

Use SQLite's online backup API to create a consistent standalone snapshot. Run
this from the repository/Compose project directory while the connector is
running:

~~~bash
umask 077
docker compose --profile gateway exec -T openshield-gateway-connector python - <<'PY'
import os
import sqlite3

source_path = "/var/lib/openshield/gateway-spool.sqlite3"
snapshot_path = "/var/lib/openshield/gateway-spool-backup.sqlite3"

source = sqlite3.connect(source_path)
snapshot = sqlite3.connect(snapshot_path)
try:
    source.backup(snapshot)
finally:
    snapshot.close()
    source.close()

os.chmod(snapshot_path, 0o600)
PY

container_id="$(docker compose --profile gateway ps -q openshield-gateway-connector)"
mkdir -p backups
backup_file="backups/gateway-spool-$(date -u +%Y%m%dT%H%M%SZ).sqlite3"
docker cp "$container_id:/var/lib/openshield/gateway-spool-backup.sqlite3" "$backup_file"
docker compose --profile gateway exec -T openshield-gateway-connector \
  rm -f /var/lib/openshield/gateway-spool-backup.sqlite3
chmod 0600 "$backup_file"
~~~

Encrypt the exported snapshot before moving it off the trusted host. Keep the
decryption key in a separate secret manager or recovery system. Protect backup
retention, access, and deletion to the same standard as the source volume.
Periodically restore a snapshot into an isolated test volume and verify that
pending events, counters, and command-result receipts are readable.

## Restore and data-loss handling

Restore only while the Gateway Connector is stopped. Preserve the original
volume until the restored connector has been validated. Restore the standalone
snapshot as `/var/lib/openshield/gateway-spool.sqlite3`, owned by UID/GID
`10001:10001`, with mode `0600`; the containing directory must remain owned
by the connector user and mode `0700`. Do not copy an old WAL or SHM sidecar
alongside the standalone online-backup snapshot.

The spool contains more than undelivered telemetry: it also stores durable
command-result receipts that prevent a repeated heartbeat from reapplying a
command after its result was persisted. Losing or restoring an outdated spool
can therefore lose queued events and command receipts. Before recreating a
missing spool, reconcile outstanding gateway commands with Node state and
inspect the Node execution/audit history. Do not assume an empty new spool
proves that the gateway completed every prior command.

After restore, start the connector and verify:

1. The connector starts as UID/GID `10001:10001` and can open the database.
2. `GET /metrics` shows the expected queue depth and durable counters after
   the next heartbeat.
3. Pending events drain only after Node acknowledgement.
4. Outstanding commands and their results agree with the Node execution
   history.

Routine shutdown must not delete the named spool volume. Do not use
`docker compose down -v` for routine operations.

## Scope and residual risk

This policy documents the accepted Home host-trust boundary and the required
storage/backup controls when that boundary does not apply. It does not add
transparent application encryption, protect a running host after compromise,
or certify backup media. Multi-user/tenant deployments remain out of scope
until a separate identity and storage-security design exists.
