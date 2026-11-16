# Secret encryption key rotation

OpenShield encrypts integration credentials with Fernet. The Node accepts one active key (\`OPENSHIELD_SECRET_KEY\`) and a comma-separated list of previous keys (\`OPENSHIELD_SECRET_KEY_PREVIOUS\`). When a secret is read with a previous key, \ `SecretStore` immediately re-encrypts it with the active key.

## Safe rotation

1. Back up PostgreSQL and the \ `openshield-runtime-secrets` volume. Keep the backup protected; it contains sensitive encrypted data and key material.
2. Generate a new Fernet key and store it securely. Do not put it in source control or a ticket.
3. In \ `.env`, set the new key as the active key and the old key as a previous key:

   \ ```dotenv
   OPENSHIELD_SECRET_KEY=<new-fernet-key>
   OPENSHIELD_SECRET_KEY_PREVIOUS=<old-fernet-key>
   \ ```

   Multiple previous keys can be comma-separated. Keep the new active key configured after rotation; removing the override without updating the persisted \ `fernet.key` file would make the old volume key active again.
4. Restart the Node so Compose passes both values into its container:

   \ ```bash
   docker compose up -d openshield-node
   \ ```
5. Re-encrypt and verify every stored integration secret:

   \ ```bash
   docker compose exec openshield-node python -m openshield.core.secret_rotation
   \ ```

   The command prints only the number of verified secrets. It fails if a secret cannot be decrypted or cannot be verified with the active key. Keep the previous key configured if it fails.
6. Verify integration connectivity and application health. Then remove the old key from \ `OPENSHIELD_SECRET_KEY_PREVIOUS` and restart the Node.
7. Run the rotation command again. It must verify all stored secrets using only the active key. Retain protected backups until their retention period expires.

Do not remove the previous key before the verification command succeeds. Do not delete or recreate Docker volumes as part of rotation.

## Security properties

- Previous and active keys are not written to integration records, audit details, logs, or API responses.
- The rotation command emits only a verified-secret count.
- The API continues to return integration metadata, never decrypted credentials or key material.
- The previous-key list is consumed only by the Node; the gateway connector does not need it.
