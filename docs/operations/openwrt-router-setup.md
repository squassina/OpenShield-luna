# OpenWrt router setup

The standard Docker Compose deployment starts the local Gateway Connector automatically. Node provisions a Fernet encryption key and an internal gateway token on first startup, then stores both in the persistent `openshield-runtime-secrets` volume.

## Configure the router

1. Open the OpenShield dashboard.
2. Under **OpenWrt router**, enter the router URL, RPC username, and password.
3. Save the credentials. OpenShield encrypts them at rest and delivers them only to the local Gateway Connector.
4. The connector validates access and begins sending discovery and health events.

No manual `OPENSHIELD_SECRET_KEY` or `OPENSHIELD_GATEWAY_TOKEN` setup is required for a standard Compose deployment. Explicit environment values remain supported for externally managed deployments.

## Persistence and recovery

- Keep the `openshield-runtime-secrets` Docker volume. It contains the encryption key and connector token.
- Back up this volume securely together with the database. Restoring the database without the matching encryption key makes stored router credentials unreadable.
- Do not delete the runtime secrets volume during upgrades or routine maintenance.
- To replace router credentials, save the new username/password through the dashboard. Do not rotate the encryption key as part of routine credential changes.

The Gateway Connector runs on the same Docker host as Node and reads the internal token from the shared volume mounted read-only. The router password is not exposed to the browser after submission or written to logs.
