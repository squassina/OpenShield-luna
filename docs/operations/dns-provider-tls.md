# Per-integration DNS provider TLS trust

Pi-hole and AdGuard integrations use normal TLS certificate and hostname verification. For providers using a private certificate authority, configure a CA bundle on that integration only. This extends the container's normal public CA trust; it does not disable verification or change trust for other integrations.

## 1. Mount the CA bundle

Docker Compose mounts the host directory `./certs` read-only at `/run/openshield/ca` inside the Node container.

Copy the CA root and any required intermediate CA certificates into a PEM bundle. Do not use the provider's leaf/server certificate as a substitute for its issuing CA.

Example:

```bash
mkdir -p certs
cat private-root-ca.pem private-intermediate-ca.pem > certs/pihole-ca.pem
chmod 0644 certs/pihole-ca.pem
docker compose up -d openshield-node
```

The `certs/` directory is ignored by Git. Keep private PKI material out of the repository. The certificates are public trust anchors, but should still be managed as infrastructure configuration.

## 2. Configure each integration

Set `ca_bundle_path` in the integration's `config`. The path is the absolute path **inside the Node container**, not the host path.

Pi-hole example:

```bash
curl -X PATCH http://localhost:8000/api/v1/integrations/pihole-1 \
  -H 'Content-Type: application/json' \
  --data '{
    "config": {
      "base_url": "https://pihole.example.lan",
      "ca_bundle_path": "/run/openshield/ca/pihole-ca.pem"
    }
  }'
```

AdGuard can use a different bundle:

```json
{
  "config": {
    "base_url": "https://adguard.example.lan",
    "ca_bundle_path": "/run/openshield/ca/adguard-ca.pem"
  }
}
```

When updating an integration, send its complete config object, including existing non-secret settings such as `base_url`. Credentials remain in the existing secret environment variables and are not placed in integration config.

## 3. Behavior and safety

- `ca_bundle_path` is optional and supported for Pi-hole and AdGuard integrations.
- It must be an absolute PEM file path available to the Node process.
- A custom CA bundle requires an `https://` provider URL.
- The configured CA is added to the system trust store; public roots remain trusted.
- Certificate-chain validation and hostname verification remain enabled.
- Each provider request uses the CA configured on that specific integration. Other integrations are unaffected.
- Missing, unreadable, invalid, or incompatible CA bundles fail closed with a sanitized provider error.
- Omitting `ca_bundle_path` preserves the existing system-default TLS behavior.

The CA path is configuration, not a credential. Do not put API keys, passwords, or private keys in this field.
