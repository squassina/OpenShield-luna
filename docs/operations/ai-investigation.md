# Hybrid AI investigation

OpenShield uses AI as an analyst assistant, not as a policy engine. It explains existing incident evidence, separates facts from hypotheses, and proposes read-only next steps. AI output never changes firewall, DNS, gateway, or incident status automatically.

## 1. Local-first: Ollama

1. Run Ollama on a host reachable from OpenShield Node.
2. Pull a model supported by your hardware, for example:

```bash
ollama pull llama3.2
ollama list
```

3. In **Service integrations**, add **Ollama (local AI)**.
4. Set the API URL (for Docker deployments, use an address reachable from the Node container, not `localhost` unless Ollama runs in that same container).
5. Enter the exact installed model name, such as `llama3.2`.
6. Save; OpenShield checks `GET /api/tags` and verifies the model is available.

Incident context stays on the local network. The provider uses Ollama's non-streaming `POST /api/chat` endpoint with JSON output mode. See https://docs.ollama.com/api/chat.

## 2. Optional cloud: OpenAI

Cloud AI is disabled by default. To enable it:

1. Set `OPENSHIELD_CLOUD_AI_ENABLED=true` on Node.
2. In **Service integrations**, add **OpenAI (cloud AI)**.
3. Enter a model available to the API key.
4. Explicitly check **Allow sanitized cloud data**.
5. Enter the OpenAI API key. It is encrypted at rest using `OPENSHIELD_SECRET_KEY`.
6. Save; OpenShield verifies the API key through `GET /v1/models`.

OpenShield calls the OpenAI Responses API. The API key is sent only in the Authorization header; it is never returned by integration APIs. See https://platform.openai.com/docs/api-reference/responses and https://platform.openai.com/overview.

Cloud processing requires both the global switch and the per-integration consent flag. Unchecking the flag prevents future cloud investigations. Removing the API key revokes use by OpenShield; rotate/revoke the key in the provider console as well.

## 3. Privacy gateway

Local Ollama receives an allowlisted incident context:
- Indicator type/value, risk score/level, risk factors.
- Event metadata and normalized CrowdSec/MISP evidence.
- No raw event payloads, credentials, or full database records.

OpenAI receives a stricter aggregate context only:
- Risk score/level and factor names/points.
- Event type and severity counts.
- CrowdSec reputation/score category and MISP actionable-IOC counts/threat level.
- No IP/domain indicator values, hostnames, MACs, event IDs, integration IDs, raw logs, or provider event descriptions.

A SHA-256 context hash and data-scope metadata are stored with each investigation. The raw prompt/context is not persisted. Provider output is capped at 256 KiB and the request timeout is 45 seconds.

## 4. Investigate an incident

1. Open **Threat intelligence incidents**.
2. Select a configured AI provider.
3. Choose **AI investigate** on an incident.
4. Review the summary, confidence, observed facts, hypotheses, recommendations, and caveats.

API equivalent:

```bash
curl -X POST http://localhost:8000/api/v1/incidents/<incident-id>/investigate \
  -H 'Content-Type: application/json' \
  --data '{"provider_id":"ollama-local"}'

curl http://localhost:8000/api/v1/incidents/<incident-id>/investigations
```

Each result stores provider, model, prompt version, context scope/hash, validated output, and audit metadata.

## 5. Governance and limitations

- The prompt explicitly treats indicators, provider tags, and evidence as untrusted data. Embedded instructions are never authoritative.
- No tools, shell, browser, network actions, or policy APIs are exposed to the model.
- Output must match the versioned JSON schema; invalid output is rejected.
- Recommendations are advisory and read-only. P5 policy/approval controls remain mandatory for response.
- Confidence is model-reported, not a calibrated probability.
- Local model quality depends on hardware and model choice. Provider test verifies API/model availability, not investigation quality.
- Cloud processing incurs separate OpenAI API charges and sends the documented aggregate context outside the home network.
