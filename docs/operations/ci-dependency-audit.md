# CI dependency and type-check policy

CI builds use Docker Buildx with the GitHub Actions cache backend. Runtime, development, and browser-test targets use separate cache scopes to avoid cross-target cache replacement.

## Type-checking baseline

CI runs mypy on the typed event models, gateway models, and durable gateway spool. This is an intentionally narrow baseline; expand the checked module list as adjacent code is annotated and cleaned up. Lint and tests remain required.

## Dependency audit

CI runs `pip-audit --strict` against the packages installed in the same development image used for tests. The image is built from `backend/pyproject.toml`, so the audit examines the resolved dependency set used by that run.

There is currently no vulnerability ignore list. Do not add blanket ignores. If an advisory cannot be fixed immediately, document the exact advisory ID, affected package/version, exploitability rationale, owner, mitigation, tracking issue, and expiry date in this document; use the narrowest possible exception and remove it when resolved. Unexplained or expired exceptions fail review.

Dependency ranges are declared in `backend/pyproject.toml`; CI resolves and audits the full installed environment on every build. A committed fully pinned lockfile remains a follow-up if bit-for-bit dependency reproduction becomes a requirement.

## Local commands

```bash
docker compose run --rm --no-deps openshield-lint mypy openshield/events/models.py openshield/gateway/models.py openshield/gateway/spool.py
docker compose run --rm --no-deps openshield-lint pip-audit --strict --progress-spinner off
```
