# Reproducible Python and container builds

OpenShield builds target Python 3.12. Runtime, development and Python build
dependencies are resolved into separate, hash-pinned lock files:

| File | Purpose |
|---|---|
| `backend/requirements.txt` | Application runtime dependencies |
| `backend/requirements-dev.txt` | Runtime plus test, lint, type-check and audit dependencies |
| `backend/requirements-build.in` | Explicit bootstrap/build tool constraints |
| `backend/requirements-build.txt` | Hashed bootstrap/build tool lock |

The build lock pins `pip==26.3` and `setuptools==84.1.0`. The same exact
setuptools version is declared in `pyproject.toml` as the build backend
requirement. The Dockerfile installs all Python packages with
`pip install --require-hashes`, then installs the local OpenShield package
with `--no-build-isolation --no-deps` so the already-locked build/runtime
environment is used without an unpinned dependency resolution.

The three external images are pinned by manifest digest while retaining their
readable release tags:

- Python 3.12 slim runtime/build base.
- Playwright Python image at the same Playwright version as the Python lock.
- PostgreSQL 16 Alpine.

This makes each build refer to a fixed image manifest. Dependabot proposes
weekly updates for Python packages, Docker images and GitHub Actions versions;
the scheduled lock/image workflow also resolves current dependency versions and
image digests, opening a pull request rather than pushing updates to `main`.
Every update still passes the normal CI pipeline before merge.

## Regenerate locks locally

Use Python 3.12 and the pinned resolver versions:

~~~bash
python -m pip install --disable-pip-version-check "pip==26.3" "pip-tools==7.7.0"
cd backend

pip-compile --upgrade --resolver=backtracking --allow-unsafe --no-strip-extras \
  --generate-hashes --output-file requirements.txt pyproject.toml
pip-compile --upgrade --resolver=backtracking --allow-unsafe --no-strip-extras \
  --generate-hashes --extra dev --output-file requirements-dev.txt pyproject.toml
pip-compile --upgrade --resolver=backtracking --allow-unsafe --no-strip-extras \
  --generate-hashes --output-file requirements-build.txt requirements-build.in
~~~

Review the lock diff, package changelogs and security advisories. Do not remove
`--generate-hashes` or `--allow-unsafe`: the locks must include hashes for
all selected distributions and explicitly pin bootstrap tools. Avoid
hand-editing generated `requirements*.txt` files; edit `pyproject.toml` or
`requirements-build.in`, then recompile.

## Update container image digests

The scheduled GitHub Actions workflow pulls the configured release tags,
resolves their registry manifest digests, updates `Dockerfile` and
`docker-compose.yml`, and opens a review PR. When updating manually, preserve
both the readable version tag and the digest:

~~~dockerfile
FROM python:3.12-slim@sha256:<manifest-digest> AS base
~~~

~~~yaml
image: postgres:16-alpine@sha256:<manifest-digest>
~~~

Do not copy a digest from a different tag, architecture-specific child image,
or unrelated release. Keep `playwright==...` in the development lock aligned
with the `mcr.microsoft.com/playwright/python` image tag.

## Validation

The normal CI build proves that all hash-locked dependencies can be installed
in the runtime, development and browser-test stages. It also runs Ruff, mypy,
pip-audit, Python/API tests, Playwright tests, the PostgreSQL backup/restore
round-trip, and non-root runtime smoke tests. A lock/image refresh is not
accepted based only on a successful resolver run.
