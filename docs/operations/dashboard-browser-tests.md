# Dashboard browser tests in CI

OpenShield runs the dashboard browser suite with Playwright and Chromium in a dedicated Docker build target. The setup deliberately avoids downloading Linux browser dependencies with APT during CI.

## Why the dedicated image exists

The hosted Ubuntu runner previously failed while running Playwright's dependency installation. APT could not resolve Ubuntu mirrors (for example, `security.ubuntu.com` and `archive.ubuntu.com`), so browser setup exited with code 100 before the tests ran. Retrying the same APT operation does not address that DNS dependency.

The `browser-test` target in the repository `Dockerfile` uses the official `mcr.microsoft.com/playwright/python:v1.64.1-noble` image. It already contains Chromium and its required OS libraries. The Python Playwright package remains pinned to the matching version in `backend/pyproject.toml`.

## Run locally

From the repository root:

```bash
docker compose build openshield-browser-test
docker compose run --rm openshield-browser-test
```

The service runs Ruff against `tests/dashboard` and then executes the browser tests with Pytest. Docker Engine and the Docker Compose plugin are the only host prerequisites.

## CI requirements

The GitHub Actions workflow builds `openshield-browser-test` with the other validation images and runs that service directly. Keep the Playwright Python package version and official browser image version aligned when upgrading either dependency.

Do not add any of the following to the browser-test CI path:

- `playwright install --with-deps`
- `npx playwright install --with-deps`
- `apt-get install` for Chromium or Playwright system libraries

Those commands reintroduce a dependency on Ubuntu package mirror DNS. If the official image itself cannot be pulled, diagnose the container registry/network failure separately; do not silently fall back to APT or skip the browser tests.

## Troubleshooting

- **APT mirror DNS errors:** confirm the workflow is building the `browser-test` target and running `openshield-browser-test`, not installing browser dependencies on the runner.
- **Playwright version mismatch:** align `playwright==...` in `backend/pyproject.toml` with the tag of `mcr.microsoft.com/playwright/python:...`.
- **Browser executable missing:** inspect the image build and `PLAYWRIGHT_BROWSERS_PATH=/ms-playwright`; do not mask the error by skipping the suite.

The browser suite remains a required CI check. This workaround changes dependency provisioning, not test coverage.
