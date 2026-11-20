FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS base

WORKDIR /app
COPY backend/pyproject.toml ./pyproject.toml
COPY backend/requirements-build.txt backend/requirements.txt ./
RUN python -m pip install --disable-pip-version-check --no-cache-dir \
        --require-hashes -r requirements-build.txt \
    && python -m pip install --disable-pip-version-check --no-cache-dir \
        --require-hashes -r requirements.txt

COPY backend/openshield ./openshield
RUN python -m pip install --disable-pip-version-check --no-cache-dir \
    --no-build-isolation --no-deps --root-user-action=ignore .

FROM base AS runtime

RUN groupadd --system --gid 10001 openshield \
    && useradd --system --uid 10001 --gid openshield --home-dir /home/openshield \
        --create-home --shell /usr/sbin/nologin openshield \
    && install -d -o openshield -g openshield -m 0700 \
        /run/openshield-secrets /var/lib/openshield

USER 10001:10001

EXPOSE 8000
CMD ["uvicorn", "openshield.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

FROM base AS dev

COPY backend/requirements-dev.txt ./requirements-dev.txt
RUN python -m pip install --disable-pip-version-check --no-cache-dir \
    --require-hashes -r requirements-dev.txt
COPY backend/tests ./tests
COPY scripts/ops ./scripts/ops
COPY scripts/backup.sh scripts/restore.sh ./scripts/
COPY scripts/update_cname_tracker_feed.py ./scripts/update_cname_tracker_feed.py

# The official image already contains Chromium and its OS libraries.
# Avoid apt-get / Playwright's --with-deps downloads in CI, where mirror DNS
# failures can make browser installation fail before tests even start.
FROM mcr.microsoft.com/playwright/python:v1.64.1-noble@sha256:330d401ae23c905896a0c26c66c36fc971b621519e7b11b435a8328d7bf6e031 AS browser-test

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app
COPY backend/pyproject.toml ./pyproject.toml
COPY backend/requirements-build.txt backend/requirements-dev.txt ./
RUN python -m pip install --disable-pip-version-check --no-cache-dir \
        --require-hashes -r requirements-build.txt \
    && python -m pip install --disable-pip-version-check --no-cache-dir \
        --require-hashes -r requirements-dev.txt
COPY backend/openshield ./openshield
RUN python -m pip install --disable-pip-version-check --no-cache-dir \
    --no-build-isolation --no-deps --root-user-action=ignore .
COPY tests/dashboard ./dashboard-tests
