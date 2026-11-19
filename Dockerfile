FROM python:3.12-slim AS base

RUN python -m pip install --no-cache-dir --upgrade "pip>=26.2,<27"

WORKDIR /app
COPY backend/pyproject.toml ./pyproject.toml
COPY backend/openshield ./openshield
RUN pip install --no-cache-dir --root-user-action=ignore .

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

RUN pip install --no-cache-dir --root-user-action=ignore ".[dev]"
COPY backend/tests ./tests
COPY scripts/ops ./scripts/ops
COPY scripts/backup.sh scripts/restore.sh ./scripts/
COPY scripts/update_cname_tracker_feed.py ./scripts/update_cname_tracker_feed.py

FROM dev AS browser-test

COPY tests/dashboard ./dashboard-tests
RUN apt-get update \
    && apt-get install -y --no-install-recommends libatomic1 \
    && rm -rf /var/lib/apt/lists/*
RUN python -m playwright install --with-deps chromium
