FROM python:3.12-slim AS base

WORKDIR /app
COPY backend/pyproject.toml ./pyproject.toml
COPY backend/openshield ./openshield
RUN pip install --no-cache-dir --root-user-action=ignore .

FROM base AS runtime

EXPOSE 8000
CMD ["uvicorn", "openshield.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

FROM base AS dev

RUN pip install --no-cache-dir --root-user-action=ignore ".[dev]"
COPY backend/tests ./tests
