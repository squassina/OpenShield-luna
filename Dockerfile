FROM python:3.12-slim

WORKDIR /app
COPY backend/pyproject.toml ./pyproject.toml
COPY backend/openshield ./openshield
RUN pip install --no-cache-dir .
EXPOSE 8000
CMD ["uvicorn", "openshield.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
