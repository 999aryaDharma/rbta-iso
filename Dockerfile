# syntax=docker/dockerfile:1
# Tahap 1: build dashboard
FROM node:20-alpine AS dashboard-build

WORKDIR /build
COPY dashboard/package*.json /build/
RUN npm ci
COPY dashboard/ /build/
RUN npm run build

# Tahap 2: runtime Python
# Python 3.11 = versi run skripsi (metadata model: 3.11.15).
FROM python:3.11-slim AS runtime

ARG GIT_SHA="unknown"
ARG BUILD_DATE="unknown"
ARG RELEASE_TAG="unknown"

LABEL org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/999aryaDharma/rbta---iso" \
      org.opencontainers.image.title="RBTA + Isolation Forest Service" \
      org.opencontainers.image.description="Rule-Based Temporal Aggregation and Isolation Forest for Wazuh SIEM Security Logs" \
      org.opencontainers.image.authors="Arya Dharma"

ENV RBTA_BUILD_SHA=${GIT_SHA} \
    RBTA_RELEASE_TAG=${RELEASE_TAG} \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    RBTA_HOST=0.0.0.0 \
    RBTA_PORT=8000 \
    RBTA_MODEL_REGISTRY_DIR=/app/artifacts/models \
    RBTA_STATE_FILE=/app/data/runtime/state.json \
    RBTA_RAW_EVIDENCE_DB=/app/data/runtime/raw_alert_evidence.sqlite3 \
    RBTA_DASHBOARD_DIST=/app/dashboard/dist

# User non-root (UID/GID 10001), dipakai juga oleh chown volume di deploy/ct.
RUN groupadd --gid 10001 appgroup && \
    useradd --uid 10001 --gid appgroup --shell /bin/false --no-create-home appuser

WORKDIR /app

COPY pyproject.toml README.md constraints.txt /app/
RUN pip install --no-cache-dir -c constraints.txt .

COPY src/ /app/src/
# Ekspor bukti harian manual: docker compose exec rbta-service python scripts/export_live_evidence.py
COPY scripts/export_live_evidence.py /app/scripts/export_live_evidence.py
COPY --from=dashboard-build /build/dist /app/dashboard/dist

RUN mkdir -p /app/data/runtime /app/artifacts/models && \
    chown -R appuser:appgroup /app

USER appuser:appgroup

EXPOSE 8000

# Healthcheck cukup pakai stdlib Python, tanpa curl di image.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8000/health", timeout=2)' || exit 1

CMD ["python", "-m", "src.api.server"]
