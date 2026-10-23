# Multi-stage Dockerfile for Aletheia DeDFIR Platform
# Stage 1: Build Frontend UI
FROM node:20-alpine AS frontend-builder
WORKDIR /app/wasp-ui
COPY wasp-ui/package*.json ./
RUN npm ci --silent
COPY wasp-ui/ ./
RUN npm run build

# Stage 2: Forensic Backend & Runner
FROM python:3.12-slim-bookworm
WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy source code and build artifacts
COPY src/ /app/src/
COPY contracts/ /app/contracts/
COPY api/ /app/api/
COPY run_artifacts/ /app/run_artifacts/
COPY docs/ /app/docs/
COPY pyproject.toml start_api.py run_demo.py wasp.py /app/

# Copy built frontend assets
COPY --from=frontend-builder /app/wasp-ui/dist /app/wasp-ui/dist

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/api/v1/health || exit 1

CMD ["python", "start_api.py"]
