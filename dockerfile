# Stage 1: Build dependencies
FROM python:3.11-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Final Runtime (Minimal Attack Surface)
FROM python:3.11-slim AS runner

WORKDIR /app

# Create a non-privileged system user
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    groupadd -g 10001 appuser && \
    useradd -u 10001 -g appuser -s /sbin/nologin -c "Docker image user" appuser

# Copy installed dependencies from builder stage
COPY --from=builder /root/.local /home/appuser/.local
COPY src/ /app/
RUN chown -R 10001:10001 /home/appuser /app

ENV PATH=/home/appuser/.local/bin:$PATH
ENV APP_ENV=production

USER 10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:8000/healthz || exit 1

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]