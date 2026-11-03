FROM python:3.11-slim

# Configure Python for container execution.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

# Install execution dependencies and permit verification primitives.
RUN python -m pip install --no-cache-dir \
    "pydantic==2.14.2" \
    "PyYAML>=6,<7" \
    "pytest==9.2.0" \
    "cryptography==50.0.2" \
    "rfc8785==0.1.4"

# Create an unprivileged runtime user and workspace directory.
RUN useradd --uid 10002 --create-home \
    --shell /usr/sbin/nologin executoruser \
    && mkdir -p /workspace \
    && chown executoruser:executoruser /workspace

# Keep application code and trusted configuration outside the workspace.
COPY src/ /app/src/
COPY configs/test_profiles.yaml /app/configs/test_profiles.yaml

USER executoruser

# Keep execution disabled until the permit-enforcing entry point is connected.
CMD ["python", "-c", "raise SystemExit('Executor entry point is not configured; execution is disabled.')"]