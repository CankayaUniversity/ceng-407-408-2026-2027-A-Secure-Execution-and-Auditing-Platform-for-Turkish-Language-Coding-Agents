FROM python:3.11-slim

# Configure Python for container execution.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

# Install execution dependencies and permit verification primitives.
RUN python -m pip install --no-cache-dir \
    "fastapi==0.162.0" \
    "uvicorn==0.54.0" \
    "pydantic==2.14.2" \
    "PyYAML>=6,<7" \
    "pytest==9.2.0" \
    "cryptography==50.0.2" \
    "rfc8785==0.1.4"

# Create an unprivileged runtime user and workspace directory.
RUN useradd --uid 10002 --create-home \
    --shell /usr/sbin/nologin executoruser \
    && mkdir -p /workspace /app/state /app/verifier \
    && chown executoruser:executoruser /workspace /app/state \
    && chown 10001:10001 /app/verifier \
    && chmod 0755 /app/verifier
# Keep application code and trusted configuration outside the workspace.
COPY src/ /app/src/
COPY configs/test_profiles.yaml /app/configs/test_profiles.yaml
COPY demo/sample_project/README.md /workspace/README.md

# Seed the demo volume with a synthetic credential for the redaction probe.
RUN printf '\nAPI_KEY=compose-fixture-canary-7f29d4\n' >> /workspace/README.md

USER executoruser

CMD ["uvicorn", "secure_agent.execution.service:create_compose_executor", "--factory", "--host", "0.0.0.0", "--port", "8001", "--no-access-log"]
