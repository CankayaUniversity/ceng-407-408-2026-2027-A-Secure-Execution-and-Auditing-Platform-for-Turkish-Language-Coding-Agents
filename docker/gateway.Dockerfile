
# Use Python 3.11 as the application runtime.
FROM python:3.11-slim

# Set the application working directory.
WORKDIR /app

# Configure Python runtime and module search paths.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

# Install the HTTP and security dependencies used by the Compose demo.
RUN pip install --no-cache-dir \
    "fastapi==0.162.0" \
    "pydantic==2.14.2" \
    "uvicorn==0.54.0" \
    "httpx==0.28.1" \
    "python-dotenv==1.2.4" \
    "casbin==1.43.0" \
    "networkx==3.6.1" \
    "cryptography==50.0.2" \
    "rfc8785==0.1.4" \
    "PyYAML>=6,<7"

# Copy the application source and shared schemas.
COPY src/ /app/src/
COPY configs/casbin_model.conf configs/casbin_policy.csv /app/configs/
COPY scripts/run_demo.py /app/scripts/run_demo.py

# Run the Gateway service as a non-root user.
RUN useradd --uid 10001 --create-home \
    --shell /usr/sbin/nologin appuser

RUN mkdir -p /app/data /app/issuer /app/verifier \
    && chown appuser:appuser /app/data /app/issuer /app/verifier \
    && chmod 0700 /app/issuer

USER appuser

# Expose the Gateway HTTP port.
EXPOSE 8000

# Start the Gateway API.
CMD ["uvicorn", "secure_agent.gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]
