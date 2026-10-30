
# Use Python 3.11 as the application runtime.
FROM python:3.11-slim

# Set the application working directory.
WORKDIR /app

# Configure Python runtime and module search paths.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

# Install HTTP server and request validation dependencies.
RUN pip install --no-cache-dir \
    "fastapi>=0.115,<1.0" \
    "pydantic>=2,<3" \
    "uvicorn>=0.30,<1.0"

# Copy the application source and shared schemas.
COPY src/ /app/src/

# Run the Gateway service as a non-root user.
RUN useradd --uid 10001 --create-home \
    --shell /usr/sbin/nologin appuser

USER appuser

# Expose the Gateway HTTP port.
EXPOSE 8000

# Start the Gateway API.
CMD ["uvicorn", "secure_agent.gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]
