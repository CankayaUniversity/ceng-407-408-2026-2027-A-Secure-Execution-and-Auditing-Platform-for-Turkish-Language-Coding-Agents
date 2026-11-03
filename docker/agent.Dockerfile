FROM python:3.11-slim

# Configure Python for container execution.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app:/app/src

WORKDIR /app

# Install the dependency used by the current agent and shared schemas.
RUN python -m pip install --no-cache-dir \
    "pydantic==2.14.2"

# Create an unprivileged runtime user.
RUN useradd --uid 10001 --create-home \
    --shell /usr/sbin/nologin agentuser

# Copy the agent, tool contracts, and exposure receipt models.
COPY agent/ /app/agent/
COPY src/secure_agent/common/schemas.py /app/src/secure_agent/common/schemas.py
COPY src/secure_agent/provenance/models.py /app/src/secure_agent/provenance/models.py

USER agentuser

# Start with the existing mock model.
CMD ["python", "-m", "agent.agent_loop", "--llm-mode", "mock"]
