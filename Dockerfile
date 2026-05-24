# Use official, stable, minimal Python runtime
FROM python:3.12-slim

# Set strict execution environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Set locked-down work directory
WORKDIR /app

# Install security utilities and iptables packet managers
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy python dependencies list
COPY requirements.txt .

# Install locked-down dependency packages
RUN pip install --no-cache-dir -r requirements.txt

# Copy all project files
COPY . .

# Create a non-privileged system user for process isolation
RUN useradd -u 10001 -U -d /app logsentry && \
    chown -R logsentry:logsentry /app

# Switch to the isolated, non-root user context
USER logsentry

# Expose backend REST API port
EXPOSE 8000

# Start FastAPI API server safely
CMD ["python", "-m", "uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
