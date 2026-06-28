# Base Image using Python 3.12
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Set working directory
WORKDIR /app

# Install system dependencies
# - libpcap-dev is required by Scapy for raw network socket sniffing on Linux
# - gcc and python3-dev are required for compiling certain python packages if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and install python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy source code and pre-trained machine learning models
COPY src/ /app/src/
COPY models/ /app/models/

# Expose FastAPI REST API port
EXPOSE 8000

# Run the application (respects the PORT env variable if provided, e.g. on Render/Railway)
CMD uvicorn src.api.app:app --host 0.0.0.0 --port ${PORT:-8000}

