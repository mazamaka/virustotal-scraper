FROM python:3.11-slim

# Install chromium and dependencies for headless
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxkbcommon0 \
    libxrandr2 \
    xdg-utils \
    && rm -rf /var/lib/apt/lists/*

# Set Chrome path for nodriver
ENV CHROME_PATH=/usr/bin/chromium

WORKDIR /app

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir nodriver

# Copy application
COPY vt_scraper.py .

# Create directories
RUN mkdir -p /app/json /data

# Volume for results and input files
VOLUME ["/app/json", "/data"]

ENTRYPOINT ["python", "vt_scraper.py"]
