# Stage 1 — build deps
FROM python:3.11-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# Stage 2 — runtime with Playwright
FROM python:3.11-slim AS runtime

WORKDIR /app

# Install Playwright system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
    libdrm2 libdbus-1-3 libxkbcommon0 libx11-6 libxcomposite1 \
    libxdamage1 libxext6 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 \
    libcairo2 libasound2 libexpat1 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Install Playwright browsers
RUN playwright install chromium

# Copy source
COPY . .

# Create output dirs
RUN mkdir -p logs reports screenshots

# Non-root user for security
RUN useradd -m -u 1000 webaudit && chown -R webaudit:webaudit /app
USER webaudit

ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
