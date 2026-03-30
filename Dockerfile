FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends \
    suricata \
    suricata-update \
    python3 \
    python3-pip \
    python3-venv \
    ca-certificates \
    jq \
    curl \
    procps \
    libpcre2-8-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/suricata-bench

COPY app/requirements.txt /opt/suricata-bench/requirements.txt

RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r /opt/suricata-bench/requirements.txt

COPY app /opt/suricata-bench/app
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 7007

ENTRYPOINT ["/entrypoint.sh"]