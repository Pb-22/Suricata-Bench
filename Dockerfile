FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    software-properties-common \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    python3 \
    python3-pip \
    python3-venv \
    python3-flask \
    python3-werkzeug \
    && add-apt-repository -y ppa:oisf/suricata-stable \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
    suricata \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/suricata-bench

COPY app /opt/suricata-bench/app
COPY entrypoint.sh /opt/suricata-bench/entrypoint.sh

RUN chmod +x /opt/suricata-bench/entrypoint.sh

VOLUME ["/data"]

EXPOSE 7007

ENTRYPOINT ["/opt/suricata-bench/entrypoint.sh"]