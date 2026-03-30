#!/usr/bin/env bash
set -euo pipefail

mkdir -p /data/uploads /data/rules /data/output /var/lib/suricata/rules

if [ ! -s /data/rules/et-open.rules ]; then
  echo "[+] Fetching free Suricata rules with suricata-update"
  suricata-update || true
  if [ -f /var/lib/suricata/rules/suricata.rules ]; then
    cp /var/lib/suricata/rules/suricata.rules /data/rules/et-open.rules
  else
    touch /data/rules/et-open.rules
  fi
fi

export FLASK_APP=app/server.py
exec python3 /opt/suricata-bench/app/server.py
