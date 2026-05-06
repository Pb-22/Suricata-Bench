#!/usr/bin/env bash
set -euo pipefail

mkdir -p /data/uploads /data/rules /data/output /var/lib/suricata/rules

write_meta() {
  local status="$1"
  local message="$2"

  cat > /data/rules/et-open.meta.json <<EOF
{
  "last_updated_utc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "source": "suricata-update",
  "status": "$status",
  "message": "$message",
  "rules_file": "/data/rules/et-open.rules"
}
EOF
}

if [ ! -s /data/rules/et-open.rules ]; then
  echo "[+] Fetching free Suricata rules with suricata-update"

  if suricata-update; then
    if [ -f /var/lib/suricata/rules/suricata.rules ]; then
      cp /var/lib/suricata/rules/suricata.rules /data/rules/et-open.rules
      write_meta "ok" "Initial ruleset fetched successfully."
    else
      touch /data/rules/et-open.rules
      write_meta "failed" "suricata-update completed, but /var/lib/suricata/rules/suricata.rules was not found."
    fi
  else
    touch /data/rules/et-open.rules
    write_meta "failed" "suricata-update failed during initial startup."
  fi
fi

export FLASK_APP=app/server.py
exec python3 /opt/suricata-bench/app/server.py