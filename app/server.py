import json
import os
import re
import subprocess
import tempfile
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from werkzeug.utils import secure_filename

BASE_DIR = Path("/data")
UPLOAD_DIR = BASE_DIR / "uploads"
RULE_DIR = BASE_DIR / "rules"
OUTPUT_DIR = BASE_DIR / "output"
DEFAULT_RULES = RULE_DIR / "et-open.rules"
CUSTOM_RULES = RULE_DIR / "custom.rules"
PALETTE_FILE = BASE_DIR / "palette.json"
SURICATA_PORT = int(os.environ.get("SURICATA_PORT", "7007"))
MAX_UPLOAD_MB = 250

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
RULE_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

DEFAULT_PALETTE = {
    "bg": "#1e1b2e",
    "panel": "#2b2740",
    "panel_alt": "#35304f",
    "accent": "#f59e0b",
    "accent_soft": "#fcd34d",
    "text": "#fef9c3",
    "muted": "#c4b5fd",
    "border": "#5b547a",
    "success": "#a7f3d0",
    "danger": "#fdba74",
}

SID_RE = re.compile(r"sid\s*:\s*(\d+)\s*;")
MSG_RE = re.compile(r'msg\s*:\s*"([^"]+)"\s*;')
UNDEFINED_VAR_RE = re.compile(r'Variable "([^"]+)" is not defined', re.IGNORECASE)
PARSE_SIG_RE = re.compile(r'error parsing signature "(.*?)"', re.IGNORECASE)


def load_palette():
    if PALETTE_FILE.exists():
        try:
            data = json.loads(PALETTE_FILE.read_text())
            if isinstance(data, dict):
                merged = DEFAULT_PALETTE.copy()
                merged.update({k: v for k, v in data.items() if isinstance(v, str)})
                return merged
        except Exception:
            pass
    return DEFAULT_PALETTE


def save_palette(palette):
    safe = DEFAULT_PALETTE.copy()
    for key in safe:
        value = palette.get(key)
        if isinstance(value, str) and re.fullmatch(r"#[0-9a-fA-F]{6}", value):
            safe[key] = value
    PALETTE_FILE.write_text(json.dumps(safe, indent=2))


def parse_rule_map(rule_text):
    rule_map = {}
    for raw_line in rule_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        sid_match = SID_RE.search(line)
        if sid_match:
            sid = sid_match.group(1)
            msg_match = MSG_RE.search(line)
            rule_map[sid] = {
                "rule": line,
                "msg": msg_match.group(1) if msg_match else "",
            }
    return rule_map


def build_ruleset(include_defaults, custom_rule_text):
    combined_parts = []
    if include_defaults and DEFAULT_RULES.exists():
        combined_parts.append(DEFAULT_RULES.read_text(errors="ignore"))
    combined_parts.append(custom_rule_text or "")
    combined = "\n\n".join(part for part in combined_parts if part.strip()) + "\n"
    CUSTOM_RULES.write_text(custom_rule_text or "")
    return combined, parse_rule_map(combined)


def build_suricata_yaml(temp_dir, rule_file_path):
    yaml_text = f"""
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: "1521"
    SSH_PORTS: "22"
rule-files:
  - {rule_file_path}
default-rule-path: {temp_dir}
stats:
  enabled: no
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: {temp_dir}/eve.json
      types:
        - alert:
            payload: yes
            packet: yes
            http: yes
        - http
        - dns
        - tls
pcap-file:
  checksum-checks: no
logging:
  default-log-level: notice
  outputs:
    - console:
        enabled: yes
app-layer:
  protocols:
    tls:
      enabled: yes
    http:
      enabled: yes
    dns:
      enabled: yes
""".strip()
    cfg = Path(temp_dir) / "suricata.yaml"
    cfg.write_text(yaml_text)
    return cfg


def summarize_stderr(stderr_text):
    lines = [line.strip() for line in (stderr_text or "").splitlines() if line.strip()]

    undefined_vars = Counter()
    parse_errors = 0
    other_lines = []

    for line in lines:
        var_match = UNDEFINED_VAR_RE.search(line)
        if var_match:
            undefined_vars[var_match.group(1)] += 1

        if "error parsing signature" in line.lower():
            parse_errors += 1

        if not var_match and "error parsing signature" not in line.lower():
            other_lines.append(line)

    summary_lines = []
    if undefined_vars:
        parts = [f"{name} ({count})" for name, count in undefined_vars.most_common()]
        summary_lines.append("Undefined vars: " + ", ".join(parts))
    if parse_errors:
        summary_lines.append(f"Signature parse errors: {parse_errors}")
    if other_lines:
        summary_lines.append(f"Other stderr lines: {len(other_lines)}")

    summary_text = "\n".join(summary_lines) if summary_lines else "(none)"

    return {
        "line_count": len(lines),
        "undefined_vars": dict(undefined_vars),
        "signature_parse_errors": parse_errors,
        "other_line_count": len(other_lines),
        "summary_text": summary_text,
        "sample_other_lines": other_lines[:25],
        "raw_excerpt": lines[:200],
    }


def build_status_text(result):
    parts = [
        f"Run complete. Alerts: {result.get('alert_count', 0)}",
        f"Rules enabled: {result.get('rules_enabled_count', 0)}",
    ]

    stderr_summary = result.get("stderr_summary", {})
    if stderr_summary.get("line_count", 0) > 0:
        parts.append("")
        parts.append("Diagnostics:")
        parts.append(stderr_summary.get("summary_text", "(none)"))
    else:
        parts.append("")
        parts.append("Diagnostics:")
        parts.append("(none)")

    return "\n".join(parts)


def run_suricata_on_pcap(pcap_path, include_defaults, custom_rules):
    run_id = datetime.utcnow().strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:8]
    run_dir = OUTPUT_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    rules_text, rule_map = build_ruleset(include_defaults, custom_rules)
    if not rules_text.strip():
        return {
            "ok": False,
            "error": "No rules were enabled. Turn on the default ruleset or paste at least one custom rule.",
        }

    temp_dir = tempfile.mkdtemp(prefix="suribench-", dir=str(run_dir))
    rule_file = Path(temp_dir) / "active.rules"
    rule_file.write_text(rules_text)
    cfg = build_suricata_yaml(temp_dir, rule_file)

    cmd = [
        "suricata",
        "-r",
        str(pcap_path),
        "-c",
        str(cfg),
        "-l",
        temp_dir,
        "-k",
        "none",
    ]

    proc = subprocess.run(cmd, capture_output=True, text=True)
    eve_path = Path(temp_dir) / "eve.json"
    alerts = []

    if eve_path.exists():
        for line in eve_path.read_text(errors="ignore").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "alert":
                continue

            alert = event.get("alert", {})
            sid = str(alert.get("signature_id", ""))
            rule_info = rule_map.get(sid, {})

            alerts.append(
                {
                    "timestamp": event.get("timestamp", ""),
                    "src_ip": event.get("src_ip", ""),
                    "src_port": event.get("src_port", ""),
                    "dest_ip": event.get("dest_ip", ""),
                    "dest_port": event.get("dest_port", ""),
                    "signature": alert.get("signature", ""),
                    "category": alert.get("category", ""),
                    "severity": alert.get("severity", ""),
                    "sid": sid,
                    "matched_rule": rule_info.get("rule", "Rule text not found in active ruleset."),
                    "matched_rule_msg": rule_info.get("msg", ""),
                }
            )

    stderr_summary = summarize_stderr(proc.stderr)
    rules_enabled_count = len(rule_map)

    result = {
        "ok": True,
        "run_id": run_id,
        "return_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "stderr_summary": stderr_summary,
        "alerts": alerts,
        "alert_count": len(alerts),
        "rules_enabled_count": rules_enabled_count,
    }

    result["status_text"] = build_status_text(result)
    (run_dir / "result.json").write_text(json.dumps(result, indent=2))
    return result


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", palette=load_palette())


@app.route("/api/palette", methods=["POST"])
def update_palette():
    payload = request.get_json(force=True, silent=True) or {}
    save_palette(payload)
    return jsonify({"ok": True, "palette": load_palette()})


@app.route("/api/run", methods=["POST"])
def api_run():
    include_defaults = request.form.get("include_defaults", "true").lower() == "true"
    custom_rules = request.form.get("custom_rules", "")
    file = request.files.get("pcap")

    if not file or not file.filename:
        return jsonify({"ok": False, "error": "Please choose a PCAP file to test."}), 400

    filename = secure_filename(file.filename)
    if not filename.lower().endswith((".pcap", ".pcapng")):
        return jsonify({"ok": False, "error": "Only .pcap and .pcapng files are supported."}), 400

    saved_path = UPLOAD_DIR / f"{uuid.uuid4().hex}-{filename}"
    file.save(saved_path)

    try:
        result = run_suricata_on_pcap(saved_path, include_defaults, custom_rules)
        return jsonify(result), 200
    finally:
        if saved_path.exists():
            saved_path.unlink()


@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify(
        {
            "ok": True,
            "default_rules_present": DEFAULT_RULES.exists(),
            "palette": load_palette(),
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=SURICATA_PORT, debug=False)