import json
import os
import re
import shutil
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
LUA_RULE_DIR = RULE_DIR / "lua"
META_FILE = RULE_DIR / "et-open.meta.json"
PALETTE_FILE = BASE_DIR / "palette.json"

SURICATA_PORT = int(os.environ.get("SURICATA_PORT", "7007"))
MAX_UPLOAD_MB = 250

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
RULE_DIR.mkdir(parents=True, exist_ok=True)
LUA_RULE_DIR.mkdir(parents=True, exist_ok=True)
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
DISABLED_RULE_RE = re.compile(r"^\s*#\s*(alert|drop|reject|pass)\s+", re.IGNORECASE)
APP_LAYER_EVENT_RE = re.compile(r"app-layer-event\s*:\s*([A-Za-z0-9_-]+)\.", re.IGNORECASE)
LUA_RULE_REFERENCE_RE = re.compile(r"lua\s*:\s*([A-Za-z0-9_./-]+)", re.IGNORECASE)
LUA_FILENAME_RE = re.compile(r"^[A-Za-z0-9_-]+(?:\.lua)?$", re.IGNORECASE)

SUPPORTED_APP_PROTOCOLS_CACHE = None


def utc_now():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def get_supported_app_protocols():
    """
    Ask the Suricata binary inside this container what app-layer parsers it supports.
    This lets disabled-rule suppression adapt automatically if a newer/different
    Suricata build later adds DNP3, Modbus, ENIP, etc.
    """
    global SUPPORTED_APP_PROTOCOLS_CACHE

    if SUPPORTED_APP_PROTOCOLS_CACHE is not None:
        return SUPPORTED_APP_PROTOCOLS_CACHE

    supported = set()

    try:
        proc = subprocess.run(
            ["suricata", "--list-app-layer-protos"],
            capture_output=True,
            text=True,
            timeout=20,
        )

        text = (proc.stdout or "") + "\n" + (proc.stderr or "")

        for raw_line in text.splitlines():
            line = raw_line.strip().lower()

            if not line:
                continue

            if line.startswith("="):
                continue

            if "supported app layer protocols" in line:
                continue

            if re.fullmatch(r"[a-z0-9_-]+", line):
                supported.add(line)

    except Exception:
        supported = set()

    SUPPORTED_APP_PROTOCOLS_CACHE = supported
    return supported


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


def load_meta():
    if META_FILE.exists():
        try:
            data = json.loads(META_FILE.read_text(errors="ignore"))
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return {}


def get_ruleset_status():
    meta = load_meta()
    rules_size = DEFAULT_RULES.stat().st_size if DEFAULT_RULES.exists() else 0

    return {
        "rules_file": str(DEFAULT_RULES),
        "rules_present": DEFAULT_RULES.exists() and rules_size > 0,
        "rules_size_bytes": rules_size,
        "last_updated_utc": meta.get("last_updated_utc", ""),
        "source": meta.get("source", "unknown"),
        "status": meta.get("status", "unknown"),
        "message": meta.get("message", ""),
    }


def write_ruleset_meta(status, message, stdout="", stderr="", return_code=None):
    meta = {
        "last_updated_utc": utc_now(),
        "source": "suricata-update",
        "status": status,
        "message": message,
        "rules_file": str(DEFAULT_RULES),
        "return_code": return_code,
        "stdout_excerpt": (stdout or "")[-5000:],
        "stderr_excerpt": (stderr or "")[-5000:],
    }
    META_FILE.write_text(json.dumps(meta, indent=2))


def refresh_default_rules():
    proc = subprocess.run(["suricata-update"], capture_output=True, text=True)
    generated = Path("/var/lib/suricata/rules/suricata.rules")

    if proc.returncode == 0 and generated.exists():
        DEFAULT_RULES.write_text(generated.read_text(errors="ignore"))
        write_ruleset_meta(
            "ok",
            "Rules refreshed successfully.",
            proc.stdout,
            proc.stderr,
            proc.returncode,
        )
        ok = True
        message = "Rules refreshed successfully."
    else:
        if not DEFAULT_RULES.exists():
            DEFAULT_RULES.write_text("")

        write_ruleset_meta(
            "failed",
            "Rules refresh failed. Existing cached rules were left in place if present.",
            proc.stdout,
            proc.stderr,
            proc.returncode,
        )
        ok = False
        message = "Rules refresh failed. Existing cached rules were left in place if present."

    return {
        "ok": ok,
        "message": message,
        "return_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "ruleset_status": get_ruleset_status(),
    }


def parse_rule_map(rule_text, include_disabled=False):
    rule_map = {}

    for raw_line in rule_text.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        disabled = False
        active_line = line
        display_line = line

        if line.startswith("#"):
            if not include_disabled:
                continue

            if not DISABLED_RULE_RE.search(line):
                continue

            disabled = True
            active_line = re.sub(r"^\s*#\s*", "", line, count=1)

        sid_match = SID_RE.search(active_line)
        if sid_match:
            sid = sid_match.group(1)
            msg_match = MSG_RE.search(active_line)
            rule_map[sid] = {
                "rule": display_line,
                "active_rule": active_line,
                "msg": msg_match.group(1) if msg_match else "",
                "disabled": disabled,
            }

    return rule_map


def should_suppress_disabled_rule(active_rule):
    """
    Suppress only from the disabled-rule test pass.

    This keeps noisy/untestable disabled rules from polluting diagnostics while
    preserving future compatibility. If a future Suricata build supports a parser
    such as DNP3, rules using app-layer-event:dnp3.* will no longer be suppressed.
    """
    lower_rule = active_rule.lower()
    supported_protocols = get_supported_app_protocols()

    event_match = APP_LAYER_EVENT_RE.search(active_rule)
    if event_match:
        proto = event_match.group(1).lower()
        if proto not in supported_protocols:
            return True

    # Old example/list rules that need real populated hash lists.
    # They are not useful for coverage review and cause Suricata 8 rohash noise.
    if "filemd5:fileextraction-chksum.list" in lower_rule:
        return True

    if "filesha1:fileextraction-chksum.list" in lower_rule:
        return True

    if "filesha256:fileextraction-chksum.list" in lower_rule:
        return True

    # Stale app-layer event name not present in this engine.
    if "mime_malformed_msg" in lower_rule:
        return True

    return False


def extract_disabled_rules(rule_text):
    disabled_rules = []

    for raw_line in rule_text.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        if not DISABLED_RULE_RE.search(line):
            continue

        active_line = re.sub(r"^\s*#\s*", "", line, count=1)

        if not SID_RE.search(active_line):
            continue

        if should_suppress_disabled_rule(active_line):
            continue

        disabled_rules.append(active_line)

    return "\n".join(disabled_rules) + ("\n" if disabled_rules else "")


def build_ruleset(include_defaults, custom_rule_text):
    combined_parts = []

    if include_defaults and DEFAULT_RULES.exists():
        combined_parts.append(DEFAULT_RULES.read_text(errors="ignore"))

    combined_parts.append(custom_rule_text or "")

    combined = "\n\n".join(part for part in combined_parts if part.strip()) + "\n"

    CUSTOM_RULES.write_text(custom_rule_text or "")

    return combined, parse_rule_map(combined)


def build_disabled_ruleset():
    if not DEFAULT_RULES.exists():
        return "", {}

    default_text = DEFAULT_RULES.read_text(errors="ignore")
    disabled_text = extract_disabled_rules(default_text)
    disabled_rule_map = parse_rule_map(disabled_text, include_disabled=False)

    return disabled_text, disabled_rule_map


def write_support_file(path, values):
    path.write_text("\n".join(values) + "\n")


def create_support_files(temp_dir):
    """
    Create placeholder files that some rules may reference.

    These are intentionally non-matching placeholder values. They are only here
    to prevent missing-file parser failures for rules that reference side files.
    """
    temp_path = Path(temp_dir)

    dummy_md5 = "00000000000000000000000000000000"
    dummy_sha1 = "0000000000000000000000000000000000000000"
    dummy_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"

    write_support_file(
        temp_path / "fileextraction-chksum.list",
        [dummy_md5, dummy_sha1, dummy_sha256],
    )

    write_support_file(temp_path / "filemd5.list", [dummy_md5])
    write_support_file(temp_path / "filesha1.list", [dummy_sha1])
    write_support_file(temp_path / "filesha256.list", [dummy_sha256])
    write_support_file(temp_path / "md5.list", [dummy_md5])
    write_support_file(temp_path / "sha1.list", [dummy_sha1])
    write_support_file(temp_path / "sha256.list", [dummy_sha256])
    write_support_file(temp_path / "filename.list", ["suricata-bench-placeholder.bin"])
    write_support_file(temp_path / "filemagic.list", ["Suricata Bench Placeholder"])


def copy_lua_support_files(temp_dir):
    temp_path = Path(temp_dir)

    if not LUA_RULE_DIR.exists():
        return []

    copied = []

    for source in sorted(LUA_RULE_DIR.rglob("*.lua")):
        if not source.is_file():
            continue

        relative = source.relative_to(RULE_DIR)
        destination = temp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        copied.append(str(relative))

    return copied


def normalize_lua_filename(raw_value):
    value = (raw_value or "").strip()

    if not value:
        return True, "custom.lua", "custom.lua will be used."

    if not LUA_FILENAME_RE.fullmatch(value):
        return False, "", "Invalid filename. Use letters, numbers, _ or - only, with optional .lua at the end."

    base = value[:-4] if value.lower().endswith(".lua") else value
    normalized = f"{base.lower()}.lua"
    return True, normalized, f"{normalized} will be used."


def stage_inline_lua_script(temp_dir, script_text, filename):
    if not (script_text or "").strip():
        return ""

    destination = Path(temp_dir) / "lua" / filename
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(script_text)
    return str(destination.relative_to(Path(temp_dir)))


def collect_lua_warnings(use_lua, script_text, normalized_filename, custom_rules):
    warnings = []
    script_present = bool((script_text or "").strip())
    refs = LUA_RULE_REFERENCE_RE.findall(custom_rules or "")
    refs_lower = [ref.strip().lower() for ref in refs if ref.strip()]
    expected_ref = f"lua/{normalized_filename}".lower() if normalized_filename else ""

    if script_present and not use_lua:
        warnings.append("Lua script text was provided, so Lua support was enabled automatically for this run.")

    if use_lua and not script_present:
        warnings.append("Lua support was enabled, but no Lua script text was provided.")

    if script_present and not refs_lower:
        warnings.append("A Lua script was provided, but the custom rule does not reference it with lua:<filename>.")

    if script_present and refs_lower and expected_ref and expected_ref not in refs_lower:
        warnings.append(
            f"Rule references {', '.join(refs_lower)}, but the inline Lua editor filename is {expected_ref}."
        )

    return warnings


def build_suricata_yaml(temp_dir, rule_file_path):
    create_support_files(temp_dir)

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
    SSH_SERVERS: "$HOME_NET"
    FTP_SERVERS: "$HOME_NET"
    SIP_SERVERS: "$HOME_NET"
    AIM_SERVERS: "$EXTERNAL_NET"

    DNP3_SERVERS: "$HOME_NET"
    MODBUS_SERVERS: "$HOME_NET"
    ENIP_SERVERS: "$HOME_NET"
    BACNET_SERVERS: "$HOME_NET"
    MQTT_SERVERS: "$HOME_NET"
    KRB5_SERVERS: "$HOME_NET"
    DC_SERVERS: "$HOME_NET"

  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: "1521"
    SSH_PORTS: "22"
    FTP_PORTS: "21"
    SIP_PORTS: "5060"

    DNP3_PORTS: "20000"
    MODBUS_PORTS: "502"
    ENIP_PORTS: "44818"
    BACNET_PORTS: "47808"
    MQTT_PORTS: "1883"
    KRB5_PORTS: "88"

rule-files:
  - {rule_file_path}

default-rule-path: {temp_dir}

classification-file: /etc/suricata/classification.config
reference-config-file: /etc/suricata/reference.config

security:
  lua:
    allow-rules: true

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
            tagged-packets: yes
        - anomaly
        - dns
        - http
        - tls
        - files
        - smtp
        - smb
        - ftp
        - ssh
        - mqtt
        - krb5
        - ike
        - quic
        - rdp
        - dhcp

pcap-file:
  checksum-checks: no

logging:
  default-log-level: notice
  outputs:
    - console:
        enabled: yes

stream:
  memcap: 64mb
  checksum-validation: no
  reassembly:
    memcap: 256mb
    depth: 0
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560

host-mode: auto

app-layer:
  protocols:
    telnet:
      enabled: yes
      detection-enabled: yes

    rfb:
      enabled: yes
      detection-enabled: yes

    mqtt:
      enabled: yes
      detection-enabled: yes

    krb5:
      enabled: yes
      detection-enabled: yes

    ike:
      enabled: yes
      detection-enabled: yes

    tls:
      enabled: yes
      detection-enabled: yes

    dcerpc:
      enabled: yes
      detection-enabled: yes

    ftp:
      enabled: yes
      detection-enabled: yes

    rdp:
      enabled: yes
      detection-enabled: yes

    ssh:
      enabled: yes
      detection-enabled: yes

    http2:
      enabled: yes
      detection-enabled: yes

    smtp:
      enabled: yes
      detection-enabled: yes
      raw-extraction: no
      mime:
        decode-mime: yes
        decode-base64: yes
        decode-quoted-printable: yes
        header-value-depth: 2000
        extract-urls: yes
        body-md5: no

    imap:
      enabled: detection-only

    smb:
      enabled: yes
      detection-enabled: yes

    nfs:
      enabled: yes
      detection-enabled: yes

    tftp:
      enabled: yes
      detection-enabled: yes

    dns:
      tcp:
        enabled: yes
        detection-enabled: yes
      udp:
        enabled: yes
        detection-enabled: yes

    http:
      enabled: yes
      detection-enabled: yes
      libhtp:
        default-config:
          personality: IDS
          request-body-limit: 0
          response-body-limit: 0
          request-body-minimal-inspect-size: 32kb
          request-body-inspect-window: 4kb
          response-body-minimal-inspect-size: 40kb
          response-body-inspect-window: 16kb
          response-body-decompress-layer-limit: 2
          http-body-inline: auto
          swf-decompression:
            enabled: yes
            type: both
            compress-depth: 100kb
            decompress-depth: 100kb
          double-decode-path: no
          double-decode-query: no

    ntp:
      enabled: yes
      detection-enabled: yes

    dhcp:
      enabled: yes
      detection-enabled: yes

    sip:
      enabled: yes
      detection-enabled: yes

    snmp:
      enabled: yes
      detection-enabled: yes

    failed:
      enabled: yes

    template:
      enabled: yes

file-store:
  version: 2
  enabled: yes
  dir: {temp_dir}/filestore
  write-fileinfo: yes
  stream-depth: 0
  force-magic: yes

file-store-stream-depth: 0

defrag:
  memcap: 32mb

flow:
  memcap: 128mb
  hash-size: 65536
  prealloc: 10000

detect:
  profile: medium
  custom-values:
    toclient-src-groups: 2
    toclient-dst-groups: 2
    toclient-sp-groups: 2
    toclient-dp-groups: 3
    toserver-src-groups: 2
    toserver-dst-groups: 4
    toserver-sp-groups: 2
    toserver-dp-groups: 25
  sgh-mpm-context: auto
  inspection-recursion-limit: 3000

mpm-algo: auto

threading:
  set-cpu-affinity: no

runmode: single
""".strip()

    cfg = Path(temp_dir) / "suricata.yaml"
    cfg.write_text(yaml_text)
    return cfg


def summarize_stderr(stderr_text):
    lines = [line.strip() for line in (stderr_text or "").splitlines() if line.strip()]

    undefined_vars = Counter()
    parse_errors = 0
    protocol_disabled = Counter()
    missing_files = Counter()
    other_lines = []

    for line in lines:
        var_match = UNDEFINED_VAR_RE.search(line)
        proto_match = re.search(r"protocol\s+([a-zA-Z0-9_-]+)\s+is disabled", line, re.IGNORECASE)
        missing_file_match = re.search(r"opening hash file\s+([^:]+):\s+No such file or directory", line, re.IGNORECASE)

        if var_match:
            undefined_vars[var_match.group(1)] += 1

        if proto_match:
            protocol_disabled[proto_match.group(1).lower()] += 1

        if missing_file_match:
            missing_files[Path(missing_file_match.group(1)).name] += 1

        if "error parsing signature" in line.lower():
            parse_errors += 1

        if (
            not var_match
            and not proto_match
            and not missing_file_match
            and "error parsing signature" not in line.lower()
        ):
            other_lines.append(line)

    summary_lines = []

    if undefined_vars:
        parts = [f"{name} ({count})" for name, count in undefined_vars.most_common()]
        summary_lines.append("Undefined vars: " + ", ".join(parts))

    if protocol_disabled:
        parts = [f"{name} ({count})" for name, count in protocol_disabled.most_common()]
        summary_lines.append("Disabled protocols referenced by rules: " + ", ".join(parts))

    if missing_files:
        parts = [f"{name} ({count})" for name, count in missing_files.most_common()]
        summary_lines.append("Missing hash/list files: " + ", ".join(parts))

    if parse_errors:
        summary_lines.append(f"Signature parse errors: {parse_errors}")

    if other_lines:
        summary_lines.append(f"Other stderr lines: {len(other_lines)}")

    summary_text = "\n".join(summary_lines) if summary_lines else "(none)"

    return {
        "line_count": len(lines),
        "undefined_vars": dict(undefined_vars),
        "protocol_disabled": dict(protocol_disabled),
        "missing_files": dict(missing_files),
        "signature_parse_errors": parse_errors,
        "other_line_count": len(other_lines),
        "summary_text": summary_text,
        "sample_other_lines": other_lines[:25],
        "raw_excerpt": lines[:200],
    }


def parse_eve_alerts(eve_path, rule_map):
    alerts = []

    if not eve_path.exists():
        return alerts

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
                "proto": event.get("proto", ""),
                "app_proto": event.get("app_proto", ""),
                "signature": alert.get("signature", ""),
                "category": alert.get("category", ""),
                "severity": alert.get("severity", ""),
                "sid": sid,
                "gid": str(alert.get("gid", "")),
                "rev": str(alert.get("rev", "")),
                "matched_rule": rule_info.get("rule", "Rule text not found in active ruleset."),
                "active_test_rule": rule_info.get("active_rule", ""),
                "matched_rule_msg": rule_info.get("msg", ""),
                "disabled_rule": bool(rule_info.get("disabled", False)),
            }
        )

    return alerts


def run_suricata_pass(pcap_path, run_dir, pass_name, rules_text, rule_map, inline_lua_script_text="", inline_lua_filename="custom.lua"):
    if not rules_text.strip():
        return {
            "ok": False,
            "return_code": None,
            "stdout": "",
            "stderr": "",
            "stderr_summary": summarize_stderr(""),
            "alerts": [],
            "alert_count": 0,
            "rules_enabled_count": 0,
            "message": "No rules available for this pass.",
        }

    temp_dir = tempfile.mkdtemp(prefix=f"suribench-{pass_name}-", dir=str(run_dir))

    rule_file = Path(temp_dir) / f"{pass_name}.rules"
    rule_file.write_text(rules_text)

    lua_scripts_available = copy_lua_support_files(temp_dir)
    inline_script_relative = stage_inline_lua_script(temp_dir, inline_lua_script_text, inline_lua_filename)
    if inline_script_relative:
        lua_scripts_available.append(inline_script_relative)
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
    alerts = parse_eve_alerts(eve_path, rule_map)
    stderr_summary = summarize_stderr(proc.stderr)

    return {
        "ok": True,
        "return_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "stderr_summary": stderr_summary,
        "alerts": alerts,
        "alert_count": len(alerts),
        "rules_enabled_count": len(rule_map),
        "lua_scripts_available": lua_scripts_available,
    }


def build_status_text(result):
    parts = [
        f"Run complete.\nAlerts: {result.get('alert_count', 0)}",
        f"Rules enabled: {result.get('rules_enabled_count', 0)}",
    ]

    lua_scripts = result.get("lua_scripts_available") or []
    if lua_scripts:
        parts.append(f"Lua scripts available: {', '.join(lua_scripts)}")

    if result.get("coverage_review_enabled"):
        parts.append(f"Disabled-rule coverage alerts: {result.get('disabled_alert_count', 0)}")
        parts.append(f"Disabled rules tested: {result.get('disabled_rules_enabled_count', 0)}")

    for warning in result.get("lua_warnings", []):
        parts.append(f"Lua note: {warning}")

    stderr_summary = result.get("stderr_summary", {})

    parts.append("")
    parts.append("Diagnostics:")

    if stderr_summary.get("line_count", 0) > 0:
        parts.append(stderr_summary.get("summary_text", "(none)"))
    else:
        parts.append("(none)")

    disabled_summary = result.get("disabled_stderr_summary", {})

    if result.get("coverage_review_enabled"):
        parts.append("")
        parts.append("Disabled-rule coverage diagnostics:")

        if disabled_summary.get("line_count", 0) > 0:
            parts.append(disabled_summary.get("summary_text", "(none)"))
        else:
            parts.append("(none)")

    return "\n".join(parts)


def run_suricata_on_pcap(pcap_path, include_defaults, custom_rules, coverage_review, use_lua=False, lua_script_text="", lua_filename="custom.lua"):
    run_id = datetime.utcnow().strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:8]
    run_dir = OUTPUT_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    rules_text, rule_map = build_ruleset(include_defaults, custom_rules)

    if not rules_text.strip():
        return {
            "ok": False,
            "error": "No rules were enabled.\nTurn on the default ruleset or paste at least one custom rule.",
        }

    active_result = run_suricata_pass(
        pcap_path=pcap_path,
        run_dir=run_dir,
        pass_name="active",
        rules_text=rules_text,
        rule_map=rule_map,
        inline_lua_script_text=lua_script_text if use_lua else "",
        inline_lua_filename=lua_filename,
    )

    disabled_alerts = []
    disabled_stderr_summary = summarize_stderr("")
    disabled_rules_enabled_count = 0
    disabled_return_code = None
    disabled_stdout = ""
    disabled_stderr = ""

    coverage_review_enabled = bool(coverage_review and include_defaults)

    if coverage_review_enabled:
        disabled_rules_text, disabled_rule_map = build_disabled_ruleset()
        disabled_result = run_suricata_pass(
            pcap_path=pcap_path,
            run_dir=run_dir,
            pass_name="disabled",
            rules_text=disabled_rules_text,
            rule_map=disabled_rule_map,
            inline_lua_script_text=lua_script_text if use_lua else "",
            inline_lua_filename=lua_filename,
        )

        disabled_alerts = disabled_result.get("alerts", [])
        disabled_stderr_summary = disabled_result.get("stderr_summary", summarize_stderr(""))
        disabled_rules_enabled_count = disabled_result.get("rules_enabled_count", 0)
        disabled_return_code = disabled_result.get("return_code")
        disabled_stdout = disabled_result.get("stdout", "")
        disabled_stderr = disabled_result.get("stderr", "")

    lua_warnings = collect_lua_warnings(use_lua, lua_script_text, lua_filename, custom_rules)

    result = {
        "ok": True,
        "run_id": run_id,
        "return_code": active_result.get("return_code"),
        "stdout": active_result.get("stdout", ""),
        "stderr": active_result.get("stderr", ""),
        "stderr_summary": active_result.get("stderr_summary", {}),
        "alerts": active_result.get("alerts", []),
        "alert_count": active_result.get("alert_count", 0),
        "rules_enabled_count": active_result.get("rules_enabled_count", 0),
        "coverage_review_enabled": coverage_review_enabled,
        "disabled_alerts": disabled_alerts,
        "disabled_alert_count": len(disabled_alerts),
        "disabled_rules_enabled_count": disabled_rules_enabled_count,
        "disabled_return_code": disabled_return_code,
        "disabled_stdout": disabled_stdout,
        "disabled_stderr": disabled_stderr,
        "disabled_stderr_summary": disabled_stderr_summary,
        "ruleset_status": get_ruleset_status(),
        "lua_enabled": bool(use_lua),
        "lua_filename": lua_filename,
        "lua_filename_message": f"{lua_filename} will be used.",
        "lua_script_provided": bool((lua_script_text or "").strip()),
        "lua_warnings": lua_warnings,
        "lua_scripts_available": active_result.get("lua_scripts_available", []),
    }

    result["status_text"] = build_status_text(result)

    (run_dir / "result.json").write_text(json.dumps(result, indent=2))

    return result


@app.route("/", methods=["GET"])
def index():
    return render_template(
        "index.html",
        palette=load_palette(),
        ruleset_status=get_ruleset_status(),
    )


@app.route("/api/palette", methods=["POST"])
def update_palette():
    payload = request.get_json(force=True, silent=True) or {}
    save_palette(payload)
    return jsonify({"ok": True, "palette": load_palette()})


@app.route("/api/rules/status", methods=["GET"])
def api_rules_status():
    return jsonify({"ok": True, "ruleset_status": get_ruleset_status()})


@app.route("/api/rules/refresh", methods=["POST"])
def api_rules_refresh():
    return jsonify(refresh_default_rules())


@app.route("/api/run", methods=["POST"])
def api_run():
    include_defaults = request.form.get("include_defaults", "true").lower() == "true"
    coverage_review = request.form.get("coverage_review", "false").lower() == "true"
    use_lua = request.form.get("use_lua", "false").lower() == "true"
    custom_rules = request.form.get("custom_rules", "")
    lua_script_text = request.form.get("lua_script", "")
    lua_filename_input = request.form.get("lua_filename", "")

    valid_lua_name, normalized_lua_filename, lua_filename_message = normalize_lua_filename(lua_filename_input)
    if not valid_lua_name:
        return jsonify({"ok": False, "error": lua_filename_message}), 400

    if (lua_script_text or "").strip():
        use_lua = True

    file = request.files.get("pcap")

    if not file or not file.filename:
        return jsonify({"ok": False, "error": "Please choose a PCAP file to test."}), 400

    filename = secure_filename(file.filename)

    if not filename.lower().endswith((".pcap", ".pcapng")):
        return jsonify({"ok": False, "error": "Only .pcap and .pcapng files are supported."}), 400

    saved_path = UPLOAD_DIR / f"{uuid.uuid4().hex}-{filename}"
    file.save(saved_path)

    try:
        result = run_suricata_on_pcap(
            saved_path,
            include_defaults,
            custom_rules,
            coverage_review,
            use_lua=use_lua,
            lua_script_text=lua_script_text,
            lua_filename=normalized_lua_filename,
        )
        result["lua_filename_message"] = lua_filename_message
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
            "ruleset_status": get_ruleset_status(),
            "palette": load_palette(),
            "supported_app_protocols": sorted(get_supported_app_protocols()),
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=SURICATA_PORT, debug=False)