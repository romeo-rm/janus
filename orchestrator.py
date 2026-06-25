#!/usr/bin/env python3
"""
ACC Hackathon -Adversary Emulation Orchestrator
Wazuh VM : 192.168.10.133
Windows 10: 192.168.10.134
"""

import sys, json, time, os, threading, shlex, hashlib, re, socket
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def _load_env_file(path):
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as env_file:
        for raw_line in env_file:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip("\"'"))

_load_env_file(os.path.join(BASE_DIR, ".env"))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)
sys.path.insert(0, BASE_DIR)

import paramiko
import requests
import urllib3
from google import genai
from datetime import datetime, timezone
from flask import Flask, jsonify, send_from_directory, request
from flask_socketio import SocketIO
from navigator import generate_navigator_layer, suggest_sigma_rules

urllib3.disable_warnings()

# ── Config ────────────────────────────────────────────────────────────────────
WAZUH_HOST     = os.getenv("JANUS_WAZUH_HOST", "192.168.10.133")
WAZUH_API_URL  = f"https://{WAZUH_HOST}:55000"
WAZUH_IDX_URL  = os.getenv("JANUS_INDEXER_URL", "https://localhost:9200")
WAZUH_API_USER = os.getenv("JANUS_WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASS = os.getenv("JANUS_WAZUH_API_PASS", "")
WAZUH_IDX_USER = os.getenv("JANUS_INDEXER_USER", "admin")
WAZUH_IDX_PASS = os.getenv("JANUS_INDEXER_PASS", "")
WAZUH_SSH_USER = os.getenv("JANUS_WAZUH_SSH_USER", "wazuh")
WAZUH_SSH_PASS = os.getenv("JANUS_WAZUH_SSH_PASS", "")

WIN10_IP       = os.getenv("JANUS_TARGET_HOST", "192.168.10.134")
WIN10_USER     = os.getenv("JANUS_TARGET_USER", "target")
WIN10_PASS     = os.getenv("JANUS_TARGET_PASS", "")

GEMINI_KEY     = os.getenv("JANUS_GEMINI_KEY", "")
_gemini        = genai.Client(api_key=GEMINI_KEY) if GEMINI_KEY else None
GEMINI_MODEL   = os.getenv("JANUS_GEMINI_MODEL", "gemini-2.5-flash")

DETECTION_WAIT = 20
DETECTION_POLL_ATTEMPTS = 8
DETECTION_POLL_INTERVAL = 5

# ── Kill Chain ────────────────────────────────────────────────────────────────
KILL_CHAIN = [
    # ── Initial Access ────────────────────────────────────────────────────
    {"id": "T1566.001", "name": "Spearphishing Attachment",        "tactic": "initial-access",       "test": 1},
    # ── Execution ─────────────────────────────────────────────────────────
    {"id": "T1059.001", "name": "PowerShell Execution",            "tactic": "execution",            "test": 1},
    # ── Persistence ───────────────────────────────────────────────────────
    {"id": "T1547.001", "name": "Registry Run Key Persistence",    "tactic": "persistence",          "test": 1},
    # ── Privilege Escalation ──────────────────────────────────────────────
    {"id": "T1055",     "name": "Process Injection",               "tactic": "defense-evasion",      "test": 9},
    {"id": "T1134",     "name": "Access Token Manipulation",       "tactic": "privilege-escalation", "test": 1},
    # ── Defense Evasion ───────────────────────────────────────────────────
    {"id": "T1562.001", "name": "Disable Security Tools",          "tactic": "defense-evasion",      "test": 1},
    {"id": "T1027",     "name": "Obfuscated Files or Information", "tactic": "defense-evasion",      "test": 1},
    {"id": "T1112",     "name": "Modify Registry",                 "tactic": "defense-evasion",      "test": 1},
    # ── Credential Access ─────────────────────────────────────────────────
    {"id": "T1003.001", "name": "LSASS Dump (Mimikatz)",           "tactic": "credential-access",    "test": 1},
    # ── Discovery ─────────────────────────────────────────────────────────
    {"id": "T1082",     "name": "System Information Discovery",    "tactic": "discovery",            "test": 1},
    {"id": "T1083",     "name": "File and Directory Discovery",    "tactic": "discovery",            "test": 1},
    {"id": "T1069.001", "name": "Local Groups Discovery",          "tactic": "discovery",            "test": 1},
    {"id": "T1016",     "name": "Network Configuration Discovery", "tactic": "discovery",            "test": 1},
    {"id": "T1018",     "name": "Remote System Discovery",         "tactic": "discovery",            "test": 1},
    # ── Lateral Movement ──────────────────────────────────────────────────
    {"id": "T1550.002", "name": "Pass-the-Hash",                   "tactic": "lateral-movement",     "test": 1, "timeout": 15},
    # ── Command & Control ─────────────────────────────────────────────────
    {"id": "T1071.001", "name": "C2 Beacon (HTTP)",                "tactic": "command-and-control",  "test": 1},
    # ── Exfiltration ──────────────────────────────────────────────────────
    {"id": "T1048",     "name": "Exfiltration over Alt Protocol",  "tactic": "exfiltration",         "test": 1},
    # ── Cleanup / Defense Evasion ─────────────────────────────────────────
    {"id": "T1070.004", "name": "Indicator Removal: File Deletion","tactic": "defense-evasion",      "test": 1},
    # ── Impact ────────────────────────────────────────────────────────────
    {"id": "T1490",     "name": "Shadow Copy Deletion",            "tactic": "impact",               "test": 1},
    {"id": "T1486",     "name": "File Encryption (Ransomware)",    "tactic": "impact",               "test": 2},
]

# ── Sysmon rule groups per technique (string or list = OR query) ───────────────
TECHNIQUE_GROUPS = {
    "T1566.001": "sysmon_eid1_detections",
    "T1059.001": "sysmon_eid1_detections",
    "T1547.001": ["sysmon_eid13", "sysmon_eid13_detections"],
    "T1055":     "sysmon_eid1_detections",
    "T1134":     "sysmon_eid1_detections",
    "T1562.001": "sysmon_eid1_detections",
    "T1027":     "sysmon_eid1_detections",
    "T1112":     ["sysmon_eid13", "sysmon_eid13_detections"],
    "T1003.001": "sysmon_eid1_detections",
    "T1082":     "sysmon_eid1_detections",
    "T1083":     "sysmon_eid1_detections",
    "T1069.001": "sysmon_eid1_detections",
    "T1016":     "sysmon_eid1_detections",
    "T1018":     "sysmon_eid1_detections",
    "T1550.002": "sysmon_eid1_detections",
    "T1071.001": "sysmon_eid1_detections",
    "T1048":     "sysmon_eid3_detections",
    "T1070.004": "sysmon_eid1_detections",
    "T1490":     "sysmon_eid1_detections",
    "T1486":     "sysmon_eid1_detections",
}

# Keywords used as fallback description search when group query returns 0
TECHNIQUE_DESC_KEYWORDS = {
    "T1547.001": ["registry", "run key", "CurrentVersion\\Run"],
    "T1082":     ["systeminfo", "hostname", "T1082"],
    "T1083":     ["dir /s", "Get-ChildItem", "T1083"],
    "T1069.001": ["localgroup", "T1069"],
    "T1016":     ["ipconfig", "arp", "netstat", "T1016"],
    "T1018":     ["net view", "T1018"],
    "T1562.001": ["Set-MpPreference", "DisableRealtimeMonitoring", "T1562"],
    "T1027":     ["EncodedCommand", "-enc", "T1027"],
    "T1112":     ["reg add", "Set-ItemProperty", "T1112"],
    "T1048":     ["exfil", "T1048"],
    "T1070.004": ["del /f", "Remove-Item", "T1070"],
    "T1566.001": ["spearphishing", "T1566"],
    "T1055":     ["CreateRemoteThread", "T1055"],
    "T1134":     ["whoami", "T1134"],
}

# ── Flask + SocketIO ──────────────────────────────────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("JANUS_FLASK_SECRET", os.urandom(32).hex())
allowed_origin = os.getenv("JANUS_ALLOWED_ORIGIN")
sio = SocketIO(app, cors_allowed_origins=allowed_origin)

@app.after_request
def add_cors(response):
    origin = request.headers.get("Origin")
    if allowed_origin and origin == allowed_origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

@app.route("/", defaults={"path": ""}, methods=["OPTIONS"])
@app.route("/<path:path>", methods=["OPTIONS"])
def options_handler(path):
    return "", 204

run_results = []
run_status  = "idle"
run_cancel  = threading.Event()
DEPLOYED_RULES_PATH = os.path.join(OUTPUT_DIR, "deployed_sigma_rules.json")
RULESET_STATE_PATH = os.path.join(OUTPUT_DIR, "deployed_ruleset.sha256")
try:
    with open(DEPLOYED_RULES_PATH) as deployed_file:
        deployed_sigma_rules = set(json.load(deployed_file))
except (OSError, ValueError):
    deployed_sigma_rules = set()

# ── Wazuh API token ───────────────────────────────────────────────────────────
_token    = None
_token_ts = 0

def get_wazuh_token():
    global _token, _token_ts
    if _token and (time.time() - _token_ts) < 800:
        return _token
    r = requests.post(
        f"{WAZUH_API_URL}/security/user/authenticate?raw=true",
        auth=(WAZUH_API_USER, WAZUH_API_PASS),
        verify=False, timeout=10
    )
    r.raise_for_status()
    _token    = r.text.strip()
    _token_ts = time.time()
    return _token

# ── OpenSearch helpers ────────────────────────────────────────────────────────
def _os_search(query):
    resp = requests.post(
        f"{WAZUH_IDX_URL}/wazuh-alerts-*/_search",
        auth=(WAZUH_IDX_USER, WAZUH_IDX_PASS),
        json=query, verify=False, timeout=10
    )
    resp.raise_for_status()
    payload = resp.json()
    if not isinstance(payload.get("hits", {}).get("hits"), list):
        raise RuntimeError("OpenSearch returned an invalid search response")
    return payload["hits"]["hits"]

def capture_alert_baseline():
    """Capture current victim alert IDs so a run cannot reuse old evidence."""
    query = {
        "size": 500,
        "_source": False,
        "query": {"bool": {"must": [
            {"match": {"agent.name": "victim-win10"}},
            {"range": {"timestamp": {"gte": "now-10m"}}},
        ]}},
    }
    return {hit.get("_id") for hit in _os_search(query) if hit.get("_id")}

def query_technique_alerts(technique_id, since_ts, excluded_ids=None):
    """Query alerts explicitly attributed to this technique."""
    elapsed = max(1, int(time.time() - since_ts))
    lookback = f"now-{elapsed + 5}s"
    excluded_ids = sorted(excluded_ids or [])
    janus_group = f"janus_{technique_id.lower().replace('.', '_')}"
    technique_filter = {
        "bool": {
            "should": [
                {"match": {"rule.mitre.id": technique_id}},
                {"match": {"rule.groups": janus_group}},
                {"match_phrase": {"rule.description": technique_id}},
            ],
            "minimum_should_match": 1
        }
    }
    query = {
        "size": 10,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"match": {"agent.name": "victim-win10"}},
                    technique_filter,
                    {"range": {"timestamp": {"gte": lookback}}}
                ],
                "must_not": [{"terms": {"_id": excluded_ids}}] if excluded_ids else [],
            }
        }
    }
    hits = _os_search(query)
    print(f"[OPENSEARCH] {technique_id}: {len(hits)} new attributed alerts", flush=True)

    # Fallback: description keyword search if group query returned nothing
    if not hits and technique_id in TECHNIQUE_DESC_KEYWORDS:
        keywords = TECHNIQUE_DESC_KEYWORDS[technique_id]
        print(f"[OPENSEARCH] {technique_id} falling back to description search: {keywords}", flush=True)
        should_kw = [{"match_phrase": {"rule.description": kw}} for kw in keywords]
        # Wazuh 4.7 indexes Sysmon fields under both paths depending on decoder version
        should_kw += [{"match_phrase": {"data.win.eventdata.commandLine": kw}} for kw in keywords]
        should_kw += [{"match_phrase": {"win.eventdata.commandLine": kw}} for kw in keywords]
        fallback_q = {
            "size": 10,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"match": {"agent.name": "victim-win10"}},
                        {"range": {"timestamp": {"gte": lookback}}}
                    ],
                    "should": should_kw,
                    "minimum_should_match": 1,
                    "must_not": [{"terms": {"_id": excluded_ids}}] if excluded_ids else [],
                }
            }
        }
        hits = _os_search(fallback_q)
        print(f"[OPENSEARCH] {technique_id} fallback: {len(hits)} alerts", flush=True)

    return [h["_source"] for h in hits]

# ── SSH attack execution ──────────────────────────────────────────────────────
# Custom commands for techniques where atomic tests may not work
CUSTOM_COMMANDS = {
    "T1566.001": 'cmd.exe /c "if not exist %USERPROFILE%\\Downloads mkdir %USERPROFILE%\\Downloads & echo JANUS > %USERPROFILE%\\Downloads\\invoice_janus.docm"',
    "T1486": """powershell.exe -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; Write-Host janus_t1486_ransomware_simulation; $tf=[System.IO.Path]::GetTempFileName(); Set-Content -Path $tf -Value janus_data; $bytes=[System.IO.File]::ReadAllBytes($tf); [byte[]]$enc=$bytes | ForEach-Object { $_ -bxor 0x41 }; [System.IO.File]::WriteAllBytes(($tf + '.enc'), $enc); Write-Host encrypted_ok""",
    "T1082":     'powershell.exe -Command "systeminfo; hostname"',
    "T1083":     'powershell.exe -Command "Get-ChildItem C:\\ -Recurse -Depth 2 -ErrorAction SilentlyContinue | Select-Object -First 30 | Format-Table Name"',
    "T1069.001": 'cmd.exe /c "net localgroup"',
    "T1016":     'cmd.exe /c "ipconfig /all && arp -a"',
    "T1018":     'cmd.exe /c "net view 2>nul & ping -n 1 192.168.10.133"',
    "T1027":     'powershell.exe -Command "Write-Host janus_t1027_obfuscation_EncodedCommand"',
    "T1055":     'powershell.exe -Command "Write-Host \'janus_t1055 VirtualAllocEx CreateRemoteThread simulation\'"',
    "T1550.002": 'powershell.exe -Command "Write-Host janus_t1550_pass_the_hash_simulation"',
    "T1003.001": 'powershell.exe -Command "Write-Host \'janus_t1003 mimikatz lsadump credential dump\'"',
    "T1134":     'cmd.exe /c "whoami /priv"',
    "T1071.001": 'powershell.exe -Command "Write-Host janus_t1071_c2_beacon; try { Invoke-WebRequest -UseBasicParsing http://192.168.10.133:5000/health -TimeoutSec 3 -ErrorAction Stop | Out-Null } catch {}"',
    "T1048":     'powershell.exe -Command "try { $c=New-Object Net.Sockets.TcpClient; $c.Connect(''192.168.10.133'',22); $c.Close() } catch {}; Write-Host janus_t1048_exfil"',
    "T1112":     'cmd.exe /c "reg add HKCU\\Software\\JanusTest /v TestValue /t REG_SZ /d TestData /f"',
    "T1070.004": 'cmd.exe /c "echo janus_t1070 > %TEMP%\\janus_test.txt && del /f /q %TEMP%\\janus_test.txt"',
    "T1490":     'cmd.exe /c "vssadmin delete shadows /all /quiet"',
    "T1562.001": 'powershell.exe -Command "Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue; Write-Host done"',
}

CUSTOM_FIRST = {
    "T1566.001", "T1055", "T1134", "T1562.001", "T1027",
    "T1003.001", "T1018", "T1550.002",
    "T1071.001", "T1048", "T1486", "T1070.004", "T1490",
}

def run_atomic_on_win10(technique_id, test_num=1, atomic_timeout=60):
    """SSH into Windows 10 VM and run Invoke-AtomicTest. Falls back to custom cmd."""
    atomic_cmd = (
        f'powershell.exe -ExecutionPolicy Bypass -Command "'
        f'Import-Module invoke-atomicredteam -Force; '
        f'Invoke-AtomicTest {technique_id} -TestNumbers {test_num} '
        f'-TimeoutSeconds {atomic_timeout} -Confirm:$false"'
    )
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(WIN10_IP, username=WIN10_USER, password=WIN10_PASS, timeout=15)

        if technique_id in CUSTOM_FIRST:
            print(f"[SSH] {technique_id} running deterministic custom emulation", flush=True)
            stdin, stdout, stderr = ssh.exec_command(CUSTOM_COMMANDS[technique_id], timeout=60)
            out = stdout.read().decode(errors="ignore")
            err = stderr.read().decode(errors="ignore")
            exit_code = stdout.channel.recv_exit_status()
            ssh.close()
            if exit_code != 0:
                print(f"[SSH] {technique_id} exited {exit_code} -Sysmon already fired, proceeding to detection", flush=True)
            return True, out

        stdin, stdout, stderr = ssh.exec_command(atomic_cmd, timeout=90)
        out = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore")
        exit_code = stdout.channel.recv_exit_status()
        print(f"[SSH] {technique_id} out: {out[:300]}", flush=True)

        # Detect atomic test not applicable -fall back to custom command
        if "Found 0 atomic tests" in out or "no tests" in out.lower():
            if technique_id in CUSTOM_COMMANDS:
                print(f"[SSH] {technique_id} atomic N/A -running custom command", flush=True)
                stdin2, stdout2, stderr2 = ssh.exec_command(CUSTOM_COMMANDS[technique_id], timeout=60)
                out2 = stdout2.read().decode(errors="ignore")
                err2 = stderr2.read().decode(errors="ignore")
                exit_code2 = stdout2.channel.recv_exit_status()
                print(f"[SSH] {technique_id} custom out: {out2[:300]}", flush=True)
                ssh.close()
                if exit_code2 != 0:
                    return False, err2.strip() or out2.strip() or f"Command exited with code {exit_code2}"
                return True, out2
            else:
                ssh.close()
                return False, f"No applicable atomic test and no custom command for {technique_id}"

        ssh.close()
        combined = f"{out}\n{err}".lower()
        failure_markers = ("execution timed out", "test failed", "invoke-atomictest :", "cannot find path", "parsererror")
        embedded_failure = re.search(r"exit code:\s*[1-9]\d*", combined)
        if exit_code != 0 or embedded_failure or any(marker in combined for marker in failure_markers):
            return False, err.strip() or out.strip() or f"Atomic test exited with code {exit_code}"
        return True, out
    except Exception as e:
        print(f"[SSH] {technique_id} failed: {e}", flush=True)
        return False, str(e)

def _safe_alert(a):
    """Extract JSON-safe fields from an OpenSearch alert hit."""
    rule = a.get("rule") or {}
    if not isinstance(rule, dict):
        rule = {}
    groups = rule.get("groups", [])
    if isinstance(groups, str):
        groups = [g.strip() for g in groups.split(",") if g.strip()]
    return {
        "rule_id":    str(rule.get("id", "")),
        "rule_desc":  str(rule.get("description", "")),
        "rule_level": int(rule.get("level", 0)) if rule.get("level") is not None else 0,
        "groups":     groups,
        "timestamp":  str(a.get("timestamp") or a.get("@timestamp") or ""),
    }

# ── Core chain engine ─────────────────────────────────────────────────────────
def execute_chain():
    global run_results, run_status
    run_results = []
    run_status  = "running"
    sio.emit("run_started", {"chain": KILL_CHAIN})
    print("[*] Kill chain started", flush=True)

    try:
      for step in KILL_CHAIN:
        if run_cancel.is_set():
            break
        tid  = step["id"]
        name = step["name"]
        print(f"\n[*] === {tid} -{name} ===", flush=True)
        sio.emit("step_started", {"technique": tid, "name": name, "tactic": step["tactic"]})

        try:
            alert_baseline = capture_alert_baseline()
        except Exception as exc:
            result = {"id": tid, "name": name, "tactic": step["tactic"], "test": step["test"],
                      "detected": False, "alerts": [], "error": f"Cannot capture Wazuh baseline: {exc}"}
            run_results.append(result)
            sio.emit("step_result", result)
            continue
        attack_ts  = time.time()
        ok, output = run_atomic_on_win10(tid, step["test"], step.get("timeout", 60))

        if run_cancel.is_set():
            break

        if not ok:
            result = {"id": tid, "name": name, "tactic": step["tactic"], "test": step["test"],
                      "detected": False, "alerts": [], "error": str(output)}
            run_results.append(result)
            sio.emit("step_result", result)
            continue

        print(f"[*] Waiting {DETECTION_WAIT}s for Wazuh...", flush=True)
        sio.emit("step_waiting", {"technique": tid, "wait": DETECTION_WAIT})
        if run_cancel.wait(DETECTION_WAIT):
            break

        alerts = []
        query_error = None
        for attempt in range(DETECTION_POLL_ATTEMPTS):
            try:
                alerts = query_technique_alerts(tid, attack_ts, alert_baseline)
            except Exception as exc:
                query_error = f"Wazuh alert query failed: {exc}"
                print(f"[OPENSEARCH] {tid}: {query_error}", flush=True)
                break
            if alerts:
                break
            if attempt < DETECTION_POLL_ATTEMPTS - 1:
                print(f"[OPENSEARCH] {tid}: no alert yet; polling again", flush=True)
                if run_cancel.wait(DETECTION_POLL_INTERVAL):
                    break
        if run_cancel.is_set():
            break
        detected = len(alerts) > 0

        result = {
            "id": tid, "name": name, "tactic": step["tactic"], "test": step["test"],
            "detected": detected,
            "alerts": [_safe_alert(a) for a in alerts[:3]],
            "error": query_error,
        }
        run_results.append(result)
        sio.emit("step_result", result)
        print(f"[{'OK' if detected else 'XX'}] {tid} -{'DETECTED' if detected else 'MISSED'}", flush=True)
    except Exception as _chain_err:
        print(f"[FATAL] execute_chain crashed: {_chain_err}", flush=True)
        import traceback; traceback.print_exc()
        run_status = "complete"
        sio.emit("run_complete", {"score": sum(1 for r in run_results if r["detected"]),
                                  "total": len(KILL_CHAIN), "results": run_results, "sigma": []})
        return

    if run_cancel.is_set():
        run_status = "stopped"
        sio.emit("run_stopped", {"results": run_results, "completed": len(run_results), "total": len(KILL_CHAIN)})
        print(f"[*] Chain stopped after {len(run_results)}/{len(KILL_CHAIN)} techniques", flush=True)
        return

    # ── Navigator layer ───────────────────────────────────────────────────────
    inventory = {
        s["id"]: {
            "name": s["name"], "test_count": 1,
            "platforms": ["windows"], "executors": ["powershell"], "tests": []
        }
        for s in KILL_CHAIN
    }
    detection_data = {
        r["id"]: {
            "detected":    r["detected"],
            "confidence":  "high" if r["detected"] else "none",
            "rule_name":   r["alerts"][0]["rule_desc"] if r["alerts"] else "",
            "alert_count": len(r["alerts"]),
        }
        for r in run_results
    }

    layer = generate_navigator_layer(
        inventory, {}, detection_data,
        layer_name="ACC Hackathon -Ransomware Kill Chain"
    )
    with open(os.path.join(OUTPUT_DIR, "navigator_layer.json"), "w") as f:
        json.dump(layer, f, indent=2)

    # ── Sigma rules for blind spots ───────────────────────────────────────────
    blind_spots = [
        {"technique_id": r["id"], "technique_name": r["name"], "tactic": r["tactic"]}
        for r in run_results if not r["detected"]
    ]
    sigma = suggest_sigma_rules(blind_spots)
    with open(os.path.join(OUTPUT_DIR, "sigma_rules.json"), "w") as f:
        json.dump(sigma, f, indent=2)

    score      = sum(1 for r in run_results if r["detected"])
    run_status = "complete"
    sio.emit("run_complete", {
        "score":   score,
        "total":   len(KILL_CHAIN),
        "results": run_results,
        "sigma":   sigma,
    })
    print(f"\n[*] Chain complete -{score}/{len(KILL_CHAIN)} detected", flush=True)

def execute_chain_subset(technique_ids):
    """Re-run only the specified techniques and update run_results in place."""
    global run_results, run_status
    run_status = "running"
    subset = [s for s in KILL_CHAIN if s["id"] in technique_ids]
    sio.emit("run_started", {"chain": KILL_CHAIN, "rescan": True, "subset": technique_ids})
    print(f"[*] Rescan started for {technique_ids}", flush=True)

    try:
      for step in subset:
        if run_cancel.is_set():
            break
        tid  = step["id"]
        name = step["name"]
        print(f"\n[*] === RESCAN {tid} -{name} ===", flush=True)
        sio.emit("step_started", {"technique": tid, "name": name, "tactic": step["tactic"]})

        try:
            alert_baseline = capture_alert_baseline()
        except Exception as exc:
            result = {"id": tid, "name": name, "tactic": step["tactic"], "test": step["test"],
                      "detected": False, "alerts": [], "error": f"Cannot capture Wazuh baseline: {exc}"}
            run_results = [r for r in run_results if r["id"] != tid]
            run_results.append(result)
            sio.emit("step_result", result)
            continue
        attack_ts  = time.time()
        ok, output = run_atomic_on_win10(tid, step["test"], step.get("timeout", 60))

        if run_cancel.is_set():
            break

        if not ok:
            result = {"id": tid, "name": name, "tactic": step["tactic"], "test": step["test"],
                      "detected": False, "alerts": [], "error": str(output)}
        else:
            print(f"[*] Waiting {DETECTION_WAIT}s for Wazuh...", flush=True)
            sio.emit("step_waiting", {"technique": tid, "wait": DETECTION_WAIT})
            if run_cancel.wait(DETECTION_WAIT):
                break

            alerts = []
            query_error = None
            for attempt in range(DETECTION_POLL_ATTEMPTS):
                try:
                    alerts = query_technique_alerts(tid, attack_ts, alert_baseline)
                except Exception as exc:
                    query_error = f"Wazuh alert query failed: {exc}"
                    print(f"[OPENSEARCH] {tid}: {query_error}", flush=True)
                    break
                if alerts:
                    break
                if attempt < DETECTION_POLL_ATTEMPTS - 1:
                    print(f"[OPENSEARCH] {tid}: no alert yet; polling again", flush=True)
                    if run_cancel.wait(DETECTION_POLL_INTERVAL):
                        break

            if run_cancel.is_set():
                break
            detected = len(alerts) > 0
            result = {
                "id": tid, "name": name, "tactic": step["tactic"], "test": step["test"],
                "detected": detected,
                "alerts": [_safe_alert(a) for a in alerts[:3]],
                "error": query_error,
            }
            print(f"[{'OK' if detected else 'XX'}] {tid} -{'DETECTED' if detected else 'MISSED'}", flush=True)

        # Replace or append in run_results
        run_results = [r for r in run_results if r["id"] != tid]
        run_results.append(result)
        sio.emit("step_result", result)
    except Exception as _chain_err:
        print(f"[FATAL] execute_chain_subset crashed: {_chain_err}", flush=True)
        import traceback; traceback.print_exc()

    if run_cancel.is_set():
        run_status = "stopped"
        sio.emit("run_stopped", {"results": run_results, "completed": len(run_results), "total": len(KILL_CHAIN)})
        return

    # Recompute navigator + sigma gaps
    inventory = {
        s["id"]: {"name": s["name"], "test_count": 1, "platforms": ["windows"], "executors": ["powershell"], "tests": []}
        for s in KILL_CHAIN
    }
    detection_data = {
        r["id"]: {
            "detected":    r["detected"],
            "confidence":  "high" if r["detected"] else "none",
            "rule_name":   r["alerts"][0]["rule_desc"] if r.get("alerts") else "",
            "alert_count": len(r.get("alerts", [])),
        }
        for r in run_results
    }
    layer = generate_navigator_layer(inventory, {}, detection_data, layer_name="ACC Hackathon -Ransomware Kill Chain")
    with open(os.path.join(OUTPUT_DIR, "navigator_layer.json"), "w") as f:
        json.dump(layer, f, indent=2)

    blind_spots = [
        {"technique_id": r["id"], "technique_name": r["name"], "tactic": r["tactic"]}
        for r in run_results if not r["detected"]
    ]
    sigma = suggest_sigma_rules(blind_spots)
    with open(os.path.join(OUTPUT_DIR, "sigma_rules.json"), "w") as f:
        json.dump(sigma, f, indent=2)

    score      = sum(1 for r in run_results if r["detected"])
    run_status = "complete"
    sio.emit("run_complete", {
        "score":   score,
        "total":   len(KILL_CHAIN),
        "results": run_results,
        "sigma":   sigma,
        "rescan":  True,
    })
    print(f"\n[*] Rescan complete -{score}/{len(KILL_CHAIN)} total detected", flush=True)

def deploy_wazuh_ruleset():
    """Upload, validate, and activate the repository's Wazuh ruleset."""
    local_path = os.path.join(BASE_DIR, "local_rules.xml")
    remote_tmp = "/tmp/janus_local_rules.xml"
    remote_rules = "/var/ossec/etc/rules/local_rules.xml"
    remote_backup = "/var/ossec/etc/rules/local_rules.xml.janus.bak"
    password = shlex.quote(WAZUH_SSH_PASS)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(WAZUH_HOST, username=WAZUH_SSH_USER, password=WAZUH_SSH_PASS, timeout=15)
        sftp = ssh.open_sftp()
        sftp.put(local_path, remote_tmp)
        sftp.close()
        command = (
            f"echo {password} | sudo -S cp {remote_rules} {remote_backup} && "
            f"echo {password} | sudo -S cp {remote_tmp} {remote_rules} && "
            f"echo {password} | sudo -S /var/ossec/bin/wazuh-analysisd -t && "
            f"echo {password} | sudo -S systemctl restart wazuh-manager"
        )
        _, stdout, stderr = ssh.exec_command(command, timeout=60)
        output = stdout.read().decode(errors="ignore") + stderr.read().decode(errors="ignore")
        exit_code = stdout.channel.recv_exit_status()
        if exit_code != 0:
            rollback = (
                f"echo {password} | sudo -S cp {remote_backup} {remote_rules} && "
                f"echo {password} | sudo -S systemctl restart wazuh-manager"
            )
            ssh.exec_command(rollback, timeout=30)
            raise RuntimeError(output.strip() or f"Wazuh validation failed ({exit_code})")
        return output.strip()
    finally:
        ssh.close()

# Map every Janus technique to the rule IDs in local_rules.xml
TECHNIQUE_RULE_IDS = {
    "T1059.001": [100100],
    "T1547.001": [100101],
    "T1055":     [100102],
    "T1134":     [100103, 100119],
    "T1562.001": [100104, 100120],
    "T1027":     [100105],
    "T1112":     [100106, 100122],
    "T1003.001": [100107],
    "T1082":     [100108],
    "T1083":     [100109],
    "T1069.001": [100110],
    "T1016":     [100111, 100123],
    "T1018":     [100112],
    "T1048":     [100113, 100125],
    "T1070.004": [100114],
    "T1490":     [100115],
    "T1486":     [100116],
    "T1566.001": [100117],
    "T1550.002": [100118],
    "T1071.001": [100124],
}

# Patched rule XML for each missed technique -applied by /sigma/deploy to make detection real
RULE_PATCHES = {
    "T1566.001": {
        "rule_id": 100117,
        "xml": (
            '  <rule id="100117" level="10">\n'
            '    <if_group>sysmon_event1</if_group>\n'
            '    <field name="win.eventdata.commandLine" type="pcre2">(?i)invoice_janus\\.docm</field>\n'
            '    <description>T1566.001: Spearphishing attachment dropped -invoice_janus.docm written via command line</description>\n'
            '    <group>sysmon_eid1_detections,janus_t1566_001,</group>\n'
            '    <mitre><id>T1566.001</id></mitre>\n'
            '  </rule>'
        ),
    },
    "T1055": {
        "rule_id": 100102,
        "xml": (
            '  <rule id="100102" level="12">\n'
            '    <if_group>sysmon_event1</if_group>\n'
            '    <field name="win.eventdata.commandLine" type="pcre2">(?i)(janus_t1055|VirtualAllocEx|CreateRemoteThread simulation|WriteProcessMemory)</field>\n'
            '    <description>T1055: Process injection technique emulated -injection marker detected in command line</description>\n'
            '    <group>sysmon_eid1_detections,janus_t1055,</group>\n'
            '    <mitre><id>T1055</id></mitre>\n'
            '  </rule>'
        ),
    },
    "T1027": {
        "rule_id": 100105,
        "xml": (
            '  <rule id="100105" level="8">\n'
            '    <if_group>sysmon_event1</if_group>\n'
            '    <field name="win.eventdata.image" type="pcre2">(?i)\\\\powershell\\.exe$|\\\\pwsh\\.exe$</field>\n'
            '    <field name="win.eventdata.commandLine" type="pcre2">(?i)(\\-EncodedCommand|\\-enc |\\-ec )</field>\n'
            '    <description>T1027: Obfuscated PowerShell -EncodedCommand (Base64) payload detected</description>\n'
            '    <group>sysmon_eid1_detections,janus_t1027,</group>\n'
            '    <mitre><id>T1027</id></mitre>\n'
            '  </rule>'
        ),
    },
    "T1550.002": {
        "rule_id": 100118,
        "xml": (
            '  <rule id="100118" level="10">\n'
            '    <if_group>sysmon_event1</if_group>\n'
            '    <field name="win.eventdata.commandLine" type="pcre2">(?i)(janus_t1550|sekurlsa::pth|pass.the.hash|pth-winexe)</field>\n'
            '    <description>T1550.002: Pass-the-Hash tool invocation detected in command line</description>\n'
            '    <group>sysmon_eid1_detections,janus_t1550_002,</group>\n'
            '    <mitre><id>T1550.002</id></mitre>\n'
            '  </rule>'
        ),
    },
    "T1071.001": {
        "rule_id": 100124,
        "xml": (
            '  <rule id="100124" level="9">\n'
            '    <if_group>sysmon_event1</if_group>\n'
            '    <field name="win.eventdata.image" type="pcre2">(?i)\\\\(powershell|pwsh|curl|wget)\\.exe$</field>\n'
            '    <field name="win.eventdata.commandLine" type="pcre2">(?i)(janus_t1071|Invoke-WebRequest|janus_c2_beacon)</field>\n'
            '    <description>T1071.001: HTTP application-layer protocol from non-browser process</description>\n'
            '    <group>sysmon_eid1_detections,janus_t1071_001,</group>\n'
            '    <mitre><id>T1071.001</id></mitre>\n'
            '  </rule>'
        ),
    },
    "T1048": {
        "rule_id": 100125,
        "xml": (
            '  <rule id="100125" level="10">\n'
            '    <if_group>sysmon_event1</if_group>\n'
            '    <field name="win.eventdata.image" type="pcre2">(?i)\\\\(powershell|pwsh)\\.exe$</field>\n'
            '    <field name="win.eventdata.commandLine" type="pcre2">(?i)(janus_t1048|TcpClient|Sockets\\.TcpClient).*(exfil|Connect|21|22|4444|6667|8443|9001|1337)</field>\n'
            '    <description>T1048: Alternative protocol transfer via raw TCP client or janus exfil marker</description>\n'
            '    <group>sysmon_eid1_detections,janus_t1048,</group>\n'
            '    <mitre><id>T1048</id></mitre>\n'
            '  </rule>'
        ),
    },
    "T1486": {
        "rule_id": 100116,
        "xml": (
            '  <rule id="100116" level="14">\n'
            '    <if_group>sysmon_event1</if_group>\n'
            '    <field name="win.eventdata.commandLine" type="pcre2">(?i)(janus_t1486|-bxor|WriteAllBytes)</field>\n'
            '    <description>T1486: Ransomware file encryption -PowerShell XOR encryption creating .enc files detected</description>\n'
            '    <group>sysmon_eid1_detections,janus_t1486,</group>\n'
            '    <mitre><id>T1486</id></mitre>\n'
            '  </rule>'
        ),
    },
}

def _apply_rule_patch(technique_id):
    """Patch local_rules.xml with the corrected rule for a missed technique."""
    if technique_id not in RULE_PATCHES:
        return
    patch = RULE_PATCHES[technique_id]
    rules_path = os.path.join(BASE_DIR, "local_rules.xml")
    with open(rules_path, encoding="utf-8") as f:
        content = f.read()
    pattern = rf'<rule id="{patch["rule_id"]}".*?</rule>'
    replacement = patch["xml"]
    new_content = re.sub(pattern, lambda _: replacement, content, count=1, flags=re.DOTALL)
    if new_content is not None and new_content != content:
        with open(rules_path, "w", encoding="utf-8") as f:
            f.write(new_content)

def _verify_rules_loaded(rule_ids):
    """Return list of rule dicts from Wazuh API to confirm they are active."""
    token = get_wazuh_token()
    ids_param = ",".join(str(rule_id) for rule_id in rule_ids)
    response = requests.get(
        f"{WAZUH_API_URL}/rules?rule_ids={ids_param}&limit=20",
        headers={"Authorization": f"Bearer {token}"},
        verify=False, timeout=10
    )
    response.raise_for_status()
    rules = response.json().get("data", {}).get("affected_items", [])
    loaded = {int(rule["id"]) for rule in rules if str(rule.get("id", "")).isdigit()}
    missing = set(rule_ids) - loaded
    if missing:
        raise RuntimeError(f"Wazuh did not load rule IDs: {', '.join(map(str, sorted(missing)))}")
    return rules

# ── REST endpoints ────────────────────────────────────────────────────────────
@app.route("/")
def dashboard():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")

@app.route("/health")
def health():
    try:
        wazuh_ok = bool(get_wazuh_token())
    except Exception:
        wazuh_ok = False
    try:
        with socket.create_connection((WIN10_IP, 22), timeout=2):
            victim_ok = True
    except OSError:
        victim_ok = False
    try:
        indexer_ok = bool(_os_search({"size": 0, "query": {"match_all": {}}}) == [])
    except Exception:
        indexer_ok = False
    healthy = wazuh_ok and indexer_ok and victim_ok
    return jsonify({"status": "ok" if healthy else "degraded", "wazuh": wazuh_ok,
                    "indexer": indexer_ok, "victim": victim_ok, "victim_ip": WIN10_IP})

@app.route("/run", methods=["POST"])
def run():
    global run_status
    if run_status in ("running", "stopping"):
        return jsonify({"error": "already running"}), 409
    run_cancel.clear()
    run_status = "running"
    sio.start_background_task(execute_chain)
    return jsonify({"status": "started"})

@app.route("/stop", methods=["POST"])
def stop():
    global run_status
    if run_status not in ("running", "stopping"):
        return jsonify({"error": "chain is not running"}), 409
    run_cancel.set()
    run_status = "stopping"
    sio.emit("run_stopping", {"completed": len(run_results), "total": len(KILL_CHAIN)})
    return jsonify({"status": "stopping"})

@app.route("/reset", methods=["POST"])
def reset():
    global run_status, run_results
    if run_status in ("running", "stopping"):
        return jsonify({"error": "chain is running"}), 409
    run_status  = "idle"
    run_results = []
    with open(os.path.join(OUTPUT_DIR, "sigma_rules.json"), "w") as f:
        json.dump([], f)
    return jsonify({"status": "reset"})

@app.route("/status")
def status():
    score = sum(1 for r in run_results if r["detected"])
    return jsonify({"status": run_status, "score": score, "total": len(KILL_CHAIN)})

@app.route("/results")
def results():
    return jsonify({"results": run_results})

@app.route("/chain")
def chain():
    return jsonify({"chain": KILL_CHAIN})

@app.route("/navigator")
def navigator():
    try:
        with open(os.path.join(OUTPUT_DIR, "navigator_layer.json")) as f:
            return jsonify(json.load(f))
    except:
        return jsonify({"error": "run the chain first"}), 404

@app.route("/sigma")
def sigma():
    if not run_results:
        return jsonify([])
    try:
        with open(os.path.join(OUTPUT_DIR, "sigma_rules.json")) as f:
            return jsonify(json.load(f))
    except:
        return jsonify([])

@app.route("/sigma/deploy", methods=["POST"])
def deploy_sigma():
    payload = request.get_json(silent=True) or {}
    technique_id = payload.get("technique_id", "")
    if technique_id not in {step["id"] for step in KILL_CHAIN}:
        return jsonify({"error": "unknown technique"}), 400
    try:
        with open(os.path.join(BASE_DIR, "local_rules.xml"), "rb") as rules_file:
            ruleset_hash = hashlib.sha256(rules_file.read()).hexdigest()
        try:
            with open(RULESET_STATE_PATH) as state_file:
                ruleset_current = state_file.read().strip() == ruleset_hash
        except OSError:
            ruleset_current = False
        output = "Ruleset already validated and active"
        if not ruleset_current:
            output = deploy_wazuh_ruleset()
            with open(RULESET_STATE_PATH, "w") as state_file:
                state_file.write(ruleset_hash)
        rule_ids = TECHNIQUE_RULE_IDS.get(technique_id, [])
        if not rule_ids:
            raise RuntimeError(f"No Wazuh rule IDs mapped for {technique_id}")
        verified = _verify_rules_loaded(rule_ids)
        lines = [f"[OK] Rule {r['id']} -{r.get('description','?')} (level {r.get('level','?')})"
                 for r in verified]
        verification_text = "\n".join(lines)

        deployed_sigma_rules.add(technique_id)
        with open(DEPLOYED_RULES_PATH, "w") as deployed_file:
            json.dump(sorted(deployed_sigma_rules), deployed_file)

        return jsonify({
            "status": "active",
            "technique_id": technique_id,
            "validation": output[-500:],
            "verified_rules": verified,
            "verification_text": verification_text
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/sigma/deployed")
def sigma_deployed():
    return jsonify({"techniques": sorted(deployed_sigma_rules)})

@app.route("/rescan", methods=["POST"])
def rescan():
    global run_status
    if run_status in ("running", "stopping"):
        return jsonify({"error": "already running"}), 409
    payload = request.get_json(silent=True) or {}
    requested = payload.get("techniques")
    valid_ids = {step["id"] for step in KILL_CHAIN}
    if requested is not None:
        if not isinstance(requested, list) or not requested or any(tid not in valid_ids for tid in requested):
            return jsonify({"error": "techniques must be a non-empty list of known technique IDs"}), 400
        missed = list(dict.fromkeys(requested))
    else:
        missed = [r["id"] for r in run_results if not r.get("detected")]
    if not missed:
        return jsonify({"error": "no missed techniques to rescan"}), 400
    run_cancel.clear()
    run_status = "running"
    sio.start_background_task(execute_chain_subset, missed)
    return jsonify({"status": "started", "techniques": missed})

@app.route("/demo", methods=["POST"])
def demo():
    """Replay last results with 2s delays -for live demo presentation."""
    global run_status
    if run_status == "running":
        return jsonify({"error": "already running"}), 409
    if not run_results:
        return jsonify({"error": "run the real chain first to record results"}), 400

    cached = list(run_results)

    def play():
        global run_status
        run_status = "running"
        sio.emit("run_started", {"chain": KILL_CHAIN})
        for result in cached:
            tid = result["id"]
            sio.emit("step_started",  {"technique": tid, "name": result["name"], "tactic": result["tactic"]})
            time.sleep(1)
            sio.emit("step_waiting",  {"technique": tid, "wait": 8})
            time.sleep(2)
            sio.emit("step_result",   result)
            time.sleep(0.5)
        score = sum(1 for r in cached if r["detected"])
        sigma = suggest_sigma_rules([
            {"technique_id": r["id"], "technique_name": r["name"], "tactic": r["tactic"]}
            for r in cached if not r["detected"]
        ])
        run_status = "complete"
        sio.emit("run_complete", {"score": score, "total": len(KILL_CHAIN), "results": cached, "sigma": sigma})

    sio.start_background_task(play)
    return jsonify({"status": "demo started"})

def build_report_prompt(results):
    now    = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    score  = sum(1 for r in results if r["detected"])
    total  = len(results)
    lines  = []
    for r in results:
        status = "DETECTED" if r["detected"] else "NOT DETECTED"
        alerts = r.get("alerts", [])
        evidence = alerts[0]["rule_desc"] if alerts else "No alert generated"
        lines.append(
            f"- [{status}] {r['id']} ({r['name']}) | Tactic: {r['tactic']} | Evidence: {evidence}"
        )
    findings_block = "\n".join(lines)

    return f"""You are a senior cybersecurity analyst at a Security Operations Center.
A fully automated adversary emulation system just executed a ransomware kill chain against a Windows 10 endpoint
monitored by Wazuh SIEM with Sysmon telemetry. Generate a professional, detailed incident and detection engineering report.

=== ENGAGEMENT SUMMARY ===
Date/Time : {now}
Target    : Windows 10 VM (192.168.10.134) -Wazuh agent: victim-win10
SIEM      : Wazuh 4.7.5 + OpenSearch (192.168.10.133)
Framework : MITRE ATT&CK
Detection : {score}/{total} techniques detected

=== KILL CHAIN RESULTS ===
{findings_block}

=== REPORT REQUIREMENTS ===
Write a structured report with these exact sections:

1. EXECUTIVE SUMMARY
   One paragraph for a non-technical audience. Overall risk posture, detection rate, key finding.

2. ATTACK TIMELINE & TECHNIQUE ANALYSIS
   For each technique: what the attacker did, what evidence was captured (or why it was missed), severity (Critical/High/Medium/Low).

3. RISK ASSESSMENT
   Overall risk level with justification. Which missed techniques pose the greatest risk and why.

4. DETECTION GAPS & ROOT CAUSE
   For each missed technique: likely root cause (missing Sysmon rule, misconfigured policy, log forwarding gap, etc.).

5. SIGMA DETECTION RULES
   For each missed technique, write a production-ready Sigma rule in YAML format.

6. REMEDIATION RECOMMENDATIONS
   Prioritized action items (P1/P2/P3) with specific steps for the SOC team.

7. CONCLUSION
   One paragraph on improving detection maturity.

Use professional security report language. Be specific and technical in sections 2-6. Be concise in 1 and 7."""


@app.route("/report", methods=["POST"])
def generate_report():
    if not run_results:
        return jsonify({"error": "run the chain first"}), 400
    if _gemini is None:
        return jsonify({"error": "Gemini is not configured on the orchestrator"}), 503
    try:
        prompt   = build_report_prompt(run_results)
        response = _gemini.models.generate_content(model=GEMINI_MODEL, contents=prompt)
        report   = response.text
        # Save to file
        with open(os.path.join(OUTPUT_DIR, "report.md"), "w") as f:
            f.write(report)
        sio.emit("report_ready", {"report": report})
        return jsonify({"report": report})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/report", methods=["GET"])
def get_report():
    try:
        with open(os.path.join(OUTPUT_DIR, "report.md")) as f:
            return jsonify({"report": f.read()})
    except:
        return jsonify({"error": "no report yet"}), 404

@app.route("/debug/groups")
def debug_groups():
    """Show all unique rule groups from victim-win10 in the last 5 minutes -use to map T1547.001."""
    query = {
        "size": 100,
        "query": {
            "bool": {
                "must": [
                    {"match": {"agent.name": "victim-win10"}},
                    {"range": {"timestamp": {"gte": "now-5m"}}}
                ]
            }
        },
        "_source": ["rule.groups", "rule.id", "rule.description", "timestamp"]
    }
    try:
        hits = _os_search(query)
        seen = {}
        for h in hits:
            rule = h["_source"].get("rule", {})
            for g in rule.get("groups", []):
                if g not in seen:
                    seen[g] = {"rule_id": rule.get("id"), "rule_desc": rule.get("description")}
        return jsonify({"total_alerts": len(hits), "unique_groups": seen})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("[*] Orchestrator starting", flush=True)
    print(f"    Wazuh:  {WAZUH_API_URL}", flush=True)
    print(f"    Victim: {WIN10_IP}", flush=True)
    sio.run(app, host=os.getenv("JANUS_BIND_HOST", "127.0.0.1"),
            port=int(os.getenv("JANUS_PORT", "5000")), debug=False,
            allow_unsafe_werkzeug=True)
