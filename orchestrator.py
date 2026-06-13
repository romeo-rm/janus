#!/usr/bin/env python3
"""
ACC Hackathon — Adversary Emulation Orchestrator
Wazuh VM : 192.168.70.129
Windows 10: 192.168.70.150
"""

import sys, json, time
sys.path.insert(0, '/opt/hackathon/workspace')

import paramiko
import requests
import urllib3
from google import genai
from datetime import datetime, timezone
from flask import Flask, jsonify, send_from_directory
from flask_socketio import SocketIO
from navigator import generate_navigator_layer, suggest_sigma_rules

urllib3.disable_warnings()

# ── Config ────────────────────────────────────────────────────────────────────
WAZUH_HOST     = "192.168.70.129"
WAZUH_API_URL  = f"https://{WAZUH_HOST}:55000"
WAZUH_IDX_URL  = "https://localhost:9200"
WAZUH_API_USER = "wazuh-wui"
WAZUH_API_PASS = "G*9npIu.8*tJBLwCbK+vhtCUIjkMdMCh"
WAZUH_IDX_USER = "admin"
WAZUH_IDX_PASS = "h0Df6PdNeWpJkstR6Xi7cS+.OLy+tQlh"

WIN10_IP       = "192.168.70.150"
WIN10_USER     = "orxan"
WIN10_PASS     = "kali"

GEMINI_KEY     = "your-gemini-api-key-here"
_gemini        = genai.Client(api_key=GEMINI_KEY)
GEMINI_MODEL   = "gemini-2.5-flash"

DETECTION_WAIT = 8

# ── Kill Chain ────────────────────────────────────────────────────────────────
KILL_CHAIN = [
    {"id": "T1059.001", "name": "PowerShell Execution",         "tactic": "execution",          "test": 1},
    {"id": "T1547.001", "name": "Registry Run Key Persistence", "tactic": "persistence",         "test": 1},
    {"id": "T1003.001", "name": "LSASS Dump (Mimikatz)",        "tactic": "credential-access",   "test": 1},
    {"id": "T1550.002", "name": "Pass-the-Hash",                "tactic": "lateral-movement",    "test": 1, "timeout": 15},
    {"id": "T1071.001", "name": "C2 Beacon (HTTP)",             "tactic": "command-and-control", "test": 1},
    {"id": "T1490",     "name": "Shadow Copy Deletion",         "tactic": "impact",              "test": 1},
    {"id": "T1486",     "name": "File Encryption (Ransomware)", "tactic": "impact",              "test": 2},
]

# ── Sysmon rule groups per technique (string or list = OR query) ───────────────
TECHNIQUE_GROUPS = {
    "T1059.001": "sysmon_eid1_detections",
    "T1547.001": ["sysmon_eid12", "sysmon_eid13", "sysmon_eid12_detections", "sysmon_eid13_detections"],
    "T1003.001": "sysmon_eid1_detections",
    "T1550.002": "authentication_success",
    "T1071.001": "sysmon_eid1_detections",
    "T1490":     "sysmon_eid1_detections",
    "T1486":     "sysmon_eid1_detections",
}

# Keywords used as fallback description search when group query returns 0
TECHNIQUE_DESC_KEYWORDS = {
    "T1547.001": ["registry", "run key", "CurrentVersion\\Run"],
}

# ── Flask + SocketIO ──────────────────────────────────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = "hackathon2026"
sio = SocketIO(app, cors_allowed_origins="*")

run_results = []
run_status  = "idle"

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
    return resp.json().get("hits", {}).get("hits", [])

def query_technique_alerts(technique_id, since_ts):
    """Query OpenSearch for victim-win10 alerts. Falls back to description search."""
    # Use relative time to avoid Ubuntu VM clock skew issues
    elapsed   = int(time.time() - since_ts)
    lookback  = f"now-{elapsed + 60}s"   # extra 60s buffer for clock skew
    groups    = TECHNIQUE_GROUPS.get(technique_id, "sysmon")
    if isinstance(groups, str):
        groups = [groups]

    # Primary: group-based OR query
    group_filter = {
        "bool": {
            "should": [{"match": {"rule.groups": g}} for g in groups],
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
                    group_filter,
                    {"range": {"timestamp": {"gte": lookback}}}
                ]
            }
        }
    }
    try:
        hits = _os_search(query)
        print(f"[OPENSEARCH] {technique_id} (groups {groups}): {len(hits)} alerts", flush=True)

        # Fallback: description keyword search if group query returned nothing
        if not hits and technique_id in TECHNIQUE_DESC_KEYWORDS:
            keywords = TECHNIQUE_DESC_KEYWORDS[technique_id]
            print(f"[OPENSEARCH] {technique_id} falling back to description search: {keywords}", flush=True)
            should_kw = [{"match_phrase": {"rule.description": kw}} for kw in keywords]
            should_kw += [{"match_phrase": {"data.win.eventdata.details": kw}} for kw in keywords]
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
                        "minimum_should_match": 1
                    }
                }
            }
            hits = _os_search(fallback_q)
            print(f"[OPENSEARCH] {technique_id} fallback: {len(hits)} alerts", flush=True)

        return [h["_source"] for h in hits]
    except Exception as e:
        print(f"[OPENSEARCH] error for {technique_id}: {e}", flush=True)
        return []

# ── SSH attack execution ──────────────────────────────────────────────────────
# Custom commands for techniques where atomic tests may not work
CUSTOM_COMMANDS = {
    "T1486": (
        'powershell.exe -ExecutionPolicy Bypass -Command "'
        '$files = Get-ChildItem $env:TEMP -File | Select-Object -First 3; '
        'foreach ($f in $files) { '
        '  $bytes = [System.IO.File]::ReadAllBytes($f.FullName); '
        '  $enc = $bytes | ForEach-Object { $_ -bxor 0x41 }; '
        '  [System.IO.File]::WriteAllBytes($f.FullName + \".enc\", $enc); '
        '  Write-Host \"Encrypted: $($f.Name)\" '
        '}'
        '"'
    )
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

        stdin, stdout, stderr = ssh.exec_command(atomic_cmd, timeout=90)
        out = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore")
        print(f"[SSH] {technique_id} out: {out[:300]}", flush=True)

        # Detect atomic test not applicable — fall back to custom command
        if "Found 0 atomic tests" in out or "no tests" in out.lower():
            if technique_id in CUSTOM_COMMANDS:
                print(f"[SSH] {technique_id} atomic N/A — running custom command", flush=True)
                stdin2, stdout2, stderr2 = ssh.exec_command(CUSTOM_COMMANDS[technique_id], timeout=60)
                out2 = stdout2.read().decode(errors="ignore")
                print(f"[SSH] {technique_id} custom out: {out2[:300]}", flush=True)
                ssh.close()
                return True, out2
            else:
                ssh.close()
                return False, f"No applicable atomic test and no custom command for {technique_id}"

        ssh.close()
        return True, out
    except Exception as e:
        print(f"[SSH] {technique_id} failed: {e}", flush=True)
        return False, str(e)

# ── Core chain engine ─────────────────────────────────────────────────────────
def execute_chain():
    global run_results, run_status
    run_results = []
    run_status  = "running"
    sio.emit("run_started", {"chain": KILL_CHAIN})
    print("[*] Kill chain started", flush=True)

    for step in KILL_CHAIN:
        tid  = step["id"]
        name = step["name"]
        print(f"\n[*] === {tid} — {name} ===", flush=True)
        sio.emit("step_started", {"technique": tid, "name": name, "tactic": step["tactic"]})

        attack_ts  = time.time()
        ok, output = run_atomic_on_win10(tid, step["test"], step.get("timeout", 60))

        if not ok:
            result = {**step, "detected": False, "alerts": [], "error": output}
            run_results.append(result)
            sio.emit("step_result", result)
            continue

        print(f"[*] Waiting {DETECTION_WAIT}s for Wazuh...", flush=True)
        sio.emit("step_waiting", {"technique": tid, "wait": DETECTION_WAIT})
        time.sleep(DETECTION_WAIT)

        alerts   = query_technique_alerts(tid, attack_ts)
        detected = len(alerts) > 0

        result = {
            **step,
            "detected": detected,
            "alerts": [
                {
                    "rule_id":    a.get("rule", {}).get("id"),
                    "rule_desc":  a.get("rule", {}).get("description"),
                    "rule_level": a.get("rule", {}).get("level"),
                    "groups":     a.get("rule", {}).get("groups", []),
                    "timestamp":  a.get("timestamp"),
                }
                for a in alerts[:3]
            ],
            "error": None
        }
        run_results.append(result)
        sio.emit("step_result", result)
        print(f"[{'✓' if detected else '✗'}] {tid} — {'DETECTED' if detected else 'MISSED'}", flush=True)

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
        layer_name="ACC Hackathon — Ransomware Kill Chain"
    )
    with open("/opt/hackathon/workspace/output/navigator_layer.json", "w") as f:
        json.dump(layer, f, indent=2)

    # ── Sigma rules for blind spots ───────────────────────────────────────────
    blind_spots = [
        {"technique_id": r["id"], "technique_name": r["name"], "tactic": r["tactic"]}
        for r in run_results if not r["detected"]
    ]
    sigma = suggest_sigma_rules(blind_spots)
    with open("/opt/hackathon/workspace/output/sigma_rules.json", "w") as f:
        json.dump(sigma, f, indent=2)

    score      = sum(1 for r in run_results if r["detected"])
    run_status = "complete"
    sio.emit("run_complete", {
        "score":   score,
        "total":   len(KILL_CHAIN),
        "results": run_results,
        "sigma":   sigma,
    })
    print(f"\n[*] Chain complete — {score}/{len(KILL_CHAIN)} detected", flush=True)

# ── REST endpoints ────────────────────────────────────────────────────────────
@app.route("/")
def dashboard():
    return send_from_directory("/opt/hackathon/workspace", "dashboard.html")

@app.route("/health")
def health():
    try:
        wazuh_ok = bool(get_wazuh_token())
    except:
        wazuh_ok = False
    return jsonify({"status": "ok", "wazuh": wazuh_ok, "victim": WIN10_IP})

@app.route("/run", methods=["POST"])
def run():
    global run_status
    if run_status == "running":
        return jsonify({"error": "already running"}), 409
    sio.start_background_task(execute_chain)
    return jsonify({"status": "started"})

@app.route("/reset", methods=["POST"])
def reset():
    global run_status, run_results
    if run_status == "running":
        return jsonify({"error": "chain is running"}), 409
    run_status  = "idle"
    run_results = []
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
        with open("/opt/hackathon/workspace/output/navigator_layer.json") as f:
            return jsonify(json.load(f))
    except:
        return jsonify({"error": "run the chain first"}), 404

@app.route("/sigma")
def sigma():
    try:
        with open("/opt/hackathon/workspace/output/sigma_rules.json") as f:
            return jsonify(json.load(f))
    except:
        return jsonify({"error": "run the chain first"}), 404

@app.route("/demo", methods=["POST"])
def demo():
    """Replay last results with 2s delays — for live demo presentation."""
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
Target    : Windows 10 VM (192.168.70.150) — Wazuh agent: victim-win10
SIEM      : Wazuh 4.7.5 + OpenSearch (192.168.70.129)
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
    try:
        prompt   = build_report_prompt(run_results)
        response = _gemini.models.generate_content(model=GEMINI_MODEL, contents=prompt)
        report   = response.text
        # Save to file
        with open("/opt/hackathon/workspace/output/report.md", "w") as f:
            f.write(report)
        sio.emit("report_ready", {"report": report})
        return jsonify({"report": report})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/report", methods=["GET"])
def get_report():
    try:
        with open("/opt/hackathon/workspace/output/report.md") as f:
            return jsonify({"report": f.read()})
    except:
        return jsonify({"error": "no report yet"}), 404

@app.route("/debug/groups")
def debug_groups():
    """Show all unique rule groups from victim-win10 in the last 5 minutes — use to map T1547.001."""
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
    sio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
