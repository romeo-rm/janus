# Janus — Adversary Emulation & Automated Detection Engineering

> *Janus, the two-faced Roman god, simultaneously looks forward as the attacker and backward as the defender. So does this system.*

Built at **ACC (Azerbaijan Cybersecurity Center) Hackathon 2026** in 24 hours.

---

## What It Does

Janus is a purple team automation platform that:

1. **Executes a 7-technique ransomware kill chain** against a Windows 10 target via SSH + Atomic Red Team
2. **Queries Wazuh SIEM** in real-time to check which techniques triggered alerts
3. **Surfaces detection gaps** and auto-generates Sigma rules for every missed technique
4. **Renders a live dashboard** with kill chain animation, score, tactic coverage, and log feed
5. **Generates an AI security report** via Google Gemini 2.5 Flash with executive summary, risk assessment, and remediation roadmap
6. **Lets you deploy Sigma rules** live during the demo — then rescan to prove the gap is closed

---

## Kill Chain (MITRE ATT&CK)

| # | Technique | Tactic | Test |
|---|-----------|--------|------|
| 1 | T1059.001 — PowerShell Execution | Execution | Atomic #1 |
| 2 | T1547.001 — Registry Run Key Persistence | Persistence | Atomic #1 |
| 3 | T1003.001 — LSASS Dump (Mimikatz) | Credential Access | Atomic #1 |
| 4 | T1550.002 — Pass-the-Hash | Lateral Movement | Atomic #1 |
| 5 | T1071.001 — C2 Beacon (HTTP) | Command & Control | Atomic #1 |
| 6 | T1490 — Shadow Copy Deletion | Impact | Atomic #1 |
| 7 | T1486 — File Encryption (Ransomware) | Impact | Custom XOR |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Janus Platform                       │
│                                                             │
│  dashboard.html ←── Socket.IO ──→ orchestrator.py (Flask)  │
│       │                                  │                  │
│  Live kill chain                    SSH (Paramiko)          │
│  animation                               │                  │
│  Score / Sigma                    Windows 10 VM             │
│  AI Report modal             (Invoke-AtomicTest)            │
│                                          │                  │
│                              Wazuh SIEM (OpenSearch)        │
│                              ← query alerts per technique   │
│                                          │                  │
│                              Gemini 2.5 Flash               │
│                              ← generate security report     │
└─────────────────────────────────────────────────────────────┘
```

---

## Stack

- **Orchestrator:** Python 3, Flask, Flask-SocketIO, Paramiko, Requests
- **SIEM:** Wazuh 4.7.5 + OpenSearch (query via REST)
- **Attack framework:** Atomic Red Team (`Invoke-AtomicTest`)
- **AI report:** Google Gemini 2.5 Flash (`google-genai`)
- **Frontend:** Vanilla JS, Socket.IO CDN, JetBrains Mono + Inter
- **Detection rules:** Sigma YAML → Wazuh XML

---

## Setup

### Requirements

```bash
pip install flask flask-socketio paramiko requests urllib3 google-genai
```

### Config

Edit the top of `orchestrator.py`:

```python
WAZUH_HOST     = "192.168.70.129"   # Wazuh manager IP
WIN10_IP       = "192.168.70.150"   # Windows 10 target IP
WIN10_USER     = "orxan"
WIN10_PASS     = "kali"
GEMINI_KEY     = "your-api-key"     # Google AI Studio
```

### Run

```bash
cd /opt/hackathon/workspace
sudo -E python3 orchestrator.py
```

Open `http://<wazuh-ip>:5000` in a browser.

---

## Dashboard

- **▶ Run Kill Chain** — executes all 7 techniques live against the target
- **⚡ Demo Mode** — replays cached results (use this for presentations)
- **⬆ Implement Rule** — deploys a Sigma rule for a detection gap (simulated)
- **⟳ Rescan Threat** — re-runs the demo with deployed rules now active
- **✦ AI Report** — generates a full security report via Gemini

---

## Project Structure

```
janus/
├── orchestrator.py        # Flask + SocketIO engine, chain runner, Gemini report
├── dashboard.html         # Live frontend dashboard
├── navigator.py           # ATT&CK Navigator layer + Sigma rule generator
├── wazuh_client.py        # Wazuh API / OpenSearch helper
├── atomic_runner.py       # Atomic Red Team SSH wrapper
└── detection/
    ├── powershell.py      # T1059.001 detection logic
    ├── mimikatz.py        # T1003.001 detection logic
    ├── pth.py             # T1550.002 detection logic
    ├── shadow_copy.py     # T1490 detection logic
    └── ransomware.py      # T1486 detection logic
```

---

## Results (Hackathon Run)

| Technique | Result | Alert |
|-----------|--------|-------|
| T1059.001 | ✓ DETECTED | Windows command prompt started by abnormal process |
| T1547.001 | ✗ MISSED | No EID 12/13 rules in Wazuh |
| T1003.001 | ✓ DETECTED | Windows command prompt started by abnormal process |
| T1550.002 | ✓ DETECTED | Windows logon success |
| T1071.001 | ✓ DETECTED | Windows command prompt started by abnormal process |
| T1490     | ✗ MISSED | No vssadmin detection rule |
| T1486     | ✗ MISSED | No FileCreate extension monitoring |

**Detection rate: 4/7 (57%) — Risk level: CRITICAL**

---

## Built By

**ACC Hackathon 2026** — Azerbaijan Cybersecurity Center
