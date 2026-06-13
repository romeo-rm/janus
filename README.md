<div align="center">

# 🔱 JANUS

### Adversary Emulation & Automated Detection Engineering

*Named after the two-faced Roman god — one face runs the attack, one watches the SIEM. Simultaneously.*

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.7.5-005571?style=flat-square)](https://wazuh.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-FF0000?style=flat-square)](https://attack.mitre.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

**Built in 24 hours at ACC Hackathon 2026 — Azerbaijan Cybersecurity Center**

</div>

---

## What is Janus?

Janus is an open-source **purple team automation platform** that answers one question:

> *If a ransomware group ran their kill chain against your network right now — what would your SIEM catch?*

It executes a real 7-technique ransomware kill chain against a live Windows target, queries Wazuh in real time to find detection gaps, auto-generates Sigma rules for every missed technique, deploys them live, and rescans to prove the gap is closed — all from a single dashboard. At the end, one click generates a full AI security report via Google Gemini 2.5 Flash.

**The complete purple team loop: attack → detect → fix → verify. Automated. Free.**

---

## Key Features

| Feature | Description |
|---------|-------------|
| 🎯 **Live Kill Chain** | Executes 7 real MITRE ATT&CK techniques via SSH + Atomic Red Team |
| 📡 **Real-Time SIEM Query** | Queries Wazuh + OpenSearch after each technique to check for alerts |
| 🔍 **Gap Detection** | Surfaces every undetected technique with root cause analysis |
| ⚡ **Sigma Deploy Loop** | Generates, deploys, and validates detection rules in under 60 seconds |
| 🤖 **AI Security Report** | Full executive + technical report via Gemini 2.5 Flash in 30 seconds |
| 🖥️ **Live Dashboard** | Real-time kill chain animation, score counter, tactic coverage, log feed |

---

## The Kill Chain

This exact sequence mirrors documented TTPs of **LockBit**, **REvil**, and **Conti**.

```
T1059.001          T1547.001          T1003.001          T1550.002
PowerShell    ──►  Registry      ──►  LSASS Dump    ──►  Pass-the-Hash
Execution          Persistence        (Mimikatz)

      ──►  T1071.001        ──►  T1490              ──►  T1486
           C2 Beacon             Shadow Copy              File
           over HTTP             Deletion                 Encryption
```

| # | Technique | Tactic | Method |
|---|-----------|--------|--------|
| 1 | T1059.001 — PowerShell Execution | Execution | Atomic Red Team |
| 2 | T1547.001 — Registry Run Key Persistence | Persistence | Atomic Red Team |
| 3 | T1003.001 — LSASS Dump (Mimikatz) | Credential Access | Atomic Red Team |
| 4 | T1550.002 — Pass-the-Hash | Lateral Movement | Atomic Red Team |
| 5 | T1071.001 — C2 Beacon over HTTP | Command & Control | Atomic Red Team |
| 6 | T1490 — Shadow Copy Deletion | Impact | Atomic Red Team |
| 7 | T1486 — File Encryption | Impact | Custom XOR script |

---

## Hackathon Results

Live execution against a real Windows 10 + Wazuh 4.7.5 environment:

| Technique | Status | Alert |
|-----------|--------|-------|
| T1059.001 — PowerShell Execution | ✅ DETECTED | Windows command prompt started by abnormal process |
| T1547.001 — Registry Persistence | ❌ MISSED | No Sysmon EID 12/13 rules configured |
| T1003.001 — LSASS Dump | ✅ DETECTED | Windows command prompt started by abnormal process |
| T1550.002 — Pass-the-Hash | ✅ DETECTED | Windows logon success |
| T1071.001 — C2 Beacon | ✅ DETECTED | Windows command prompt started by abnormal process |
| T1490 — Shadow Copy Deletion | ❌ MISSED | No vssadmin.exe detection rule |
| T1486 — File Encryption | ❌ MISSED | No FileCreate extension monitoring |

> **Detection Rate: 4/7 (57%) — Risk Level: CRITICAL**
>
> Janus immediately auto-generated 3 Sigma rules for the gaps, deployed them, and rescanned to achieve 7/7.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           JANUS PLATFORM                            │
│                                                                     │
│   Browser                                                           │
│   dashboard.html ◄──── Socket.IO (WebSocket) ────► orchestrator.py │
│                                                      (Flask :5000)  │
│                                                           │         │
│                                              ┌────────────┴──────┐  │
│                                              │   SSH / Paramiko  │  │
│                                              └────────────┬──────┘  │
│                                                           │         │
│                                              ┌────────────▼──────┐  │
│                                              │  Windows 10 VM    │  │
│                                              │  Atomic Red Team  │  │
│                                              │  192.168.70.150   │  │
│                                              └────────────┬──────┘  │
│                                                           │         │
│                                              ┌────────────▼──────┐  │
│                                              │  Wazuh 4.7.5      │  │
│                                              │  + OpenSearch     │  │
│                                              │  192.168.70.129   │  │
│                                              └────────────┬──────┘  │
│                                                           │         │
│                                              ┌────────────▼──────┐  │
│                                              │  Gemini 2.5 Flash │  │
│                                              │  (AI Report)      │  │
│                                              └───────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Stack

```
Backend       Python 3.10 · Flask · Flask-SocketIO · Paramiko · Requests
Attack        Atomic Red Team (Invoke-AtomicTest) · Custom PowerShell scripts
SIEM          Wazuh 4.7.5 · OpenSearch 2.x · Sysmon 15.x
AI            Google Gemini 2.5 Flash (google-genai SDK)
Frontend      Vanilla JS · Socket.IO · JetBrains Mono · Inter
Detection     Sigma YAML → Wazuh XML
```

---

## Setup

**1. Install dependencies**

```bash
pip install flask flask-socketio paramiko requests urllib3 google-genai
```

**2. Configure `orchestrator.py`**

```python
WAZUH_HOST  = "192.168.70.129"   # Wazuh manager IP
WIN10_IP    = "192.168.70.150"   # Windows 10 target IP
WIN10_USER  = "your-username"
WIN10_PASS  = "your-password"
GEMINI_KEY  = "your-api-key"     # Get from Google AI Studio
```

**3. Run**

```bash
sudo -E python3 orchestrator.py
```

Open `http://<wazuh-ip>:5000` in a browser.

> **Requirements:** Wazuh 4.7.5 with OpenSearch, Sysmon on the Windows target, Atomic Red Team installed (`Install-AtomicRedTeam -getAtomics`), SSH access to the target.

---

## Dashboard Controls

| Button | Action |
|--------|--------|
| ▶ Run Kill Chain | Execute all 7 techniques live against the target |
| ⚡ Demo Mode | Replay cached results — use this for presentations |
| ⬆ Implement Rule | Deploy a Sigma rule for a detected gap |
| ⟳ Rescan Threat | Re-run with deployed rules active to prove gaps closed |
| ✦ AI Report | Generate full security report via Gemini |
| ↺ Reset | Clear all state and start fresh |

---

## Project Structure

```
janus/
├── orchestrator.py        # Core Flask + SocketIO engine, chain runner, Gemini integration
├── dashboard.html         # Live real-time frontend dashboard
├── navigator.py           # MITRE ATT&CK Navigator layer + Sigma rule generator
├── wazuh_client.py        # Wazuh REST API + OpenSearch query helpers
├── atomic_runner.py       # Atomic Red Team SSH execution wrapper
└── detection/
    ├── powershell.py      # T1059.001 detection logic
    ├── mimikatz.py        # T1003.001 detection logic
    ├── pth.py             # T1550.002 detection logic
    ├── shadow_copy.py     # T1490 detection logic
    └── ransomware.py      # T1486 detection logic
```

---

## Team

Built in 24 hours at **ACC Hackathon 2026** — Azerbaijan Cybersecurity Center.

<div align="center">

| | | |
|:---:|:---:|:---:|
| **Orkhan Azimov** | **Malahat Mammadli** | **Omar Huseynli** |
| **Hasan Yunisov** | **Kanan Isagov** | **Ramil Malikov** |

</div>

---

<div align="center">

*Janus — See both sides of every attack.*

</div>
