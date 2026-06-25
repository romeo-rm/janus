<div align="center">

<img src="https://img.shields.io/badge/-%F0%9F%94%B1%20JANUS-000000?style=for-the-badge&labelColor=000000" alt="JANUS"/>

# J A N U S

### `Adversary Emulation · Automated Detection Engineering · Purple Team Automation`

<br/>

> *In Roman mythology, Janus is the god of duality — two faces, two directions, one god.*
> *One face stares into the attacker's world. The other watches your defenses.*
> *Both, simultaneously. Always.*

<br/>

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.7.5-005571?style=for-the-badge)](https://wazuh.com)
[![Gemini](https://img.shields.io/badge/Gemini-2.5_Flash-4285F4?style=for-the-badge&logo=google&logoColor=white)](https://ai.google.dev)
[![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-FF0000?style=for-the-badge)](https://attack.mitre.org)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)
[![Built In](https://img.shields.io/badge/Built_In-24_Hours-f59e0b?style=for-the-badge)](https://github.com/romeo-rm/janus)

<br/>

**🏆 Built at ACC Hackathon 2026 — Azerbaijan Cybersecurity Center**

<br/>

```
╔══════════════════════════════════════════════════════════════╗
║  "If a ransomware group hit your network right now —        ║
║   would your SIEM catch it?"                                ║
║                                                              ║
║  Most SOCs don't know the answer until it's too late.       ║
║  Janus gives you the answer in minutes.                     ║
╚══════════════════════════════════════════════════════════════╝
```

</div>

---

## 🔥 What is Janus?

Janus is an **open-source, AI-powered adversary emulation and automated detection engineering platform** that closes the most dangerous gap in enterprise security: the space between *"we think we're protected"* and *"we know we're protected."*

It executes a real, end-to-end ransomware kill chain against a live Windows target — the same techniques documented in LockBit, REvil, and Conti playbooks — then immediately queries your Wazuh SIEM to find out exactly what was caught and what walked right through. For every gap found, Janus generates a production-ready Sigma detection rule, deploys it live to the running SIEM engine, and rescans to prove the gap is mathematically closed.

No assumptions. No guessing. No expensive consultants. **Evidence.**

At the end of a run, one click triggers Google Gemini 2.5 Flash to produce a full professional security report — executive summary, risk ratings, detection gap root cause analysis, three Sigma rules in YAML, and a prioritized remediation roadmap — in 30 seconds flat.

**This is the complete purple team loop: attack → detect → fix → verify. Fully automated. Completely free.**

---

## ⚡ Features

<table>
<tr>
<td width="50%">

### 🎯 Live Kill Chain Execution
Execute a real 20-technique ransomware kill chain against a live Windows 10 target via SSH. No synthetic simulation — real PowerShell, real LSASS dumps, real shadow copy deletion. Covers initial access through encryption across 8 MITRE ATT&CK tactics.

</td>
<td width="50%">

### 📡 Real-Time SIEM Correlation
After each technique, Janus queries Wazuh + OpenSearch with precision time-windowed queries to determine — with certainty — whether an alert fired or the attack passed silently through.

</td>
</tr>
<tr>
<td width="50%">

### 🛡️ Automatic Sigma Generation
Every undetected technique surfaces a gap card with a complete, production-ready Sigma rule in YAML — the industry standard format. No manual rule writing. No research required.

</td>
<td width="50%">

### ⚡ 60-Second Deploy Loop
The feature no competitor has. Click "Implement Rule" — watch the terminal compile Sigma to Wazuh XML, write it to the detection engine, signal a reload. Click "Rescan" — the gap is now DETECTED. Under 60 seconds. What used to take 17 days.

</td>
</tr>
<tr>
<td width="50%">

### 🤖 AI Security Report
One click. 30 seconds. Google Gemini 2.5 Flash produces an 8-section professional security report ready to hand to a CISO — or a board. What a senior analyst would spend 2–3 days writing.

</td>
<td width="50%">

### 🖥️ Real-Time Dashboard
A live SOC-style dashboard with kill chain pipeline animation, per-technique status nodes, score counter, MITRE ATT&CK tactic coverage chips, Sigma gap cards, and a timestamped log feed — all updating via WebSocket with no page refresh.

</td>
</tr>
</table>

---

## 💀 The Kill Chain

This is not a random selection of techniques. This is the **documented operational playbook** of the world's most prolific ransomware operators, reconstructed step by step from MITRE ATT&CK intelligence reports and threat actor profiles.

```
 ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
 │  T1059.001  │───►│  T1547.001  │───►│  T1003.001  │───►│  T1550.002  │
 │  PowerShell │    │  Registry   │    │  LSASS Dump │    │  Pass-the-  │
 │  Execution  │    │  Persistence│    │  (Mimikatz) │    │  Hash       │
 └─────────────┘    └─────────────┘    └─────────────┘    └──────┬──────┘
                                                                  │
              ┌───────────────────────────────────────────────────┘
              ▼
 ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
 │  T1071.001  │───►│    T1490    │───►│    T1486    │
 │  C2 Beacon  │    │  Shadow     │    │    File     │
 │  over HTTP  │    │  Copy Del.  │    │  Encryption │
 └─────────────┘    └─────────────┘    └─────────────┘
                          💀                  🔒
                     (No recovery)      (Ransom note)
```

| # | Technique ID | Name | Tactic | Real-World Actor |
|---|-------------|------|--------|-----------------|
| 1 | **T1566.001** | Spearphishing Attachment | Initial Access | LockBit, Conti |
| 2 | **T1059.001** | PowerShell Execution | Execution | LockBit, Conti, REvil |
| 3 | **T1547.001** | Registry Run Key Persistence | Persistence | LockBit 3.0 |
| 4 | **T1055** | Process Injection | Defense Evasion | BlackCat, Conti |
| 5 | **T1134** | Access Token Manipulation | Privilege Escalation | REvil, BlackCat |
| 6 | **T1562.001** | Disable Security Tools | Defense Evasion | LockBit, REvil |
| 7 | **T1027** | Obfuscated Files or Information | Defense Evasion | All major ransomware groups |
| 8 | **T1112** | Modify Registry | Defense Evasion | LockBit 3.0 |
| 9 | **T1003.001** | LSASS Memory Dump (Mimikatz) | Credential Access | Conti, BlackCat |
| 10 | **T1082** | System Information Discovery | Discovery | Conti, REvil |
| 11 | **T1083** | File and Directory Discovery | Discovery | LockBit, BlackCat |
| 12 | **T1069.001** | Local Groups Discovery | Discovery | Conti, REvil |
| 13 | **T1016** | Network Configuration Discovery | Discovery | LockBit, Conti |
| 14 | **T1018** | Remote System Discovery | Discovery | Conti, REvil |
| 15 | **T1550.002** | Pass-the-Hash Lateral Movement | Lateral Movement | REvil, Conti |
| 16 | **T1071.001** | C2 Beacon over HTTP | Command & Control | Lazarus, REvil |
| 17 | **T1048** | Exfiltration over Alternative Protocol | Exfiltration | BlackCat, LockBit |
| 18 | **T1070.004** | File Deletion (Indicator Removal) | Defense Evasion | All major ransomware groups |
| 19 | **T1490** | Volume Shadow Copy Deletion | Impact | All major ransomware groups |
| 20 | **T1486** | File Encryption (XOR) | Impact | LockBit, BlackCat, REvil |

---

## 📊 Hackathon Results — Live Run

*Real execution. Real target. Real SIEM. No simulation.*

```
┌────────────────────────────────────────────────────────────────────┐
│  ENGAGEMENT SUMMARY                                                │
│                                                                    │
│  Target      victim-win10 (192.168.70.150)                         │
│  SIEM        Wazuh 4.7.5 + OpenSearch                              │
│  Date        ACC Hackathon 2026 — June 12, 22:41 UTC               │
│  Duration    ~6 minutes                                            │
│                                                                    │
│  Detection Rate   ████████░░░░░░  4 / 7   (57%)                   │
│  Risk Level       ██ CRITICAL                                      │
│  Gaps Found       3                                                │
│  Sigma Generated  3                                                │
└────────────────────────────────────────────────────────────────────┘
```

| Technique | Result | Wazuh Alert |
|-----------|--------|-------------|
| T1059.001 — PowerShell Execution | ✅ **DETECTED** | *Windows command prompt started by abnormal process* |
| T1547.001 — Registry Persistence | ❌ **MISSED** | No Sysmon EID 12/13 rules configured |
| T1003.001 — LSASS Dump | ✅ **DETECTED** | *Windows command prompt started by abnormal process* |
| T1550.002 — Pass-the-Hash | ✅ **DETECTED** | *Windows logon success* |
| T1071.001 — C2 Beacon | ✅ **DETECTED** | *Windows command prompt started by abnormal process* |
| T1490 — Shadow Copy Deletion | ❌ **MISSED** | No vssadmin.exe detection rule |
| T1486 — File Encryption | ❌ **MISSED** | No FileCreate extension monitoring |

> **The three missed techniques are the three most dangerous.** Registry persistence means the attacker survives cleanup. Shadow copy deletion means recovery is impossible. File encryption is the payload. Janus found all three — and closed all three in under 3 minutes.

---

## 🏗️ Architecture

```
                              ┌──────────────────────────────┐
                              │         BROWSER              │
                              │       dashboard.html         │
                              │   Kill chain · Score · Logs  │
                              └──────────────┬───────────────┘
                                             │
                                      WebSocket (Socket.IO)
                                             │
                              ┌──────────────▼───────────────┐
                              │       ORCHESTRATOR           │
                              │     orchestrator.py          │
                              │     Flask · SocketIO         │
                              │     :5000 on 192.168.70.129  │
                              └────────┬─────────────┬───────┘
                                       │             │
                              SSH/Paramiko        REST API
                                       │             │
               ┌───────────────────────▼──┐   ┌──────▼────────────────────────┐
               │    WINDOWS 10 TARGET     │   │       WAZUH SIEM              │
               │    192.168.70.150        │   │       192.168.70.129          │
               │                          │   │                               │
               │  • Atomic Red Team       │   │  • Wazuh Manager 4.7.5        │
               │  • Invoke-AtomicTest     │◄──┤  • OpenSearch :9200           │
               │  • Sysmon 15.x           │   │  • Sysmon Event Processing    │
               │  • Wazuh Agent           │──►│  • Alert Correlation Engine   │
               └──────────────────────────┘   └──────────────┬────────────────┘
                                                              │
                                                       Query Results
                                                              │
                                              ┌───────────────▼────────────────┐
                                              │       GEMINI 2.5 FLASH         │
                                              │    AI Report Generation        │
                                              │    Executive · Risk · Sigma    │
                                              │    P1 / P2 / P3 Remediation   │
                                              └────────────────────────────────┘
```

---

## 🛠️ Stack

```yaml
Backend:
  - Python 3.10
  - Flask 3.x           # REST API + web server
  - Flask-SocketIO 5.x  # Real-time WebSocket events to dashboard
  - Paramiko 3.x        # SSH into Windows target to run attacks
  - Requests 2.x        # OpenSearch + Wazuh REST API queries

Attack Execution:
  - Custom PowerShell   # One crafted command per MITRE technique with janus markers
  - Paramiko SSH        # Remote execution on the Windows target

Security Monitoring:
  - Wazuh 4.7.5         # SIEM — collects and correlates events
  - OpenSearch 2.x      # Alert storage and search engine
  - Sysmon 15.x         # Windows endpoint telemetry (EID 1, 3, 11, 12, 13)

AI & Reporting:
  - Google Gemini 2.5 Flash  # Report generation (google-genai SDK)
  - Sigma YAML               # Industry-standard detection rule format

Frontend:
  - Vanilla JavaScript  # No heavy frameworks — pure speed
  - Socket.IO CDN       # Live event streaming
  - JetBrains Mono      # Terminal-style data display
  - Inter               # Clean body typography
```

---

## 🚀 Setup

### Prerequisites

- Ubuntu 22.04 server with Wazuh 4.7.5 + OpenSearch installed
- Windows 10 target with Sysmon, Wazuh Agent, and Atomic Red Team
- SSH access from the Ubuntu server to the Windows target
- Google AI Studio API key (free tier works)

### Installation

```bash
# Clone the repo
git clone https://github.com/romeo-rm/janus.git
cd janus

# Install Python dependencies
pip install -r requirements.txt
```

### Configuration

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

```ini
JANUS_WAZUH_HOST=192.168.10.133      # Your Wazuh manager IP
JANUS_WAZUH_API_USER=wazuh-wui
JANUS_WAZUH_API_PASS=your-api-pass
JANUS_INDEXER_USER=admin
JANUS_INDEXER_PASS=your-indexer-pass
JANUS_WAZUH_SSH_USER=wazuh
JANUS_WAZUH_SSH_PASS=your-ssh-pass
JANUS_TARGET_HOST=192.168.10.134     # Your Windows target IP
JANUS_TARGET_USER=target
JANUS_TARGET_PASS=your-target-pass
JANUS_GEMINI_KEY=your-api-key        # Google AI Studio → Get API Key
```

### Run

```bash
python3 orchestrator.py
```

Open **`http://<your-wazuh-ip>:5000`** in a browser. You're live.

---

## 🎮 Dashboard Controls

| Control | What It Does |
|---------|-------------|
| **▶ Run Kill Chain** | Live execution — SSHes into target, runs all 20 techniques, queries Wazuh after each one |
| **⬆ Implement Rule** | Deploys Wazuh detection rules for the selected gap — terminal overlay shows live SSH deployment |
| **⟳ Rescan Missed** | Re-runs only the missed techniques with deployed rules active — proves gaps are closed |
| **✦ AI Report** | Calls Gemini 2.5 Flash — full security report generated in ~30 seconds |
| **↺ Reset** | Clears all run results and logs — ready for a fresh run |

---

## 📁 Project Structure

```
janus/
│
├── orchestrator.py        # 🧠 Core engine — Flask API, SocketIO, 20-technique chain
│                          #    runner, SSH rule deployment, Wazuh Indexer queries,
│                          #    Gemini report generation
│
├── dashboard.html         # 🖥️  Real-time SOC dashboard — kill chain pipeline animation,
│                          #    score counter, Sigma gap cards, rule deploy terminal,
│                          #    log feed, AI report modal
│
├── local_rules.xml        # 🔍 20 Wazuh detection rules with janus markers (IDs 100100–100119)
│
├── local_rules_weak.xml   # 🎯 Baseline ruleset with intentional gaps for T1055, T1486,
│                          #    T1027, T1550.002, T1071.001 — used to demonstrate gap
│                          #    detection and remediation flow
│
├── navigator.py           # 🗺️  MITRE ATT&CK Navigator layer generator
│
├── requirements.txt       # 📦 Python dependencies
├── .env.example           # ⚙️  Configuration template (copy to .env and fill in values)
├── OPERATIONS.md          # 📖 Runtime operations and maintenance guide
│
├── sigma/                 # 📐 20 Sigma rules in YAML — one per ATT&CK technique
│
├── deploy/
│   └── janus.service      # 🚀 systemd unit file for production deployment
│
└── tests/
    └── test_orchestrator.py  # ✅ Unit tests for detection correlation and rule deployment
```

---

## 🆚 Why Janus?

| | Cymulate | AttackIQ | SafeBreach | MITRE Caldera | **Janus** |
|--|:---:|:---:|:---:|:---:|:---:|
| **Price** | $7K–$91K/yr | Custom/$$$ | Custom/$$$ | Free | **Free** |
| **Open Source** | ❌ | ❌ | ❌ | ✅ | ✅ |
| **Self-Hosted** | ❌ | Partial | ❌ | ✅ | ✅ |
| **Wazuh-Native** | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Real-Time SIEM Loop** | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Auto Sigma Generation** | ❌ | ❌ | ❌ | ❌ | ✅ |
| **One-Click Rule Deploy** | ❌ | ❌ | ❌ | ❌ | ✅ |
| **AI Security Report** | ❌ | ❌ | ❌ | ❌ | ✅ |

> Every commercial platform on this list costs more than the annual salary of an Azerbaijani SOC analyst.

---

## 🗺️ Roadmap

```
NOW ──────────────────────────────────────────────────────────────► 24 months

  Phase 1            Phase 2            Phase 3            Phase 4
  0–3 months         3–9 months         6–12 months        12–24 months
  ──────────         ──────────         ───────────        ────────────
  40+ techniques     Active Directory   Linux / macOS      Visual chain
  3 kill chains      Kerberoasting      Containers         builder
  PDF reports        DCSync             Kubernetes         MISP/OpenCTI
  ISO 27001          Golden Ticket      Multi-target       CI/CD gates
  NIST/PCI-DSS       BloodHound         orchestration      Splunk/Sentinel
  mapping            integration                           MSSP platform
```

---

## 👥 Team

Built in **24 hours** at **ACC Hackathon 2026** — Azerbaijan Cybersecurity Center.

<div align="center">

<br/>

| 🧑‍💻 | 🧑‍💻 | 🧑‍💻 |
|:---:|:---:|:---:|
| **Orkhan Azimov** | **Malahat Mammadli** | **Omar Huseynli** |
| **Hasan Yunisov** | **Kanan Isagov** | **Ramil Malikov** |

</div>

---

<div align="center">

<br/>

```
Janus — See both sides of every attack.
```

<br/>

*Made with 🔥 and zero sleep at ACC Hackathon 2026*

</div>
