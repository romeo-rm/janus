# Janus — Repeatable Attack-to-Detection Process

**Platform**: Janus Purple Team Automation | **ACC Hackathon 2026**  
**Reference**: [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) — `building-detection-rules-with-sigma`, `analyzing-threat-actor-ttps-with-mitre-navigator`

---

## Overview

Janus implements a 7-step repeatable process for tracing adversary techniques to Sysmon telemetry, writing detection logic, and validating coverage. Each step produces a concrete artifact that feeds the next.

```
SELECT TTP → EXECUTE → CAPTURE TELEMETRY → QUERY SIEM → EVALUATE → WRITE SIGMA → VALIDATE
```

---

## The 7-Step Process

### Step 1: Select Technique

Choose an ATT&CK technique and map it to an Atomic Red Team test.

**Inputs:**
- ATT&CK technique ID (e.g. `T1082`)
- Atomic Red Team test number
- Expected telemetry source (Sysmon EID)

**Artifacts:**
- Entry in `KILL_CHAIN` list in `orchestrator.py`
- Corresponding Sigma rule YAML filename

**Example:**
```python
{"id": "T1082", "name": "System Information Discovery", "tactic": "discovery", "test": 1}
```

---

### Step 2: Execute via Janus / Atomic Red Team

Run the technique on the Windows target using `Invoke-AtomicTest`.

**Via orchestrator (automated):**
```
POST /run   →  Janus SSH → Windows target → Invoke-AtomicTest
```

**Via manual script:**
```powershell
# On Windows target (192.168.10.134)
Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1
Invoke-AtomicTest T1082 -TestNumbers 1 -Confirm:$false -TimeoutSeconds 45
```

**Via orchestrator SSH (from Wazuh host):**
```bash
plink -ssh target@192.168.10.134 -batch \
  "powershell -ExecutionPolicy Bypass -File C:\Users\target\run_atomics.ps1"
```

**Artifacts:**
- ART execution log (stdout)
- Atomic test exit code

---

### Step 3: Capture Telemetry

Identify which Sysmon Event IDs the technique triggers. Each EID maps to a Wazuh decoder field path.

| Sysmon EID | Event Type          | Key Field                    | Wazuh Group         |
|-----------|---------------------|------------------------------|---------------------|
| 1         | Process Create      | `win.eventdata.image`        | `sysmon_event1`     |
| 3         | Network Connect     | `win.eventdata.destinationPort` | `sysmon_event3`  |
| 8         | CreateRemoteThread  | `win.eventdata.targetImage`  | `sysmon_event8`     |
| 10        | ProcessAccess       | `win.eventdata.targetImage`  | `sysmon_event_10`   |
| 11        | FileCreate          | `win.eventdata.targetFilename` | `sysmon_event_11` |
| 12        | RegistryCreate/Del  | `win.eventdata.targetObject` | `sysmon_event_12`   |
| 13        | RegistrySetValue    | `win.eventdata.targetObject` | `sysmon_event_13`   |
| 23        | FileDelete          | `win.eventdata.targetFilename` | `sysmon_event_23` |

**Verification command:**
```powershell
# On Windows target — check recent Sysmon events
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 20 |
  Where-Object {$_.Id -in @(1,3,8,11,13)} | Format-List Id, TimeCreated, Message
```

---

### Step 4: Query SIEM (Wazuh / OpenSearch)

After technique execution, query Wazuh for matching alerts.

**Via Janus orchestrator (`/debug/groups` endpoint):**
```bash
curl http://192.168.10.133:5001/debug/groups
```

**Via Wazuh alerts log:**
```bash
# On Wazuh (192.168.10.133)
grep "janus_t1082" /var/ossec/logs/alerts/alerts.log | tail -5
grep '"id":"T1082"' /var/ossec/logs/alerts/alerts.json | tail -5
```

**Via OpenSearch API:**
```bash
curl -u admin:admin -k "https://192.168.10.133:9200/wazuh-alerts-*/_search" \
  -H "Content-Type: application/json" \
  -d '{"query": {"match": {"rule.groups": "janus_t1082"}}, "size": 5}'
```

---

### Step 5: Evaluate Detection

Compare the Wazuh alert count against expected outcome.

| Result | Meaning | Action |
|--------|---------|--------|
| Alert fired, janus group present | **DETECTED** | Mark green in Navigator |
| Alert fired, existing Wazuh rule only | **DETECTED (built-in)** | Mark yellow in Navigator |
| No alert, but telemetry seen | **GAP — rule missing or regex fail** | Go to Step 6 |
| No telemetry | **BLIND SPOT** | Check Sysmon config + agent.conf |

---

### Step 6: Write / Deploy Sigma Rule

If detection fails, write a Sigma rule in `sigma/`, compile to Wazuh XML, and deploy.

**Sigma rule template:**
```yaml
title: T1082 - System Information Discovery
id: <uuid>
status: experimental
description: Detects systeminfo or hostname enumeration
references:
  - https://attack.mitre.org/techniques/T1082/
author: Janus / Anthropic Cybersecurity Skills
date: 2026-06-16
tags:
  - attack.discovery
  - attack.t1082
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 1
    Image|endswith:
      - '\systeminfo.exe'
      - '\hostname.exe'
  condition: selection
level: low
```

**Compile to Wazuh XML and deploy:**
```bash
# Write rule to local_rules.xml on Wazuh
sudo nano /var/ossec/etc/rules/local_rules.xml

# Reload Wazuh rules
sudo systemctl restart wazuh-manager

# Verify rule loaded
sudo grep "100108" /var/ossec/logs/ossec.log | tail -3
```

**Local rule example (from `local_rules.xml`):**
```xml
<rule id="100108" level="4">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)\\(systeminfo|hostname)\.exe$</field>
  <description>T1082: System Information Discovery via systeminfo or hostname</description>
  <group>sysmon_eid1_detections,janus_t1082,</group>
  <mitre><id>T1082</id></mitre>
</rule>
```

---

### Step 7: Validate and Update Navigator

Re-run the technique after deploying the rule. Confirm the alert fires, then update the ATT&CK Navigator layer.

```bash
# Re-run the technique
plink -ssh target@192.168.10.134 -batch \
  "powershell -Command Invoke-AtomicTest T1082 -TestNumbers 1 -Confirm:`$false"

# Confirm detection
grep "janus_t1082" /var/ossec/logs/alerts/alerts.log | wc -l
# Expected: > 0

# Update navigator_layer.json — set color to green (#66bb6a) for detected techniques
```

**Navigator layer location:** `sigma/navigator_layer.json`  
**Import at:** https://mitre-attack.github.io/attack-navigator/

---

## Validation Results (ART Run — 2026-06-16)

| # | ATT&CK ID  | Technique                       | ART Test | Status        | Janus Rule | Alert Count |
|---|------------|---------------------------------|----------|---------------|------------|-------------|
| 1 | T1566.001  | Spearphishing Attachment        | -        | Sigma ready   | 100117     | -           |
| 2 | T1059.001  | PowerShell Execution            | #17      | **DETECTED**  | 100100     | 4           |
| 3 | T1547.001  | Registry Run Key Persistence    | #1       | **DETECTED**  | 100101     | 1           |
| 4 | T1055      | Process Injection               | -        | Sigma ready   | 100102     | -           |
| 5 | T1134      | Access Token Manipulation       | -        | Sigma ready   | 100103     | -           |
| 6 | T1562.001  | Disable Security Tools          | #1       | ART missing   | 100104     | -           |
| 7 | T1027      | Obfuscated Files                | #1       | ART missing   | 100105     | -           |
| 8 | T1112      | Modify Registry                 | #1       | **DETECTED**  | 100122     | 1           |
| 9 | T1003.001  | LSASS Dump (Mimikatz)           | -        | Sigma ready   | 100107     | -           |
|10 | T1082      | System Information Discovery    | #1       | **DETECTED**  | 100108     | 21          |
|11 | T1083      | File and Directory Discovery    | #1       | Timeout       | 100109     | -           |
|12 | T1069.001  | Local Groups Discovery          | #1       | ART missing   | 100110     | -           |
|13 | T1016      | Network Config Discovery        | #1       | **DETECTED**  | 100123     | 2           |
|14 | T1018      | Remote System Discovery         | #1       | **DETECTED**  | 100112     | 2           |
|15 | T1550.002  | Pass-the-Hash                   | -        | Sigma ready   | 100118     | -           |
|16 | T1071.001  | C2 Beacon (HTTP)                | -        | Sigma ready   | -          | -           |
|17 | T1048      | Exfiltration over Alt Protocol  | -        | Sigma ready   | 100113     | -           |
|18 | T1070.004  | Indicator Removal: File Delete  | -        | Sigma ready   | 100114     | -           |
|19 | T1490      | Shadow Copy Deletion            | #1       | **DETECTED**  | 100115     | 1           |
|20 | T1486      | File Encryption (Ransomware)    | -        | ART missing   | 100116     | -           |

**Detection rate: 7/20 techniques validated live (35%) + 13 Sigma rules deployed and ready**

---

## Tactic Coverage Map

| Kill Chain Phase     | ATT&CK Tactic         | Techniques |
|----------------------|-----------------------|------------|
| Initial Access       | initial-access        | T1566.001  |
| Execution            | execution             | T1059.001  |
| Persistence          | persistence           | T1547.001  |
| Privilege Escalation | privilege-escalation  | T1134      |
| Defense Evasion      | defense-evasion       | T1055, T1562.001, T1027, T1112, T1070.004 |
| Credential Access    | credential-access     | T1003.001  |
| Discovery            | discovery             | T1082, T1083, T1069.001, T1016, T1018 |
| Lateral Movement     | lateral-movement      | T1550.002  |
| C2                   | command-and-control   | T1071.001  |
| Exfiltration         | exfiltration          | T1048      |
| Impact               | impact                | T1490, T1486 |

**11 of 14 ATT&CK tactics covered**

---

## Infrastructure Reference

| Component | Address | Credentials |
|-----------|---------|-------------|
| Wazuh SIEM | `192.168.10.133` | `wazuh` / `4242` |
| Windows Target | `192.168.10.134` | `target` / `target` |
| Atomic Red Team | `C:\AtomicRedTeam\` | — |
| Sysmon Config | `C:\Windows\sysmon.xml` | — |
| Wazuh Rules | `/var/ossec/etc/rules/local_rules.xml` | — |
| Sigma Rules | `/opt/hackathon/workspace/sigma/` | — |
| Janus API | `http://192.168.10.133:5001` | — |

---

## Janus Rule ID Reference

| Rule ID | Technique | Description | Level |
|---------|-----------|-------------|-------|
| 100100  | T1059.001 | PowerShell from abnormal parent | 10 |
| 100101  | T1547.001 | Registry Run Key Persistence | 10 |
| 100102  | T1055     | CreateRemoteThread Injection | 12 |
| 100103  | T1134     | whoami /priv token enumeration | 8  |
| 100104  | T1562.001 | Defender disabled via PowerShell | 14 |
| 100105  | T1027     | PowerShell EncodedCommand | 8  |
| 100106  | T1112     | Security/policy registry key mod | 8  |
| 100107  | T1003.001 | LSASS dump / mimikatz cmdline | 14 |
| 100108  | T1082     | systeminfo.exe / hostname.exe | 4  |
| 100109  | T1083     | Recursive directory listing | 4  |
| 100110  | T1069.001 | net localgroup enumeration | 4  |
| 100111  | T1016     | ipconfig/arp/netstat process | 3  |
| 100112  | T1018     | net view / remote host discovery | 5  |
| 100113  | T1048     | Non-browser on exfil port | 10 |
| 100114  | T1070.004 | Forced file deletion via cmd | 6  |
| 100115  | T1490     | vssadmin delete shadows | 15 |
| 100116  | T1486     | Encrypted file extension created | 14 |
| 100117  | T1566.001 | Suspicious file in user Downloads | 10 |
| 100118  | T1550.002 | Pass-the-Hash tool cmdline | 10 |
| 100119  | T1134     | Known token impersonation tool | 10 |
| 100120  | T1562.001 | WinDefend service stopped via sc | 14 |
| 100121  | T1059.001 | PowerShell from cmd chain | 10 |
| 100122  | T1112     | reg.exe/PS registry modification | 6  |
| 100123  | T1016     | cmd.exe with network enum cmds | 3  |

---

*Process inspired by [Anthropic Cybersecurity Skills — building-detection-rules-with-sigma](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)*
