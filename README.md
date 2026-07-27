# SOC Lab Investigations & Triage Notes

SOC Lab Investigations & Triage Notes — home‑lab incident triage examples (KQL, Defender XDR, ReportLab PDF generator).  
Contact: leonardo.barros

This repository contains practical incident triage notes, KQL detection queries, and timeline analyses generated during home-lab security simulations. It demonstrates alert triage, evidence collection, and containment reasoning using Microsoft Defender XDR and Microsoft Sentinel concepts.

---

## Investigation 01: Suspicious PowerShell Execution via IIS

**Date:** 2026-07-20  
**Environment:** Home Lab Simulation  
**Analyst:** Leonardo Barros

### 1. Alert Summary

- **Alert Title:** `Suspicious Process Execution - Encoded PowerShell Spawned by IIS Process`  
- **Severity:** High  
- **Host:** `WEB-SRV-01 (lab)`  
- **Account Context:** `svc-webapp`

### 2. KQL Detection Query Used

```kql
DeviceProcessEvents
| where Timestamp > ago(12h) and DeviceName == 'WEB-SRV-01'
| where InitiatingProcessFileName == 'w3wp.exe' and FileName == 'powershell.exe'
| project Timestamp, DeviceName, AccountName, ProcessId, CommandLine, InitiatingProcessCommandLine
```

### 3. Incident Timeline

- 14:02:11 UTC – Inbound web request to /contact/upload.aspx handled by IIS (w3wp.exe).

- 14:02:15 UTC – w3wp.exe (PID 2104) spawns powershell.exe (PID 4892) under svc-webapp.

- 14:02:16 UTC – PowerShell executes encoded command: powershell.exe -EncodedCommand a3ZyZXE...

- 14:02:18 UTC – Encoded payload decodes to script inspecting directory permissions and running whoami /priv.

- 14:03:00 UTC – High-severity alert generated in Defender for Endpoint; assigned for triage.

### 4. Evidence and Analysis

- Unusual Parent-Child Relationship: w3wp.exe should not spawn interactive shells.

- Command Obfuscation: -EncodedCommand indicates evasion.

- Local Reconnaissance: whoami /priv suggests discovery activity.

- Context Check: No scheduled maintenance for this host.

### 5. Conclusion and Likely Cause

Potential file upload abuse or web application vulnerability allowing unauthorized command execution via the web server account.

### 6. Recommended Containment and Initial Actions

1. Isolate Host: Soft network isolation via Defender for Endpoint.

2. Reset Credentials: Reset svc-webapp password and revoke sessions.

3. Application Review: Inspect upload logs and patch the endpoint.

### 7. MITRE ATT&CK Mapping

- T1190 — Exploit Public-Facing Application

- T1059.001 — PowerShell

- T1027 — Obfuscated Files or Information

- T1033 — System Owner/User Discovery

---

## Automation

Run generate_report.py to create a single-page PDF Investigation_PowerShell.pdf using ReportLab. See requirements.txt for dependencies.

---

## How to run locally

1. Create and activate a Python virtual environment.

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Generate the PDF:

```bash
python generate_report.py
```
4. Review the generated PDF and commit files you want visible in the repo.
