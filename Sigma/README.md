# Sigma Detection Rules

![Sigma](https://img.shields.io/badge/Format-Sigma-4CAF50?style=flat&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?style=flat&logo=windows&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-Detection_Engineering-E01B1B?style=flat&logoColor=white)

**Analyst:** Denis O. Onduso  
**Format:** Sigma — vendor-neutral detection rule format convertible to Splunk SPL, Elastic EQL, Microsoft Sentinel KQL, and others

---

## Overview

This directory contains Sigma rules covering three high-priority detection use cases: brute-force credential attacks, PowerShell-based execution and obfuscation, and post-compromise persistence via local account creation. Each rule is written against Windows log sources and maps to specific MITRE ATT&CK techniques.

---

## Rules

### 1. Windows Brute Force Detection
**File:** `brute_force_detection.yml`  
**Status:** Experimental  
**Level:** Medium

Detects multiple failed Windows logon events (Event ID 4625) from a single source IP within a 15-minute window. Filtered to network (Logon Type 3) and RDP (Logon Type 10) logon types to exclude local and service account noise. Fires when failure count exceeds 7 per source IP per user within the timeframe.

| Field | Value |
|-------|-------|
| Log source | Windows Security Log |
| Event ID | 4625 |
| Logon types | 3 (Network), 10 (RemoteInteractive) |
| Threshold | >7 failures within 15 minutes |
| MITRE | T1110.001 — Brute Force: Password Guessing |

**Known false positives:** Service accounts with expired credentials, legitimate user lockouts, penetration testing activity.

---

### 2. Suspicious PowerShell Execution Patterns
**File:** `powershell_suspicious.yml`  
**Status:** Test  
**Level:** High

Detects PowerShell script block content containing indicators of encoded execution, dynamic invocation, and in-memory download patterns. Targets the string patterns most commonly found in malicious PowerShell payloads while remaining specific enough to limit noise from legitimate administrative scripts.

| Field | Value |
|-------|-------|
| Log source | Windows PowerShell (Script Block Logging) |
| Detected strings | `-EncodedCommand`, `Invoke-Expression`, `IEX`, `DownloadString`, `FromBase64String` |
| MITRE | T1059.001 — PowerShell, T1027 — Obfuscated Files |

**Known false positives:** Legitimate administrative scripts using encoded commands, security tooling (e.g. SCCM, Ansible) that uses `IEX` or encoded payloads internally. Recommend allowlisting known tooling parent processes.

---

### 3. Account Creation and Immediate Use
**File:** `account_creation_immediate_use.yml`  
**Status:** Experimental  
**Level:** High

Detects a new local user account (Event ID 4720) followed by a successful logon from that account (Event ID 4624) within one hour. An account being used immediately after creation is a strong indicator of an attacker-created backdoor account rather than a legitimate provisioning workflow — provisioned accounts typically have a delay before first use.

| Field | Value |
|-------|-------|
| Log source | Windows Security Log |
| Event IDs | 4720 (account created) → 4624 (successful logon) |
| Timeframe | Within 1 hour of creation |
| MITRE | T1136.001 — Create Account: Local Account, T1078.003 — Valid Accounts: Local |

**Known false positives:** Automated provisioning workflows that create and immediately test accounts, onboarding scripts that log in to verify account creation.

---

## Deployment

These rules are in Sigma format and require conversion to your target SIEM's query language using [sigma-cli](https://github.com/SigmaHQ/sigma-cli):

```bash
# Convert to Splunk SPL
sigma convert -t splunk brute_force_detection.yml

# Convert to Elastic EQL
sigma convert -t elasticsearch powershell_suspicious.yml

# Convert to Microsoft Sentinel KQL
sigma convert -t azure-monitor account_creation_immediate_use.yml
```

---

## Rule Status Definitions

| Status | Meaning |
|--------|---------|
| `experimental` | Initial version — not yet validated against production log data; false positive rate unknown |
| `test` | Validated in lab environment — false positive rate estimated, not yet tuned for production |
| `production` | Validated and tuned against production log data — ready for live alerting |

All three rules should be validated against your environment's baseline before enabling live alerting. The brute force and account creation rules in particular require threshold tuning based on observed normal activity.

---

## MITRE ATT&CK Coverage

| Technique | ID | Rule |
|-----------|----|------|
| Brute Force: Password Guessing | T1110.001 | brute_force_detection.yml |
| PowerShell | T1059.001 | powershell_suspicious.yml |
| Obfuscated Files or Information | T1027 | powershell_suspicious.yml |
| Create Account: Local Account | T1136.001 | account_creation_immediate_use.yml |
| Valid Accounts: Local Accounts | T1078.003 | account_creation_immediate_use.yml |
