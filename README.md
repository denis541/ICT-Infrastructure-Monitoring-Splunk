# ICT Infrastructure Monitoring with Splunk   
     
![Splunk](https://img.shields.io/badge/Tool-Splunk_Enterprise-000000?style=flat&logo=splunk&logoColor=white)        
![Platform](https://img.shields.io/badge/Platform-Windows_11-0078D4?style=flat&logo=windows&logoColor=white)        
![MITRE](https://img.shields.io/badge/MITRE-T1110_Brute_Force-E01B1B?style=flat&logoColor=white)    
   
**Analyst:** Denis O. Onduso | [GitHub](https://github.com/denis541) | Denis.Onduso@outlook.com   
**License:** MIT  

---

## Overview

End-to-end brute force detection pipeline built in a controlled home lab: attack simulation on Windows 11 via Kali Linux, log forwarding into Splunk Enterprise, and iterative detection rule tuning from 22 daily alerts down to 3–4 high-fidelity alerts. The project covers the full detection engineering lifecycle — threat modelling, rule development, false positive analysis, and tuning — against a realistic attack pattern documented under MITRE ATT&CK T1110.

---

## Architecture

```mermaid
graph LR
    A[Kali Linux] -->|Brute Force - Hydra| B[Windows 11]
    B -->|Security Event Logs - Universal Forwarder| C[Splunk Enterprise]
    C -->|Alert| D[Analyst]
```

| Component | Details |
|-----------|---------|
| SIEM | Splunk Enterprise (Free Tier) |
| Target | Windows 11 — Security Event Log source |
| Attack simulation | Kali Linux — Hydra, custom PowerShell/Python scripts |
| Network | Isolated VMware virtual subnet — no external traffic |
| Hypervisor | VMware Workstation |

---

## Threat Model

**Targeted technique:** T1110.001 — Brute Force: Password Guessing  
**Targeted asset:** Windows local authentication (NTLM)  
**Attack path:** Credential compromise → valid account access (T1078) → lateral movement or persistence

**Detection approach:** Threshold-based analysis of Event ID 4625 (Failed Logon), filtered to network-based logon types, with a threat score assigned per source IP for analyst triage prioritisation.

---

## Detection Rule

**File:** `/detection_rules/splunk/windows_auth_bruteforce.spl`

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4625
  (Logon_Type=3 OR Logon_Type=10)
| stats count values(Logon_Type) as logon_types by src_ip, user
| where count > 7
| eval threat_score = count * 10
| sort -threat_score
| table src_ip, user, count, logon_types, threat_score
```

| Logic Component | Purpose |
|----------------|---------|
| `EventCode=4625` | Failed logon events only |
| `Logon_Type=3 OR Logon_Type=10` | Network and RDP logons — filters out local console failures which generate high legitimate noise |
| `count > 7` | Threshold tuned to suppress single-user lockout false positives while catching tool-generated spray patterns |
| `threat_score = count * 10` | Linear score for analyst queue prioritisation — higher count = higher score |

Note: The `Logon_Type` filter is applied before the `stats` aggregation so the field is available for filtering. Filtering after `stats` on an aggregated-away field produces incorrect results.

---

## Tuning Process

Starting condition: alert threshold of 5 failures, no logon type filter, no allowlist — generating 22 alerts per day with a 95% false positive rate.

| Iteration | Change | Outcome |
|-----------|--------|---------|
| Baseline | Threshold: 5 failures, no filters | 22 daily alerts — 95% false positives |
| Tuning 1 | Threshold raised to 7, Logon_Type filter added | Alert volume reduced — residual FPs from service accounts |
| Tuning 2 | Source IP allowlist added for known internal systems | High-fidelity alerts only |
| Final | Multi-factor correlation across IP, user, and logon type | 3–4 daily alerts — all requiring genuine investigation |

**Result:** 82% reduction in daily alert volume. False positive rate reduced from 95% to under 5% in the final configuration.

The 95% → near-zero false positive reduction is the more meaningful result than raw accuracy — in a SOC environment, alert fatigue from high-FP rules causes analysts to begin ignoring or auto-closing alerts without investigation, which is a more dangerous condition than having no rule at all.

---

## Evidence

| File | Purpose |
|------|---------|
| `01_splunk_dashboard.png` | Log ingestion overview and index health |
| `02_windows_log_ingestion.png` | Event ID 4625 parsing validation |
| `03_bruteforce_alert_fired.png` | Detection rule firing against simulated attack |
| `04_alert_tuning_fp_reduction.png` | Alert volume before and after tuning |

---

## Regulatory Alignment

Logging and monitoring configuration addresses the following requirements under the **Kenya Data Protection Act, 2019:**

| Section | Requirement | Implementation |
|---------|-------------|---------------|
| Section 30 | Records of processing activities | Splunk index retains full audit trail of authentication events |
| Section 32 | Security safeguards for personal data | Detection rules alert on unauthorised access attempts to systems holding personal data |
| Section 39 | Breach detection and notification | Alert pipeline provides documented detection timestamp for breach notification timelines |

---

## Skills Demonstrated

| Area | Detail |
|------|--------|
| SIEM administration | Splunk index management, Universal Forwarder configuration, data onboarding |
| Detection engineering | Threat modelling, SPL rule development, iterative tuning, false positive analysis |
| Log analysis | Windows Event Log parsing, field extraction, logon type classification |
| MITRE ATT&CK | T1110.001 detection, T1078 follow-on activity identification |
| Infrastructure | VMware network segmentation, Windows 11 and Kali Linux administration |
| Automation | PowerShell and Python log generation scripts for detection validation |

---

## Related Documentation

- [Detection Engineering Process](Detection_rules)
- [False Positive Tuning Analysis](Docs/04_lessons_false_positives.md)
- [Threat Model — T1110.001](Docs/01_threat_modeling_T1110.md)
- [Incident Response Playbook — Brute Force](Playbooks/01-Incident_response.md)
