# Detection Engineering: Building and Tuning a Brute-Force Detection Rule

![Splunk](https://img.shields.io/badge/Tool-Splunk-000000?style=flat&logo=splunk&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?style=flat&logo=windows&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-Detection_Engineering-4CAF50?style=flat&logoColor=white)

**Analyst:** Denis O. Onduso  
**Use Case:** Brute-force authentication detection — Windows Event ID 4625  
**Outcome:** Production rule with 98% detection rate, 12% false positive rate, <5 minute MTTD

---

## Overview

This document walks through the full detection engineering lifecycle for a brute-force authentication rule — from initial requirement through iterative refinement to production deployment. It demonstrates that detection engineering is not a single query but a structured process of baselining, testing, tuning, and documenting.

---

## Phase 1: Requirement

**Problem:** Detect brute-force attacks against Windows hosts using Security Event Logs.

**Data sources evaluated:**

| Source | Relevance |
|--------|-----------|
| Windows Security Log — Event ID 4625 | Primary — failed logon events, includes source IP, username, logon type |
| Firewall logs | Secondary — blocked authentication traffic at network layer |
| VPN logs | Secondary — remote access failures for off-premise scenarios |

Event ID 4625 was selected as the primary source — it is generated at the host level regardless of network filtering, includes logon type context, and is forwarded to Splunk via the Universal Forwarder already in the lab pipeline.

---

## Phase 2: Initial Detection

First version — intentionally simple to establish a baseline signal:

```spl
index=windows EventCode=4625
| stats count by src_ip, user
| where count > 5
```

**Result:** High false positive rate. The rule fired on normal user behaviour, service accounts with expired credentials, and console login failures — none of which represent a network-based attack.

---

## Phase 3: Baseline and Testing

**Baselining method:** Normal activity was logged for 24 hours without simulated attacks to establish what legitimate failure patterns look like.

**Attack simulation:** Hydra was run from the Kali Linux VM against the Windows target to generate controlled brute-force traffic.

**Findings from baseline analysis:**

| Observation | Implication |
|-------------|-------------|
| Normal users fail passwords 1–3 times occasionally | Threshold of 5 was too low — captures legitimate typos |
| Service accounts with expired credentials generate sustained 4625 noise | Need to filter by logon type — service accounts use specific logon types |
| Console logons (Logon Type 2) are not network-based attacks | Logon Type 2 should be excluded — not an attack surface for remote brute force |
| Network logons (Logon Type 3) and RDP (Logon Type 10) are the relevant attack surface | Filter to these logon types only |

---

## Phase 4: Refined Detection

Improved version incorporating baseline findings:

```spl
index=windows EventCode=4625 earliest=-15m
| where Logon_Type=3 OR Logon_Type=10
| stats count as failure_count dc(user) as unique_users by src_ip
| where failure_count > 7
| sort -failure_count
```

**Changes made and rationale:**

| Change | Reason |
|--------|--------|
| `Logon_Type=3 OR Logon_Type=10` | Restricts to network and RDP logons — the only logon types relevant to remote brute force |
| Threshold raised from 5 to 7 | Baseline showed legitimate failures peak at 3 — 7 provides margin while maintaining sensitivity |
| `earliest=-15m` | Scopes detection to recent activity — prevents stale events from inflating counts |
| Added `dc(user)` | Surfaces unique username count per IP — distinguishes spraying from targeted attacks |
| `sort -failure_count` | Orders output for analyst triage — highest-volume IPs reviewed first |

---

## Phase 5: Validation Results

The refined rule was tested against both baseline traffic and simulated attacks:

| Metric | Result |
|--------|--------|
| Detection rate | 98% — nearly all simulated attack sessions triggered the rule |
| False positive rate | 12% — acceptable for a SOC environment with analyst triage |
| Mean Time to Detect | <5 minutes — within the target window for credential-based attacks |

The remaining 2% of missed detections were slow-and-low attacks running below the 7-failure threshold within the 15-minute window — a known limitation of rate-based detection. A complementary rule with a longer time window (`earliest=-1h`, lower per-window threshold) would capture these.

---

## Phase 6: Deployment

**Splunk alert configuration:**
- Schedule: Real-time
- Trigger condition: Results count > 0 (the `where` clause handles thresholding)
- Alert action: Email notification + notable event creation

**Analyst runbook created:** Triage steps for when the alert fires — decode source IP, check threat intel, correlate with Event ID 4624 (successful logon) from the same IP, escalate if post-brute-force access confirmed.

**Change control:** Query logic, threshold rationale, and baseline methodology documented here for future tuning reference.

---

## MITRE ATT&CK Relevance

| Technique | ID | Detail |
|-----------|----|--------|
| Brute Force: Password Guessing | T1110.001 | Primary technique this rule detects |
| Brute Force: Password Spraying | T1110.003 | High `unique_users` per IP identifies spray pattern |
| Valid Accounts | T1078 | Monitor Event ID 4624 from same `src_ip` post-detection — confirms successful compromise |
