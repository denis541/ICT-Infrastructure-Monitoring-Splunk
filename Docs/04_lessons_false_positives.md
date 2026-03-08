# Detection Tuning: False Positive Reduction Analysis

![Splunk](https://img.shields.io/badge/Tool-Splunk-000000?style=flat&logo=splunk&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?style=flat&logo=windows&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-Detection_Engineering-4CAF50?style=flat&logoColor=white)

**Analyst:** Denis O. Onduso  
**Use Case:** Brute-force authentication detection — Event ID 4625  
**Outcome:** False positive rate reduced from 85% to 12% through four targeted tuning iterations

---

## Problem Statement

The initial detection rule produced an 85% false positive rate — 85 out of every 100 alerts were non-actionable. At 47 alerts per day averaging 18 minutes of analyst investigation time each, the rule was consuming approximately 14 hours of analyst time daily on noise. That is not a detection problem, it is an operational cost problem.

---

## Root Cause Analysis

| False Positive Source | Volume | Mechanism |
|----------------------|--------|-----------|
| Normal user typos and caps lock errors | High | 1–3 failures per user per day — below attack volume but above threshold |
| Service accounts with expired credentials | High | Continuous 4625 events until credential rotation — sustained noise |
| IT and developer testing activity | Medium | Intentional failures during testing — not malicious |
| Misconfigured applications | Medium | Applications authenticating with wrong credentials against AD |

None of these sources represent an attack. All of them were indistinguishable from brute force under the original rule because the rule lacked context.

---

## Tuning Iterations

### Iteration 1: Logon Type Filter

**Change:** Restricted detection to network logons (`Logon_Type=3`) and RDP (`Logon_Type=10`)

**Rationale:** Remote brute force attacks arrive over the network — they produce Logon Type 3 (SMB/WinRM) or Logon Type 10 (RDP) failures. Console logons (Type 2), service logons (Type 5), and batch logons (Type 4) are not accessible to a remote attacker and were generating the majority of false positives from service accounts and local user errors.

**Result:** False positive rate dropped from 85% to 51% — a 40% reduction

---

### Iteration 2: Threshold Increase

**Change:** Raised failure threshold from 5 to 7

**Rationale:** Baseline analysis over 24 hours showed legitimate users failing authentication at a maximum of 3 times before either succeeding or calling the helpdesk. A threshold of 5 captured the tail of normal user behaviour. Raising to 7 maintained sensitivity to actual attack velocity (5–20 attempts per minute) while excluding the noise floor.

**Result:** False positive rate dropped from 51% to 26% — a 25% reduction

---

### Iteration 3: Time Window

**Change:** Added `earliest=-15m` to scope the count to a rolling 15-minute window

**Rationale:** Without a time window, a service account accumulating 7 failures over 3 days would trigger the rule. The `where count > 7` filter was designed to detect high-velocity attacks — adding the time window enforces that intent. 7 failures within 15 minutes is consistent with automated tooling. 7 failures over days is credential misconfiguration.

**Result:** False positive rate dropped from 26% to 14% — a 30% reduction

---

### Iteration 4: Allowlist Exclusions

**Change:** Excluded known benign sources from detection scope

**Sources excluded:**
- Admin subnets performing legitimate remote administration
- Service account IPs during documented maintenance windows
- Backup system IPs authenticating against multiple hosts on schedule

**Rationale:** After the first three iterations, remaining false positives were attributable to known, documented sources with legitimate reasons to produce authentication failures at volume. Allowlisting these sources removes known-clean noise without affecting detection coverage against unknown sources.

**Result:** False positive rate dropped from 14% to 12% — a 15% reduction

---

## Results Summary

| Metric | Before Tuning | After Tuning | Change |
|--------|--------------|--------------|--------|
| False positive rate | 85% | 12% | −73 percentage points |
| Alerts per day | 47 | 6 | 87% reduction |
| Investigation time per alert | 18 min | 5 min | 72% reduction |
| Analyst time on noise per day | ~14 hours | ~30 minutes | Operationally viable |

---

## Key Lessons

**Baseline before writing rules.** The threshold and logon type decisions were only possible because 24 hours of normal activity had been logged first. Writing detections against an unknown baseline is guesswork.

**False positives are data.** Each false positive source revealed something about the environment — service accounts with expired credentials, misconfigured applications, admin subnet behaviour. That information has value beyond the detection itself.

**Context reduces noise more than threshold adjustment.** The single most impactful change was the logon type filter (40% reduction), not the threshold increase (25%). Adding context to a detection is almost always more effective than simply raising the bar.

**Document every decision.** The rationale for each tuning change is recorded here. Without this, the next analyst inheriting this rule has no way to evaluate whether the threshold is still appropriate or why certain sources are allowlisted.

---

## What Would Be Done Differently

- Collect **7 days of baseline logs** before writing the initial rule — 24 hours captures daily patterns but misses weekly cycles (e.g. weekend service account behaviour)
- Involve SOC analysts earlier for environment-specific knowledge — they know which service accounts are noisy before the data shows it
- Build a **feedback loop**: analysts marking false positives in the ticketing system feeds back into allowlist review
- Set **review dates on all allowlist entries** — sources added to an allowlist should be revalidated periodically, not left permanently excluded

---

## MITRE ATT&CK Relevance

| Technique | ID | Tuning Implication |
|-----------|----|--------------------|
| Brute Force: Password Guessing | T1110.001 | Logon Type filter ensures only network-reachable attack surface is monitored |
| Brute Force: Password Spraying | T1110.003 | Time window ensures spray velocity is captured, not just cumulative count |
| Valid Accounts | T1078 | Reduced false positive rate means analysts spend time on real post-brute-force access events |
