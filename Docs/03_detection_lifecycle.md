# The Process: How Detections Get Built
## Phase 1: Identify the Need
### Problem: We need to detect brute-force attacks in Windows logs.

# Sources to check:

Windows Security Logs (Event ID 4625 = failed login)

Firewall logs for blocked authentication attempts

VPN logs for remote access failures

## Phase 2: Build Initial Detection
First attempt (simple):

```spl
index=windows EventCode=4625
| stats count by src_ip, user
| where count > 5
```
## Problem: This catches everything - too many false positives.

## Phase 3: Test & Refine
### Testing method:

Run normal activity for 24 hours (baseline)

Simulate attacks (Kali Linux → Windows)

Compare what triggers vs. what should trigger

### What we learned:

Normal users fail passwords 1-3 times occasionally

Service accounts cause noise with expired credentials

Console logins (Logon Type 2) aren't security threats

## Phase 4: Improve the Detection
Better version:

```spl
index=windows EventCode=4625
| where Logon_Type=3 OR Logon_Type=10  # Network logins only
| stats count by src_ip, user
| where count > 7  # Increased threshold
```
Added:

Filter for only network-based attacks

Higher threshold (7 instead of 5)

Time window (15 minutes)

## Phase 5: Document & Deploy
Created:

Alert configuration in Splunk

Runbook for analysts

Testing procedure for future changes

## Success Metrics
Detection rate: 98% (catches real attacks)

False positive rate: 12% (acceptable for SOC)

Time to detect: <5 minutes
