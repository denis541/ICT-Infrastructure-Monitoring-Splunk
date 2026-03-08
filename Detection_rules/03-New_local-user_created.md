# Detection Rule: New Local User Account Created (Event ID 4720)

![Splunk](https://img.shields.io/badge/Tool-Splunk-000000?style=flat&logo=splunk&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?style=flat&logo=windows&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-Detection_Engineering-4CAF50?style=flat&logoColor=white)

**Analyst:** Denis O. Onduso  
**Tactic:** Persistence (TA0003)  
**Technique:** Create Account: Local Account (T1136.001)  
**Data Source:** Windows Security Event Log — Event ID 4720 (A user account was created)  
**Query Language:** SPL (Splunk Processing Language)

---

## Objective

Detect the creation of new local user accounts on Windows hosts — a common post-exploitation persistence technique where attackers create backdoor accounts to maintain access after the initial compromise vector is remediated.

---

## Detection Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4720
| table _time, member_id, dest, user
```

---

## Query Logic

| Stage | SPL | Purpose |
|-------|-----|---------|
| Filter | `EventCode=4720` | Isolates user account creation events from the Windows Security log |
| Output | `table _time, member_id, dest, user` | Returns timestamp, created account name, destination host, and the account that performed the creation |

**Field reference:**
- `_time` — when the account was created
- `member_id` — the newly created account name
- `dest` — the host where the account was created
- `user` — the account that performed the creation action (who created it)

The `user` field is the most important for triage — a new local account created by `SYSTEM` or an unexpected privileged account warrants immediate investigation. A new account created by a named admin during a documented change window is expected behavior.

---

## Why This Matters

Local account creation is a high-signal event in most enterprise environments. Legitimate reasons are narrow: a sysadmin provisioning a service account, or a deployment script running during onboarding. In most cases, new local accounts should be created via Active Directory, not directly on individual hosts.

An attacker who has gained administrator access will frequently create a new local account as a persistence mechanism — it survives reboots, is independent of domain credentials, and is less likely to be noticed than a modification to an existing privileged account.

---

## Extended Query — Correlated with Privilege Escalation

Account creation alone is a detection signal. Account creation *followed by* group membership changes raises the severity significantly:

```spl
index=windows sourcetype="WinEventLog:Security" EventCode IN (4720, 4732)
| stats values(EventCode) as events values(_time) as times by user, dest
| where mvcount(events) > 1
| eval sequence=if(array_contains(events, "4720") AND array_contains(events, "4732"),
    "Account Created then Added to Group", "Single Event")
| where sequence="Account Created then Added to Group"
```

**Event ID 4732** — A member was added to a security-enabled local group (commonly the Administrators group). A 4720 followed by a 4732 on the same host is a high-confidence persistence + privilege escalation sequence.

---

## Triage Questions

When this alert fires, answer these before closing:

1. Was this account creation part of a documented change request?
2. Is `user` (the creator) a known admin account, or an unexpected principal?
3. Was Event ID 4732 (group membership change) logged on the same host shortly after?
4. Was Event ID 4624 (successful logon) logged for the new `member_id` account — indicating it has already been used?
5. Is `dest` a server, workstation, or domain controller? A new local account on a DC is critical severity.

---

## Tuning Recommendations

In environments with automated provisioning or deployment pipelines, exclude known service accounts and provisioning hosts to reduce false positives:

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4720
NOT user IN ("provisioningaccount", "deploymentservice")
NOT dest IN ("known-imaging-host")
| table _time, member_id, dest, user
```

---

## MITRE ATT&CK Relevance

| Technique | ID | Detail |
|-----------|----|--------|
| Create Account: Local Account | T1136.001 | Direct technique — Event ID 4720 is the primary detection data source |
| Valid Accounts: Local Accounts | T1078.003 | Created account used for subsequent access — monitor for 4624 logon events for the new account |
| Account Manipulation | T1098 | Follow-on 4732 event adding the new account to Administrators group |
| Persistence | TA0003 | Local accounts survive domain credential resets and persist across reboots |
