# Incident Response Playbook: New Local User Account Created

![Splunk](https://img.shields.io/badge/Tool-Splunk-000000?style=flat&logo=splunk&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?style=flat&logo=windows&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-Incident_Response-E01B1B?style=flat&logoColor=white)

**Analyst:** Denis O. Onduso  
**Trigger:** Splunk alert — Event ID 4720 (A user account was created)  
**Tactic:** Persistence (TA0003) — T1136.001  
**SLA:** Determine legitimacy within 10 minutes; disable unauthorized account within 15 minutes of confirmation

---

## Scope

This playbook covers detection of new local user account creation on Windows hosts. Local account creation is a common post-exploitation persistence technique — an attacker with administrator access creates a backdoor account that survives domain credential resets and persists across reboots independently of the compromised initial access vector.

---

## Step 1 — Extract Full Event Context

Pull the complete 4720 event details:

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4720
| table _time, host, user, member_id, src_ip
| sort -_time
```

| Field | Meaning | What to Look For |
|-------|---------|-----------------|
| `user` | Account that created the new user | Should be a known admin — unexpected creator is the primary red flag |
| `member_id` | Name of the newly created account | Generic names (`admin2`, `svc_test`, `helpdesk`) are common attacker naming patterns |
| `host` | Host where the account was created | A DC is critical severity; a workstation is high |
| `_time` | When the account was created | Off-hours creation without a change ticket warrants immediate escalation |

---

## Step 2 — Check for Immediate Follow-On Events

Account creation alone is suspicious. Account creation followed by group membership changes is a confirmed persistence + privilege escalation sequence. Run this immediately:

```spl
index=windows sourcetype="WinEventLog:Security" EventCode IN (4720, 4732, 4728, 4624)
| where host="<affected_host>" AND earliest=-30m
| table _time, EventCode, user, member_id, Group_Name
| sort _time
```

| Event ID | Meaning | Severity if Found After 4720 |
|----------|---------|------------------------------|
| 4732 | Account added to local security group | **Critical** if group is Administrators |
| 4728 | Account added to global security group | **Critical** if group is Domain Admins |
| 4624 | Successful logon | **Critical** — new account already in use |

If **4624** is found for the newly created `member_id`, the attacker has already used the backdoor account. Treat as active compromise and escalate immediately.

---

## Step 3 — Determine Legitimacy

**Was this account creation part of a documented change?**

Check against:
- IT change management records for the host and timeframe
- Known provisioning service accounts (`user` field should be a named provisioning account)
- Scheduled onboarding activity

**Is the creator account (`user`) expected to create local accounts?**

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4720
| stats count by user, host
| sort -count
```

A provisioning account creating accounts daily across many hosts is expected. A standard user account or an interactive admin account creating a local account outside business hours is not.

**Is the host a domain controller?**

Local account creation on a DC is inherently anomalous — domain controllers use domain accounts, not local ones. Any 4720 event on a DC should be treated as high severity regardless of the creator identity.

---

## Step 4 — Investigate the Creator Account

If the creator (`user`) is unexpected, the creator account itself may be compromised. Investigate what else it did:

```spl
index=windows sourcetype="WinEventLog:Security" EventCode IN (4624, 4688, 4732, 4740)
| where user="<creator_account>" AND host="<affected_host>"
| table _time, EventCode, user, CommandLine, Group_Name
| sort _time
```

Look for:
- Process execution (4688) under the creator account — especially PowerShell, cmd, or net.exe
- Other group membership changes (4732) — how many accounts were modified
- Account lockout of the creator (4740) — may indicate the account itself was brute-forced to gain the access used to create the backdoor

---

## Step 5 — Containment

**Disable the unauthorized account immediately:**

```powershell
Disable-LocalUser -Name "<backdoor_account>"
```

Or via Active Directory if domain-joined:

```powershell
Disable-ADAccount -Identity "<backdoor_account>"
```

**Remove from any groups it was added to:**

```powershell
Remove-LocalGroupMember -Group "Administrators" -Member "<backdoor_account>"
```

**If the creator account is compromised:**
- Disable the creator account pending investigation
- Force password reset before re-enabling
- Review all actions taken by the creator account in the investigation window

**If 4624 was found for the new account (already used):**
- Isolate the host — treat as active compromise
- Preserve memory and logs before remediation
- Escalate to Tier 2 for full incident response
- Switch to the Unauthorized Login Playbook for the active session

---

## Step 6 — Document and Close

| Field | Required Content |
|-------|----------------|
| New account name | `member_id` from the 4720 event |
| Creator account | `user` — authorized or unauthorized |
| Host | Where the account was created — workstation / server / DC |
| Group membership changes | 4732/4728 events — which groups the account was added to |
| Account used (4624) | Yes / No — whether the backdoor account logged in |
| Legitimacy determination | Authorized change / Unauthorized / Unverified |
| Containment actions | Account disabled, removed from groups |
| Creator account status | Active / Disabled / Password reset |
| Escalated to Tier 2 | Yes / No |

---

## MITRE ATT&CK Relevance

| Technique | ID | Step |
|-----------|----|------|
| Create Account: Local Account | T1136.001 | Step 1 — primary detection trigger |
| Account Manipulation: Local Account | T1098 | Step 2 — 4732 group membership change follow-on |
| Valid Accounts: Local Accounts | T1078.003 | Step 2 — 4624 logon using the new account |
| Brute Force | T1110 | Step 4 — creator account lockout (4740) may indicate brute-forced admin |
| Persistence | TA0003 | Core tactic — local accounts survive domain credential resets |
