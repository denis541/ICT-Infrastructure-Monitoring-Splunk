# Incident Response Playbook: Brute-Force Authentication Attack

![Splunk](https://img.shields.io/badge/Tool-Splunk-000000?style=flat&logo=splunk&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-Incident_Response-E01B1B?style=flat&logoColor=white)
![Type](https://img.shields.io/badge/Type-SOC_Playbook-0078D4?style=flat&logoColor=white)

**Analyst:** Denis O. Onduso  
**Trigger:** Splunk alert — `failure_count > 7` from single `src_ip` within 15 minutes (Event ID 4625 / linux_secure)  
**Tactic:** Credential Access (TA0006) — T1110  
**SLA:** Classify attack pattern within 5 minutes; contain within 30 minutes if active compromise confirmed

---

## Scope

This playbook specifically covers **brute-force authentication attacks** — high-volume, automated credential guessing from a single or small set of source IPs. It is distinct from the Unauthorized Login playbook in that the first priority here is classifying the *type* of brute-force attack, because the response differs depending on whether the attacker is spraying, stuffing, or targeting a specific account.

---

## Step 1 — Classify the Attack Pattern

This is the step that makes this playbook different from a generic login alert response. Pull the alert fields and classify before taking any action:

```spl
index=windows EventCode=4625 earliest=-15m
| where src_ip="<attacker_ip>"
| stats count as failure_count dc(user) as unique_users values(user) as targeted_accounts by src_ip
| table src_ip, failure_count, unique_users, targeted_accounts
```

| Pattern | `failure_count` | `unique_users` | Classification | Priority |
|---------|----------------|----------------|----------------|----------|
| Many failures, many users | High | High (>10) | **Password Spray** — one password across many accounts | High |
| Many failures, few users | High | Low (1–3) | **Dictionary / Credential Stuffing** — wordlist or breach creds against specific accounts | High |
| Moderate failures, one user | Medium | 1 | **Targeted Attack** — specific account being pursued | High |
| Low failures, known-malicious IP | Low | Any | **Reconnaissance / Slow Attack** — intentionally staying under threshold | Critical |

**Why classification matters:** A password spray means *all accounts* are at risk and the priority is checking every account for a successful logon. A targeted attack against one account means the investigation is narrower but the account may be high-value. These require different response scopes.

---

## Step 2 — Identify the Attack Velocity and Tool Signature

Brute-force tools have characteristic timing patterns. Check the inter-event timing:

```spl
index=windows EventCode=4625 earliest=-15m
| where src_ip="<attacker_ip>"
| sort _time
| streamstats current=f last(_time) as prev_time
| eval gap_seconds=round(_time - prev_time, 2)
| table _time, user, gap_seconds
```

| Gap Pattern | Likely Tool |
|-------------|-------------|
| Consistent 0.1–0.5s gaps | Hydra, Medusa — automated, high-speed |
| Consistent 2–5s gaps | Ncrack or throttled tooling |
| Irregular gaps, human-speed | Manual attempt or slow-and-low evasion |
| Random gaps from multiple IPs | Distributed botnet — requires different containment |

---

## Step 3 — Check for Successful Logins

For **spray attacks**, check across all targeted accounts:

```spl
index=windows EventCode=4624 earliest=-1h
| where src_ip="<attacker_ip>"
| table _time, user, src_ip, Logon_Type, dest
```

For **targeted attacks**, check specifically for the account under fire:

```spl
index=windows EventCode=4624 earliest=-1h
| where user="<targeted_account>"
| table _time, user, src_ip, Logon_Type, dest
```

| Result | Action |
|--------|--------|
| No 4624 from attacker IP | Attempted breach, no confirmed access — proceed to Step 4 |
| 4624 found from attacker IP | **Active compromise** — switch to Unauthorized Login Playbook Step 6 immediately |
| 4624 from different IP for same user | Possible credential theft and use from separate infrastructure — treat as compromise |

---

## Step 4 — Platform-Specific Verification

**Windows:**
```powershell
# Check active sessions on target host
query user /server:<hostname>

# Check account lockout status
Get-ADUser <username> -Properties LockedOut, BadLogonCount, LastBadPasswordAttempt
```

**Linux:**
```bash
# Check current sessions
who && last <username>

# Check auth log for the attack window
grep "Failed password" /var/log/secure | grep "<attacker_ip>"
```

---

## Step 5 — Containment Actions

**If spray attack (high unique_users):**
- Block `src_ip` at perimeter
- Pull the full list of targeted accounts from the alert and check each for a successful 4624 within the attack window
- Notify all targeted users — do not single out individuals, treat as a group notification
- Check whether any targeted account has MFA disabled — those are the highest compromise risk

**If targeted attack (low unique_users):**
- Block `src_ip` at perimeter
- Notify the specific targeted user
- If `failure_count` is very high against one account, check whether the attacker has valid username intelligence — the account may be privileged or have been exposed in a prior breach

**If internal source IP:**
- Do not just block — internal brute force indicates a compromised internal host being used to move laterally
- Isolate the source host, not just block the IP
- Expand investigation to the source host using the Unauthorized Login Playbook

---

## Step 6 — Document and Close

Minimum documentation required before closing the ticket:

| Field | Required Content |
|-------|----------------|
| Attack classification | Spray / stuffing / targeted / slow-and-low |
| Source IP | IP, enrichment results, geo, threat intel match |
| Accounts targeted | Full list from `values(user)` |
| Successful logins | Yes / No — Event ID 4624 check result |
| Containment action | What was blocked, where, by whom |
| User notification | Confirmed sent |
| Recommendation | MFA enforcement, allowlist review, threshold adjustment if needed |

---

## MITRE ATT&CK Relevance

| Technique | ID | Step |
|-----------|----|------|
| Brute Force: Password Spraying | T1110.003 | Step 1 — high `unique_users` classification |
| Brute Force: Credential Stuffing | T1110.004 | Step 1 — low `unique_users`, high `failure_count` classification |
| Brute Force: Password Guessing | T1110.001 | Step 1 — targeted single-account attack |
| Valid Accounts | T1078 | Step 3 — post-brute-force access confirmation |
| Lateral Movement | T1021 | Step 5 — internal source IP response path |
