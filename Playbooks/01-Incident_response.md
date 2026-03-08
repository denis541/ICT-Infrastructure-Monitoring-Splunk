# Incident Response Playbook: Unauthorized Login Attempt

![Splunk](https://img.shields.io/badge/Tool-Splunk-000000?style=flat&logo=splunk&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-Incident_Response-E01B1B?style=flat&logoColor=white)
![Type](https://img.shields.io/badge/Type-SOC_Playbook-0078D4?style=flat&logoColor=white)

**Analyst:** Denis O. Onduso  
**Trigger:** Splunk alert — `failure_count > 7` from single `src_ip` within 15 minutes (Event ID 4625)  
**Severity:** High if login succeeded post-brute-force; Medium if failures only  
**SLA:** Investigate within 10 minutes of alert, contain within 30 minutes if active compromise confirmed

---

## Scope

This playbook covers unauthorized or suspicious login attempts detected via brute-force authentication alerts. It applies to both failed-only scenarios (attempted breach, no confirmed access) and post-brute-force successful login scenarios (confirmed compromise).

---

## Step 1 — Triage the Alert

Open the Splunk alert and extract the following fields:

| Field | Where to Find It | Purpose |
|-------|-----------------|---------|
| `src_ip` | Alert results | Origin of the authentication attempts |
| `failure_count` | Alert results | Volume of failures — indicates attack velocity |
| `unique_users` | Alert results | Number of distinct usernames attempted |
| `_time` (first/last) | Alert results | Attack window — duration of activity |
| `dest` | Alert results | Target host |

**Classify the attack pattern:**

| Pattern | Classification |
|---------|---------------|
| High `failure_count`, low `unique_users` | Dictionary attack or credential stuffing against specific account |
| High `failure_count`, high `unique_users` | Password spraying across accounts |
| Low `failure_count` from known-malicious IP | Targeted — escalate regardless of count |

---

## Step 2 — Enrich the Source IP

Run the following enrichment steps against `src_ip`:

```spl
| makeresults
| eval src_ip="<paste_ip>"
| lookup threat_ips ip AS src_ip OUTPUT threat_category, confidence
```

Then check externally:
- **AbuseIPDB** — abuse reports and scan history
- **VirusTotal** — passive DNS, malware associations
- **Shodan** — open ports, exposed services, geolocation

**Classify the source:**

| Source Type | Assessment |
|-------------|------------|
| Known threat intel match | High confidence malicious — proceed to containment |
| Tor exit node / VPN / hosting provider | Likely malicious — proceed to containment |
| Internal IP | Lateral movement — critical severity, expand investigation scope |
| Unknown external | Investigate further before containment |

---

## Step 3 — Determine if Login Succeeded

Check whether any authentication attempt from `src_ip` succeeded:

```spl
index=windows EventCode=4624 earliest=-1h
| where src_ip="<attacker_ip>"
| table _time, user, src_ip, Logon_Type, dest
```

| Result | Severity | Action |
|--------|----------|--------|
| No 4624 events from `src_ip` | Medium | Attempted breach, no confirmed access — proceed to Step 4 |
| 4624 event found | **Critical** | Active compromise confirmed — jump to Step 6 immediately |

---

## Step 4 — Check Current Session Status

Determine whether the targeted user account has an active session:

**Windows:**
```powershell
query user /server:<hostname>
```
Or review RDP session logs via Event ID 4778 (session reconnected) and 4779 (session disconnected).

**Linux:**
```bash
who
last <username>
```

If the user is logged in from an unexpected location or at an unexpected time, treat as **active compromise** and jump to Step 6.

---

## Step 5 — Failed Attempts Only (No Confirmed Access)

If no successful logon was detected:

1. **Block `src_ip`** at the perimeter firewall, VPN gateway, and any cloud security controls (NSG, WAF)
2. **Notify the targeted user** — inform them their account was targeted; verify they have not noticed any suspicious activity
3. **Check for account lockout** — Event ID 4740. If locked, confirm with the user before unlocking
4. **Document in the incident ticket** — source IP, timestamps, failure count, enrichment results, action taken

---

## Step 6 — Confirmed Compromise (Successful Login Detected)

Escalate severity to Critical. Execute in order:

1. **Isolate the affected host** from the network — disconnect from domain if possible without destroying volatile evidence
2. **Disable the compromised account** immediately in Active Directory
3. **Block `src_ip`** at all network control points — firewall, VPN, cloud controls
4. **Preserve evidence** — export relevant Splunk logs, take a memory snapshot if EDR is available
5. **Notify the affected user** and their manager — do not allow them to log back in until investigation is complete
6. **Expand investigation scope:**

```spl
index=windows EventCode IN (4624, 4688, 4720, 4732) earliest=-2h
| where user="<compromised_account>"
| table _time, EventCode, user, dest, CommandLine
| sort _time
```

Look for: new accounts created (4720), group membership changes (4732), process execution (4688) — these indicate post-compromise activity.

7. **Escalate to Tier 2 / IR team** if lateral movement or persistence indicators are found

---

## Completion Criteria

| Criteria | Required |
|----------|---------|
| Source IP blocked at perimeter | Yes |
| Affected user notified | Yes |
| Account status verified or reset | Yes |
| Incident ticket documented with all findings | Yes |
| Post-brute-force access investigated (if 4624 found) | Yes if applicable |
| Escalated to Tier 2 if persistence/lateral movement found | Yes if applicable |

---

## MITRE ATT&CK Relevance

| Technique | ID | Playbook Step |
|-----------|----|--------------|
| Brute Force | T1110 | Step 1 — alert triage and pattern classification |
| Valid Accounts | T1078 | Step 3 — confirming whether brute force succeeded |
| Lateral Movement | T1021 | Step 4 — internal source IP indicates lateral movement scenario |
| Create Account | T1136.001 | Step 6 — post-compromise persistence check via Event ID 4720 |
| Account Manipulation | T1098 | Step 6 — group membership changes via Event ID 4732 |
