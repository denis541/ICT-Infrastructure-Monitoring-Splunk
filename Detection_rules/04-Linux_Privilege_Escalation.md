# Detection Rule: Sudo Privilege Escalation to Root (Linux)

![Splunk](https://img.shields.io/badge/Tool-Splunk-000000?style=flat&logo=splunk&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=flat&logo=linux&logoColor=black)
![Domain](https://img.shields.io/badge/Domain-Detection_Engineering-4CAF50?style=flat&logoColor=white)

**Analyst:** Denis O. Onduso  
**Tactic:** Privilege Escalation (TA0004)  
**Technique:** Abuse Elevation Control Mechanism: Sudo (T1548.003)  
**Data Source:** Linux `/var/log/secure` — PAM session logs  
**Query Language:** SPL (Splunk Processing Language)

---

## Objective

Detect successful sudo escalations to root on Linux hosts by monitoring PAM session open events — identifying users gaining root-level access, the frequency of escalation per user, and the hosts where it occurred.

---

## Detection Query

```spl
index=linux sourcetype=linux_secure "session opened for user root by"
| stats count by user, host
| sort -count
```

---

## Query Logic

| Stage | SPL | Purpose |
|-------|-----|---------|
| Filter | `"session opened for user root by"` | Matches the specific PAM log string generated when a user successfully opens a root session via sudo |
| Aggregate | `stats count by user, host` | Groups escalation events by the initiating user and the host — surfaces who is escalating and where |
| Sort | `sort -count` | Orders by highest escalation count — prioritises the most active users for review |

**Log string context:** The string `session opened for user root by` appears in `/var/log/secure` when PAM successfully opens a privileged session. This fires on successful escalations only — failed sudo attempts produce a different log entry (`sudo: user NOT in sudoers` or `sudo: authentication failure`) and require a separate detection rule.

---

## Triage Interpretation

| Pattern | Likely Explanation | Action |
|---------|-------------------|--------|
| Known admin, low count, business hours | Expected administrative activity | Review, no immediate action |
| Known admin, high count, off-hours | Unusual volume — investigate what commands were run | Review sudo logs for command history |
| Unknown or non-admin user | Unauthorized escalation or compromised account | High priority — immediate investigation |
| Service account escalating to root | Misconfigured sudoers or compromised service | Investigate sudoers file and service integrity |
| Single user, multiple hosts | Lateral movement with root escalation | Critical — contains and investigate |

---

## Extended Query — Command-Level Visibility

The base query identifies *who* escalated and *how often*. To see *what commands* were run under root:

```spl
index=linux sourcetype=linux_secure sudo
| rex field=_raw "COMMAND=(?<sudo_command>.+)"
| stats count by user, host, sudo_command
| sort -count
```

This surfaces the specific commands executed via sudo — a user running `sudo bash` or `sudo su` is attempting to drop into a persistent root shell, which is a higher-severity indicator than `sudo systemctl restart nginx`.

---

## Tuning Recommendations

In environments with known admin accounts performing routine maintenance, filter out expected users to reduce noise:

```spl
index=linux sourcetype=linux_secure "session opened for user root by"
NOT user IN ("known-admin1", "deploy-service")
| stats count by user, host
| sort -count
```

For alerting, consider triggering on any escalation from a non-whitelisted user rather than a count threshold — legitimate root escalations should be predictable and attributable.

---

## MITRE ATT&CK Relevance

| Technique | ID | Detail |
|-----------|----|--------|
| Abuse Elevation Control: Sudo | T1548.003 | Direct technique — PAM session open for root is the primary detection signal |
| Valid Accounts: Local Accounts | T1078.003 | Compromised local account used to sudo to root |
| Lateral Movement | T1021 | Same user escalating to root across multiple hosts indicates lateral movement with privilege escalation |
| Persistence via Sudoers | T1548.003 | Attackers modify `/etc/sudoers` to add persistence — monitor for 4720-equivalent file modification events alongside this rule |
