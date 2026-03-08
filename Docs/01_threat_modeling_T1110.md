# Threat Modeling: Brute-Force Authentication Attacks

**Analyst:** Denis O. Onduso  
**Technique:** T1110.001 — Brute Force: Password Guessing  
**Tactic:** Credential Access (TA0006)  
**Frameworks:** MITRE ATT&CK, NIST SP 800-53, CIS Controls v8

---

## Objective

Model the threat of brute-force authentication attacks against Windows and Linux endpoints — profiling the adversary, analysing the attack path, assessing risk, and defining the detection strategy and countermeasures implemented in this lab.

---

## Threat Actor Profile

| Attribute | Detail |
|-----------|--------|
| Type | Opportunistic — automated tooling against exposed authentication interfaces |
| Sophistication | Basic to intermediate — widely available tools, low technical barrier |
| Resources | Low to moderate — password lists, open-source attack frameworks |
| Primary objective | Initial access via credential compromise |
| Common tools | Hydra, Ncrack, Medusa, custom PowerShell scripts |

---

## Attack Path

```
Reconnaissance → Target Identification → Brute-Force Attempt → Successful Access → Lateral Movement
```

**Characteristics of the attack in this lab:**

| Parameter | Value |
|-----------|-------|
| Target interfaces | RDP (3389), SSH (22), WinRM (5985) |
| Attack velocity | 5–20 attempts per minute per source IP |
| Duration | Minutes to days depending on lockout policy |
| Variants | Password spraying, dictionary attack, credential stuffing |

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Password Guessing | T1110.001 | Primary technique — automated attempts against a single account or set of accounts |
| Password Spraying | T1110.003 | One common password tried across many accounts — evades per-account lockout |
| Credential Stuffing | T1110.004 | Breach-sourced credential pairs tested against live services |
| Valid Accounts | T1078 | End goal — successful authentication with a compromised credential |
| Remote Services | T1021 | Attack surface — RDP, SSH, WinRM are the primary targets |

---

## Risk Assessment

### Impact

| Factor | Level | Justification |
|--------|-------|---------------|
| Confidentiality | High | Successful compromise exposes all data accessible to the account |
| Integrity | Medium | Account takeover enables data modification and malicious action |
| Availability | Low | Account lockout policies limit service disruption as a side effect |
| Business impact | High | Data breach, regulatory exposure, reputational damage |

### Likelihood

| Factor | Score | Rationale |
|--------|-------|-----------|
| Attack frequency | 9/10 | Most common initial access vector in enterprise environments |
| Ease of execution | 8/10 | Tools widely available, minimal technical knowledge required |
| Detection difficulty | 4/10 | Basic detection is achievable; evasion via slow or distributed attacks raises difficulty |
| Overall likelihood | High | Frequent occurrence expected in any internet-exposed environment |

---

## Detection Strategy

### Primary Detection Points

| Signal | Source | Event |
|--------|--------|-------|
| Failed authentication volume | Windows Security Log | Event ID 4625 — An account failed to log on |
| Account lockout | Windows Security Log | Event ID 4740 — A user account was locked out |
| Linux auth failures | `/var/log/secure` | PAM authentication failure entries |
| Network-layer patterns | Firewall / NSM | High-frequency auth protocol traffic from single source |

### Detection Challenges

**False positives:** Service accounts with cached stale credentials, legitimate users mistyping passwords, and monitoring tools that authenticate frequently can all produce 4625 noise. Threshold tuning per environment is required.

**Evasion techniques:** Slow-and-low attacks (1–2 attempts per minute) stay under rate-based thresholds. Distributed attacks from botnets spread failures across hundreds of source IPs, defeating per-IP aggregation. Detection of these patterns requires longer time windows and cross-source correlation rather than simple count thresholds.

**Logging gaps:** Misconfigured audit policies, missing Sysmon deployment, or agents not forwarding to SIEM create blind spots. Detection coverage depends entirely on log source completeness.

---

## Countermeasures

### Preventive Controls

| Control | Configuration |
|---------|--------------|
| Account lockout | 5 failed attempts triggers 30-minute lockout |
| Password policy | Minimum length, complexity, and history requirements enforced |
| MFA | Simulated in lab — in production, eliminates credential-only attack viability |

### Detective Controls

| Control | Implementation |
|---------|---------------|
| Real-time alerting | Threshold-based alert on `failure_count > 10` per source IP per 15-minute window |
| Geographic anomaly correlation | Alert on successful login from geography inconsistent with user baseline |
| Threat intelligence integration | Source IP enrichment against known scanner and botnet feeds |

### Response Playbook

```
1. Alert triggers (threshold breach)
2. Investigate — decode source IP, correlate with threat intel, check for subsequent 4624 (successful logon)
3. Contain — block source IP at firewall, disable affected account if compromise confirmed
4. Eradicate — rotate credentials, review for persistence mechanisms (new accounts, scheduled tasks)
5. Recover — re-enable account with new credentials, verify MFA enrollment
6. Document — record IOCs, update detection thresholds based on findings
```

---

## Success Criteria

| Metric | Target |
|--------|--------|
| Detection rate | >95% of brute-force attempts detected |
| False positive rate | <15% after threshold tuning |
| Mean Time to Detect (MTTD) | <10 minutes |
| Mean Time to Respond (MTTR) | <30 minutes |

### Validation Methods

- Controlled attack simulations against the lab environment using Hydra
- Manual testing of SPL detection logic against known-malicious log samples
- Historical log analysis to verify rule fires on past events
- Peer review of detection thresholds and query logic

---

## References

| Standard | Controls |
|----------|---------|
| MITRE ATT&CK | T1110.001, T1110.003, T1110.004, T1078, T1021 |
| NIST SP 800-53 | IA-5 (Authenticator Management), AC-7 (Unsuccessful Logon Attempts) |
| CIS Controls v8 | 5.1 (Establish Secure Config), 5.2 (Use Unique Passwords), 5.3 (Disable Dormant Accounts) |
