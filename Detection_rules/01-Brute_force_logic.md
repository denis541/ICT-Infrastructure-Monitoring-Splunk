# Detection Rule: Linux Brute Force Authentication Monitor

![Splunk](https://img.shields.io/badge/Tool-Splunk-000000?style=flat&logo=splunk&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=flat&logo=linux&logoColor=black)
![Domain](https://img.shields.io/badge/Domain-Detection_Engineering-4CAF50?style=flat&logoColor=white)

**Analyst:** Denis O. Onduso  
**Tactic:** Credential Access (TA0006)  
**Technique:** Brute Force — Password Spraying / Credential Stuffing (T1110)  
**Data Source:** Linux `/var/log/secure` — authentication logs  
**Query Language:** SPL (Splunk Processing Language)

---

## Objective

Detect brute force attacks against Linux hosts by aggregating failed authentication events from `linux_secure` logs — surfacing the most active source IPs, the volume of failed attempts, and the number of unique usernames targeted per IP.

---

## Detection Query

```spl
index=realtime sourcetype=linux_secure Failed
| rex field=_raw "from (?<source_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as Failed_Attempts dc(user) as Unique_Users by source_ip
| sort -Failed_Attempts
| head 20
```

---

## Query Logic

| Stage | SPL | Purpose |
|-------|-----|---------|
| Filter | `sourcetype=linux_secure Failed` | Isolates failed authentication events from the secure log source |
| Extract | `rex field=_raw "from (?<source_ip>...)"` | Parses the source IP from the raw log line using regex — field is not natively extracted by the sourcetype |
| Aggregate | `stats count ... dc(user) ... by source_ip` | Groups by attacker IP; counts total failures and distinct usernames attempted |
| Sort | `sort -Failed_Attempts` | Orders results by highest failure count descending |
| Scope | `head 20` | Returns top 20 most active source IPs for analyst review |

---

## Key Metrics

**`Failed_Attempts`** — Total failed login count from a single IP. A high count from one IP over a short window is a strong brute force indicator. Threshold for alerting should be tuned to the environment's baseline — a shared server will have higher noise than a single-user host.

**`Unique_Users`** — Number of distinct usernames attempted from the same IP. A high `Unique_Users` count relative to `Failed_Attempts` suggests **password spraying** — one password tried across many accounts. A low `Unique_Users` count with high `Failed_Attempts` suggests **credential stuffing or dictionary attack** against a specific account.

**`source_ip`** — Origin of the authentication attempts. Should be enriched with GEO-IP and threat intelligence lookups as a secondary investigation step to determine whether the source is a known scanner, Tor exit node, or cloud VPS commonly used for attack infrastructure.

---

## Tuning Recommendations

This query returns the top 20 IPs by raw failure count. In a production deployment, consider adding:

```spl
| where Failed_Attempts > 10
```

to filter out single-event noise, and a time window (`earliest=-1h`) to scope detection to recent activity rather than the full index.

For alerting, a threshold of 10+ failures from a single IP within a 5-minute window is a common starting point — adjust based on observed baseline in your environment.

---

## MITRE ATT&CK Relevance

| Technique | ID | Detail |
|-----------|----|--------|
| Brute Force: Password Spraying | T1110.003 | High `Unique_Users`, low per-user failure count — one password across many accounts |
| Brute Force: Credential Stuffing | T1110.004 | High failures against a small set of usernames — known credential pairs being tested |
| Valid Accounts | T1078 | Successful login following brute force activity — monitor for `Accepted` events from same source IP post-detection |
