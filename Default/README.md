# Threat Intelligence Lookup Integration (Splunk)

![Splunk](https://img.shields.io/badge/Tool-Splunk-000000?style=flat&logo=splunk&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-Detection_Engineering-4CAF50?style=flat&logoColor=white)
![Type](https://img.shields.io/badge/Config-transforms.conf-0078D4?style=flat&logoColor=white)

**Analyst:** Denis O. Onduso  
**Purpose:** CSV-based threat intelligence lookups for IP, domain, and file hash enrichment in Splunk detection rules

---

## Overview

This configuration registers three threat intelligence lookup tables in Splunk via `transforms.conf`. Once deployed, these lookups allow any SPL query to enrich events with threat intelligence context — flagging known-malicious IPs, domains, and file hashes inline during detection and investigation.

---

## Lookup Tables

| Lookup Name | CSV File | Enriches |
|-------------|----------|---------|
| `threat_ips` | `threat_intel_ips.csv` | Source/destination IPs against known-malicious IP list |
| `threat_domains` | `threat_intel_domains.csv` | DNS query names and HTTP hostnames against malicious domain list |
| `threat_hashes` | `threat_intel_hashes.csv` | File hashes (MD5/SHA256) against known-malicious binary list |

---

## Configuration File

**Path:** `$SPLUNK_HOME/etc/apps/<your_app>/lookups/transforms.conf`

```ini
[threat_ips]
batch_index_query = 0
case_sensitive_match = 0
filename = threat_intel_ips.csv

[threat_domains]
batch_index_query = 0
case_sensitive_match = 0
filename = threat_intel_domains.csv

[threat_hashes]
batch_index_query = 0
case_sensitive_match = 0
filename = threat_intel_hashes.csv
```

**Configuration notes:**
- `case_sensitive_match = 0` — domain and hash lookups are case-insensitive, preventing evasion via case variation (e.g. `MaliciousDomain.COM` vs `maliciousdomain.com`)
- `batch_index_query = 0` — lookups are evaluated at query time rather than indexed, keeping the CSV files as the authoritative source

---

## CSV Format

Each lookup CSV requires at minimum an indicator column and a context column. Recommended schema:

**`threat_intel_ips.csv`**
```
ip,threat_category,confidence,source,last_seen
31.22.4.176,C2,High,ABUSE.CH,2024-01-15
209.165.201.17,Brute Force,Medium,Internal,2024-02-01
```

**`threat_intel_domains.csv`**
```
domain,threat_category,confidence,source,last_seen
tybenme.com,Exploit Kit,High,Emerging Threats,2024-01-20
maliciousdomain.com,DNS Tunneling,High,Internal,2024-01-22
```

**`threat_intel_hashes.csv`**
```
hash,hash_type,malware_family,confidence,source
2a9b0ed40f1f0bc0c13ff35d304689e9cadd633781cbcad1c2d2b92ced3f1c85,SHA256,Remcos RAT,High,Cisco Talos
```

---

## Usage in SPL Queries

Once registered, lookups are called using the `lookup` command:

```spl
| lookup threat_ips ip AS src_ip OUTPUT threat_category, confidence
| where isnotnull(threat_category)
```

```spl
| lookup threat_domains domain AS dns_query OUTPUT threat_category, confidence
| where isnotnull(threat_category)
```

```spl
| lookup threat_hashes hash AS file_hash OUTPUT malware_family, confidence
| where isnotnull(malware_family)
```

The `where isnotnull()` filter returns only events that matched a threat intel entry — keeping output clean for triage.

---

## Enriched Detection Example

Combining the brute force detection rule with IP threat intel enrichment:

```spl
index=windows EventCode=4625 earliest=-15m
| where Logon_Type=3 OR Logon_Type=10
| stats count as failure_count by src_ip
| where failure_count > 7
| lookup threat_ips ip AS src_ip OUTPUT threat_category, confidence
| eval intel_match=if(isnotnull(threat_category), "Known Threat: " + threat_category, "No Intel Match")
| table src_ip, failure_count, intel_match, confidence
| sort -failure_count
```

A source IP that appears in both the brute force detection and the threat intel lookup is high-confidence malicious — the two signals together justify immediate containment without further investigation.

---

## Keeping Lookups Current

CSV-based lookups are static unless updated manually or via automation. Recommended update sources:

| Feed | Data Type | Update Frequency |
|------|-----------|-----------------|
| ABUSE.CH SSL Blacklist | IPs, domains | Daily |
| Emerging Threats | IPs, domains | Daily |
| Cisco Talos | IPs, hashes | Daily |
| Internal IOCs (from investigations) | All types | Per incident |

For production environments, consider replacing static CSVs with a threat intelligence platform (MISP, OpenCTI) feeding Splunk via the Splunk Add-on for Threat Intelligence.

---

## MITRE ATT&CK Relevance

| Technique | ID | Relevance |
|-----------|----|-----------|
| Indicator Removal | T1070 | Threat intel lookups detect known IOCs even if local logs are partially cleared |
| Command and Control | T1071 | IP and domain lookups flag known C2 infrastructure in network traffic |
| Malware Identification | — | Hash lookups against threat intel feeds is the primary malware triage step |
