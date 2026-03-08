# Splunk System Configuration

![Splunk](https://img.shields.io/badge/Tool-Splunk_Enterprise-000000?style=flat&logo=splunk&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?style=flat&logo=windows&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-Detection_Engineering-4CAF50?style=flat&logoColor=white)

**Analyst:** Denis O. Onduso  
**Purpose:** Splunk index definitions, data input configuration, parsing rules, and data transformation logic for the home lab SIEM pipeline

---

## Configuration Files

| File | Purpose |
|------|---------|
| `indexes.conf` | Index definitions — storage paths and size limits |
| `inputs.conf` | Data ingestion — Windows Event Logs, file monitors, TCP receiver |
| `props.conf` | Parsing rules — sourcetype configuration and timestamp handling |
| `transforms.conf` | Data transformation — field extraction, PII masking, routing, lookups |

---

## indexes.conf — Index Definitions

Four indexes defined for log separation and retention management:

| Index | Purpose | Max Size |
|-------|---------|----------|
| `bots` | Boss of the SOC (BOTS) dataset — CTF/training scenario data | 512 GB |
| `secure_log` | Linux `/var/log/secure` — authentication and sudo events | 512 GB |
| `realtime` | Real-time Windows Security Event Logs | 512 GB |
| `weblogs` | Web server access and error logs | 512 GB |

All indexes follow the standard three-tier Splunk storage model: `homePath` (hot/warm, active search), `coldPath` (cold, compressed), `thawedPath` (restored archived data).

---

## inputs.conf — Data Ingestion

### TCP Receiver
```ini
[splunktcp://9997]
connection_host = ip
```
Receives forwarded data from Splunk Universal Forwarder instances on port 9997. `connection_host = ip` uses the forwarder's IP as the host value — relevant for environments where DNS resolution is unreliable.

### Windows Event Log Collection

| Channel | Disabled | Notes |
|---------|----------|-------|
| Application | No | Application errors and warnings |
| System | No | OS-level events, service failures |
| Security | No | Authentication, account management, process creation |
| Setup | No | Windows Update and installation events |

All channels configured with `start_from = oldest` to ensure no historical events are missed on initial deployment, and `checkpointInterval = 5` seconds for near-real-time ingestion.

### File Monitors

| Monitor Path | Host | Index | Sourcetype | Notes |
|-------------|------|-------|------------|-------|
| `C:\` | DenisLaptop1 | default | default | Full drive monitor |
| `C:\xampp\apache\logs\access.log` | DenisLaptop1 | default | access_combined | Apache access log |
| `C:\xampp\apache\logs\` (error.log only) | DenisLaptop1 | default | default | Whitelist filters to error.log only |
| `C:\SplunkData\logs\app.log` | DenisLaptop1 | main | _json | JSON-formatted application log |
| `C:\splunk_logs` | DenisLaptop1 | simple | default | Simple log directory |

---

## props.conf — Parsing Rules

| Term | Configuration | Purpose |
|--------|--------------|---------|
| `access_combined_json` | Custom sourcetype | Apache access log parsing |
| `secure` | Custom line breaker, no binary check | Linux secure log normalization — ensures correct event boundary detection on auth log entries |

The `secure` sourcetype explicitly sets `LINE_BREAKER = ([\r\n]+)` to prevent multi-line auth events from being concatenated into a single event, which would break field extraction and timestamp parsing.

---

## transforms.conf — Data Transformation

### Section 1: Metadata Overrides

**`force_host_for_syslog`** — Corrects host field for syslog relay scenarios where the relay's IP is incorrectly used as the host value. Regex extracts the actual hostname from the syslog message body and writes it to `MetaData:Host`.

**`force_sourcetype_cisco_asa`** — Dynamically re-classifies Cisco ASA logs arriving via generic syslog input. Regex matches on the `%ASA-` pattern and rewrites the sourcetype to `cisco:asa` for correct field extraction.

### Section 2: PII Masking

**`mask_credit_cards`** — Masks 16-digit credit card numbers in raw event data before indexing:

```
Original:  4532-0151-1208-3619
Masked:    4532-xxxx-xxxx-3619
```

`REPEAT_MATCH = true` ensures all card numbers in a single event are masked, not just the first match. This is applied at index time — the raw data stored in Splunk never contains full card numbers.

### Section 3: Data Routing and Filtering

**`drop_debug_logs`** — Routes events containing `DEBUG` log level to `nullQueue`, dropping them before indexing. Reduces Splunk license volume consumption from verbose application logs.

**`route_security_to_audit_index`** — Routes events matching `Failed Login` or `Access Denied` patterns to the `security_audit_logs` index for extended retention, separate from general log storage.

### Section 4: Field Extractions

**`extract_custom_app_fields`** — Extracts five fields from comma-delimited application logs:

| Field | Content |
|-------|---------|
| `timestamp` | Event time |
| `user_id` | Acting user |
| `action` | Operation performed |
| `status` | Success / failure |
| `response_time` | Application response latency |

### Section 5: Lookup Definitions

**`error_code_lookup`** — Maps application error codes to human-readable descriptions via `error_codes.csv`. Allows SPL queries to enrich raw error code fields with descriptive text without hardcoding values in detection rules.

---

## Security Notes

The `mask_credit_cards` transform in `transforms.conf` directly addresses the data exposure vector identified in the SQL injection and DNS exfiltration investigation (project 15) — where credit card data was exfiltrated via DNS tunneling. Masking at index time ensures that even if Splunk logs are accessed by an unauthorized party, full card numbers are not recoverable from the index.

The `route_security_to_audit_index` transform ensures authentication failure and access denied events are retained on a separate extended-retention index — supporting forensic investigation timelines that extend beyond the default retention window of the main index.
