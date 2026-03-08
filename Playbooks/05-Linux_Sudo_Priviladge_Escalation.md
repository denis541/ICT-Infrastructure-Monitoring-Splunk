# Incident Response Playbook: Linux Sudo Privilege Escalation

![Splunk](https://img.shields.io/badge/Tool-Splunk-000000?style=flat&logo=splunk&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=flat&logo=linux&logoColor=black)
![Domain](https://img.shields.io/badge/Domain-Incident_Response-E01B1B?style=flat&logoColor=white)

**Analyst:** Denis O. Onduso  
**Trigger:** Splunk alert — `session opened for user root by` in `linux_secure` logs  
**Tactic:** Privilege Escalation (TA0004) — T1548.003  
**SLA:** Determine legitimacy within 10 minutes; contain within 20 minutes if unauthorized escalation confirmed

---

## Scope

This playbook covers unexpected or suspicious sudo escalations to root on Linux hosts. The detection fires on any successful root session open — the playbook's purpose is to rapidly determine whether the escalation was authorized, what commands were run under root, and whether the sudoers configuration has been tampered with.

---

## Step 1 — Identify the Escalation Event

Pull the full context of the alert:

```spl
index=linux sourcetype=linux_secure "session opened for user root by"
| rex field=_raw "by (?<sudo_user>\S+)\("
| table _time, host, sudo_user
| sort -_time
```

Key fields to extract:
- **`sudo_user`** — the account that ran sudo (not root — the originating user)
- **`host`** — which Linux host the escalation occurred on
- **`_time`** — when the session was opened

Then pull the specific command executed under sudo:

```spl
index=linux sourcetype=linux_secure sudo
| rex field=_raw "COMMAND=(?<sudo_command>.+)"
| where sudo_user="<escalating_user>"
| table _time, host, sudo_user, sudo_command
| sort -_time
```

**Document the command before proceeding.** `sudo nginx -t` is routine. `sudo bash`, `sudo su`, or `sudo python3 -c 'import os; os.system("/bin/bash")'` are interactive shell drops — treat as critical immediately.

---

## Step 2 — Classify the Escalation

| Command Pattern | Classification | Severity |
|-----------------|---------------|----------|
| `sudo bash`, `sudo su`, `sudo -s` | Interactive root shell — persistent elevated access | **Critical** |
| `sudo python3/perl/ruby -e ...` | Script-based shell drop | **Critical** |
| `sudo visudo` / editing `/etc/sudoers` | Sudoers modification — persistence attempt | **Critical** |
| `sudo useradd`, `sudo passwd` | New account or credential change under root | **High** |
| `sudo systemctl stop <security-tool>` | Disabling monitoring or security controls | **High** |
| `sudo systemctl restart nginx` | Service management — verify against change record | **Low** |
| `sudo apt install <package>` | Package installation — verify against change record | **Low** |

If the command is in the Critical or High rows above, move to Step 4 containment immediately — do not wait for legitimacy verification.

---

## Step 3 — Verify Legitimacy

**Is the user expected to have sudo access?**

Check the sudoers configuration on the host:

```bash
sudo cat /etc/sudoers
sudo cat /etc/sudoers.d/*
```

If the escalating user is not in the sudoers file or was recently added, that is a persistence indicator — an attacker who gained initial access may have modified sudoers to grant themselves escalation rights.

**Has this user escalated before?**

```spl
index=linux sourcetype=linux_secure "session opened for user root by"
| rex field=_raw "by (?<sudo_user>\S+)\("
| where sudo_user="<escalating_user>"
| stats count by sudo_user, host
| sort -count
```

A first-time escalation from a user with no history of sudo usage warrants higher scrutiny than an admin who escalates daily.

**Does the timing make sense?**

Off-hours escalation from a non-admin account is a stronger indicator of compromise than a known admin running `sudo` during business hours.

---

## Step 4 — Investigate Post-Escalation Activity

Regardless of initial legitimacy assessment, check what happened after the root session opened:

```bash
# Review auth log for the session window
grep "sudo\|su\|root" /var/log/secure | grep -A 20 "<timestamp>"

# Check for new accounts created under root
grep "useradd\|adduser" /var/log/secure

# Check for cron persistence
cat /etc/cron.d/*
crontab -l -u root

# Check for sudoers modification
stat /etc/sudoers
ls -la /etc/sudoers.d/
```

In Splunk, check for file integrity events if auditd is configured:

```spl
index=linux sourcetype=linux_audit earliest=-1h
| where host="<affected_host>"
| search key="sudoers_change" OR key="etc_passwd_change"
| table _time, host, key, exe, auid
```

**High-severity indicators to look for:**

| Indicator | Significance |
|-----------|-------------|
| `/etc/sudoers` modified after escalation | Persistence — attacker granting permanent sudo rights |
| New user added to `/etc/passwd` or `/etc/sudoers` | Backdoor account creation |
| SSH authorized_keys modified | Persistent SSH access added |
| Cron job added under root | Scheduled persistence mechanism |
| Outbound connection from root process | C2 activity or data exfiltration |

---

## Step 5 — Containment

**If unauthorized escalation confirmed:**

1. **Disable the compromised account** immediately:
```bash
sudo usermod -L <compromised_user>
```

2. **Kill any active root sessions** from the account:
```bash
# Find and kill the session
who | grep <compromised_user>
pkill -KILL -u <compromised_user>
```

3. **Revert sudoers if modified** — restore from known-good backup or remove unauthorized entries:
```bash
sudo visudo  # Review and remove unauthorized entries
```

4. **Remove any backdoor accounts** created during the escalation window

5. **Isolate the host** if C2 activity, outbound connections from root processes, or lateral movement indicators are found

6. **Escalate to Tier 2** if persistence mechanisms were installed or if the initial access vector is unknown

---

## Step 6 — Document and Close

| Field | Required Content |
|-------|----------------|
| Escalating user | Account that ran sudo |
| Command executed | Full sudo command — decoded if obfuscated |
| Legitimacy determination | Authorized / Unauthorized / Unverified |
| Sudoers modification | Yes / No — checked and documented |
| Post-escalation activity | New accounts, cron jobs, SSH keys, outbound connections |
| Containment actions | Account disabled, session killed, sudoers reverted |
| Persistence confirmed | Yes / No |
| Escalated to Tier 2 | Yes / No |

---

## MITRE ATT&CK Relevance

| Technique | ID | Step |
|-----------|----|------|
| Abuse Elevation Control: Sudo | T1548.003 | Step 1 — primary detection trigger |
| Create Account: Local Account | T1136.001 | Step 4 — backdoor account creation post-escalation |
| Boot or Logon Initialization: Cron | T1053.003 | Step 4 — cron-based persistence check |
| SSH Authorized Keys | T1098.004 | Step 4 — SSH key persistence check |
| Impair Defenses | T1562 | Step 2 — `sudo systemctl stop <security-tool>` pattern |
| Lateral Movement | T1021.004 | Step 4 — outbound SSH connections from root process |
