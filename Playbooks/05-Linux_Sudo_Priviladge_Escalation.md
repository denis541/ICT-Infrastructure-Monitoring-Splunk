![Status: Production](https://img.shields.io/badge/Status-Production-green)
![Category: Privilege%20Escalation](https://img.shields.io/badge/Category-Privilege%20Escalation-blue)
![Tactic: Privilege%20Escalation](https://img.shields.io/badge/Tactic-Privilege%20Escalation-orange)
![Platform: Linux](https://img.shields.io/badge/Platform-Linux-black)
![Severity: High](https://img.shields.io/badge/Severity-High-red)
# Incident Response Playbook: Linux Sudo Privilege Escalation

## 🎯 Purpose
Respond to suspicious or unexpected sudo usage on Linux systems.

---

## 🛠️ Steps

### **Step 1 — Validate the Sudo Event**
- Review logs for "session opened for user root".
- Identify the user who escalated privileges.

### **Step 2 — Determine Legitimacy**
- Check if the user is an admin or expected to use sudo.
- Review recent commands executed with elevated privileges.

### **Step 3 — Investigate the Host**
- Look for unusual processes, file changes, or new accounts.
- Check SSH logs for suspicious access.

### **Step 4 — Contain if Necessary**
- Disable the user account if compromised.
- Isolate the host for deeper investigation.

### **Step 5 — Document & Close**
- Record findings and remediation steps.
