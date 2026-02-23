![Status: Production](https://img.shields.io/badge/Status-Production-green)
![Category: Authentication](https://img.shields.io/badge/Category-Authentication-blue)
![Tactic: Credential%20Access](https://img.shields.io/badge/Tactic-Credential%20Access-orange)
![Platform: Multi-Platform](https://img.shields.io/badge/Platform-Multi--Platform-purple)
![Severity: High](https://img.shields.io/badge/Severity-High-red)
# Incident Response Playbook: Brute-Force Login Attempt

## 🎯 Purpose
Guide analysts through responding to brute-force authentication attempts detected by SIEM alerts.

---

## 🛠️ Steps

### **Step 1 — Validate the Alert**
- Review failed login patterns (e.g., EventCode 4625, SSH failures).
- Confirm repeated attempts from the same IP or against the same user.

### **Step 2 — Identify the Source IP**
- Determine whether the IP is internal, external, or known malicious.
- Enrich with threat intelligence sources.

### **Step 3 — Check for Successful Logins**
- Look for any successful login following the failures.
- If found, escalate severity immediately.

### **Step 4 — Block or Contain**
- Escalate to Network/Security team to block the IP.
- If internal, isolate the host.

### **Step 5 — Notify the User**
- Inform the targeted user and verify if attempts were legitimate.

### **Step 6 — Document & Close**
- Record findings, actions taken, and recommendations.
