# Incident Response Playbook: Unauthorized Login Attempt
![Category: Incident Response](https://img.shields.io/badge/Category-Incident%20Response-blue)
![Status: Active](https://img.shields.io/badge/Status-Active-green)
![Playbook Type: SOC](https://img.shields.io/badge/Playbook%20Type-SOC-orange)
![Scope: Enterprise](https://img.shields.io/badge/Scope-Enterprise-purple)
![Priority: High](https://img.shields.io/badge/Priority-High-red)
## 🎯 Purpose
Provide a clear, repeatable workflow for responding to unauthorized or suspicious login attempts detected by SIEM alerts.

---

## 🛠️ Step-by-Step Response Procedure

### **Step 1 — Identify the Source IP**
- Review the alert details in the SIEM.
- Extract the source IP address associated with the failed or suspicious login.
- Check whether the IP is internal, external, or known to be malicious.
- Optionally enrich with threat intel (VirusTotal, AbuseIPDB, etc.).

---

### **Step 2 — Check if the User Is Currently Logged In**
- Verify whether the affected user account is actively logged in.
- On Windows:  
  - Query active sessions (e.g., `query user`, RDP session logs).
- On Linux:  
  - Check `who`, `last`, or SSH session logs.
- If the user is logged in unexpectedly, treat as **high severity**.

---

### **Step 3 — Escalate to Network Administration**
- Provide the source IP, timestamps, and user account involved.
- Request immediate blocking of the suspicious IP at:
  - Firewall  
  - VPN gateway  
  - Reverse proxy  
  - Cloud security controls  
- Document the escalation in the incident ticket.

---

## 📝 Notes
- If multiple failed logins occur from the same IP, consider brute-force indicators.
- If the login succeeded, escalate severity and begin containment steps.
- Always notify the user whose account was targeted.

---

## ✅ Completion Criteria
- IP blocked or mitigated.
- User account verified or reset if needed.
- Incident documented and closed.
