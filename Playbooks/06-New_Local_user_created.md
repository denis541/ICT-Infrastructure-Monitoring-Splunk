# Incident Response Playbook: New Local User Account Created
![Status: Production](https://img.shields.io/badge/Status-Production-green)
![Category: Account%20Management](https://img.shields.io/badge/Category-Account%20Management-blue)
![Tactic: Persistence](https://img.shields.io/badge/Tactic-Persistence-orange)
![Platform: Windows](https://img.shields.io/badge/Platform-Windows-0078D6)
![Severity: Medium](https://img.shields.io/badge/Severity-Medium-yellow)
## 🎯 Purpose
Respond to unauthorized or suspicious creation of local user accounts.

---

## 🛠️ Steps

### **Step 1 — Validate the Event**
- Confirm EventCode 4720 (new user created).
- Identify the account name and creator.

### **Step 2 — Determine Legitimacy**
- Check if IT or automation created the account.
- If unknown, treat as suspicious.

### **Step 3 — Investigate the Host**
- Review recent admin activity.
- Check for privilege escalation or lateral movement.

### **Step 4 — Contain**
- Disable or delete the unauthorized account.
- Reset credentials for affected admins.

### **Step 5 — Document & Close**
- Summarize findings and actions.
