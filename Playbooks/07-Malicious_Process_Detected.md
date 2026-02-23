# Incident Response Playbook: Malicious or Unknown Process Detected
![Status: Production](https://img.shields.io/badge/Status-Production-green)
![Category: Process%20Monitoring](https://img.shields.io/badge/Category-Process%20Monitoring-blue)
![Tactic: Execution](https://img.shields.io/badge/Tactic-Execution-orange)
![Platform: Multi-Platform](https://img.shields.io/badge/Platform-Multi--Platform-purple)
![Severity: Critical](https://img.shields.io/badge/Severity-Critical-darkred)
## 🎯 Purpose
Provide a workflow for responding to suspicious or malicious processes identified by SIEM or EDR.

---

## 🛠️ Steps

### **Step 1 — Validate the Process**
- Review process name, path, hash, and parent process.
- Check against threat intelligence.

### **Step 2 — Investigate the Host**
- Look for persistence mechanisms.
- Review network connections and file modifications.

### **Step 3 — Contain**
- Terminate the malicious process.
- Isolate the host if compromise is suspected.

### **Step 4 — Eradicate**
- Remove malicious files.
- Patch vulnerabilities or misconfigurations.

### **Step 5 — Recover**
- Restore from backup if needed.
- Re-enable the host after validation.

### **Step 6 — Document & Close**
- Record findings, root cause, and lessons learned.
