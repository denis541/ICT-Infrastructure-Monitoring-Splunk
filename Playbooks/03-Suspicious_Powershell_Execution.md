# Incident Response Playbook: Suspicious PowerShell Execution
![Status: Production](https://img.shields.io/badge/Status-Production-green)
![Category: PowerShell](https://img.shields.io/badge/Category-PowerShell-blue)
![Tactic: Execution](https://img.shields.io/badge/Tactic-Execution-orange)
![Platform: Windows](https://img.shields.io/badge/Platform-Windows-0078D6)
![Severity: High](https://img.shields.io/badge/Severity-High-red)

## 🎯 Purpose
Respond to detections involving encoded or obfuscated PowerShell commands.

---

## 🛠️ Steps

### **Step 1 — Review the Command Line**
- Inspect the full PowerShell command.
- Look for `-EncodedCommand`, Base64 strings, or obfuscation.

### **Step 2 — Identify the Parent Process**
- Determine what launched PowerShell (e.g., Office, cmd.exe, wscript).
- Unexpected parents increase severity.

### **Step 3 — Check User Context**
- Identify which user executed the command.
- Determine if the activity aligns with their role.

### **Step 4 — Investigate the Host**
- Review recent process activity.
- Check for suspicious downloads, persistence, or lateral movement.

### **Step 5 — Contain if Malicious**
- Kill malicious processes.
- Isolate the host if compromise is suspected.

### **Step 6 — Document & Close**
- Summarize findings and actions.
