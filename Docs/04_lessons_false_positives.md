## ⚠️ The False Positive Problem

### What Went Wrong Initially
Our first detection rule was **too simple**:

- Alerted on **any 5+ failed logins**
- Did **not consider context**
- Resulted in an **85% false positive rate**

> Translation: For every 100 alerts, **85 were false**. Analysts wasted significant time chasing noise.

### Root Causes Found
- Normal user mistakes (typos, caps lock)  
- Service accounts with expired credentials  
- Testing activities (IT team, developers)  
- Misconfigured applications  

---

### How We Fixed It

1. **Added Context (Logon Type)**  
   - **Before:** All failed logins  
   - **After:** Only network logins (`Logon Types 3 & 10`)  
   - **Impact:** False positives dropped **40%**

2. **Increased Threshold**  
   - **Before:** 5+ failures  
   - **After:** 7+ failures (based on observed data)  
   - **Impact:** False positives dropped **25%**

3. **Added Time Window**  
   - **Before:** Any 7 failures ever  
   - **After:** 7 failures **within 15 minutes**  
   - **Impact:** False positives dropped **30%**

4. **Created Allow Lists**  
   - Excluded known benign sources:  
     - Admin subnets  
     - Service account maintenance windows  
     - Backup system IPs  
   - **Impact:** False positives dropped **15%**

---

### The Numbers

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| False Positive Rate | 85% | 12% | ✅ Huge improvement |
| Alerts per Day | 47 | 6 | 87% reduction |
| Investigation Time per Alert | 18 min | 5 min | Major efficiency gain |

---

### Key Lessons
- Start simple, then refine — perfection on first try is impossible  
- Baseline normal activity — know what “normal” looks like  
- Treat false positives as data — they reveal environment quirks  
- Document every change — you’ll forget decisions if you don’t  

---

### What We’d Do Differently Next Time
- Collect **7 days of normal logs** before writing detections  
- Involve SOC analysts **earlier for feedback**  
- Create a **feedback loop** for continuous improvement  
- Schedule **review dates** for all allowlist/exclusion rules
