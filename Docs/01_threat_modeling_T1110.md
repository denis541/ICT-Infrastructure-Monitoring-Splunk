# Threat Modeling: Brute-Force Authentication Attacks (MITRE T1110.001)

## Executive Summary
This document details the threat modeling process for brute-force authentication attacks, the primary use case implemented in this security lab. The analysis follows industry-standard frameworks to ensure comprehensive coverage and realistic implementation.

## Threat Actor Profile

| **Category** | **Description** | **Relevance to Lab** |
|--------------|-----------------|---------------------|
| **Adversary** | Opportunistic attacker | Primary focus - automated tools |
| **Resources** | Low to moderate | Scripts, password lists |
| **Sophistication** | Basic to intermediate | Common attack patterns |
| **Objective** | Initial access | Credential compromise |

## Attack Vector Analysis

### Primary Attack Path
Reconnaissance → 2. Target Identification → 3. Brute-Force Attempt → 4. Successful Access → 5. Lateral Movement


### Key Characteristics:
- **Target:** Authentication interfaces (RDP, SSH, WinRM)
- **Tools:** Hydra, Ncrack, custom PowerShell scripts
- **Frequency:** Continuous automated attempts
- **Velocity:** 5-20 attempts per minute per source
- **Duration:** Minutes to days

## MITRE ATT&CK Mapping

### Technique: T1110.001 (Password Guessing)
**Description:** Adversaries use brute-force techniques to guess passwords.

**Procedure Examples in Lab:**
1. **Password Spraying:** Common passwords across multiple accounts
2. **Dictionary Attacks:** Wordlist-based password attempts
3. **Credential Stuffing:** Reused credentials from breaches

### Related Techniques:
- **T1110.002** - Password Cracking (Post-compromise)
- **T1078** - Valid Accounts (Goal of brute-force)
- **T1021** - Remote Services (Target of attacks)

## Risk Assessment

### Impact Analysis
| **Factor** | **Level** | **Justification** |
|------------|-----------|-------------------|
| **Confidentiality** | High | Successful attack exposes all account-accessible data |
| **Integrity** | Medium | Account takeover enables data manipulation |
| **Availability** | Low | Lockout policies mitigate service disruption |
| **Business Impact** | High | Data breach, compliance violations, reputation damage |

### Likelihood Assessment
| **Factor** | **Score** | **Rationale** |
|------------|-----------|---------------|
| **Attack Frequency** | 9/10 | Most common initial access vector |
| **Ease of Execution** | 8/10 | Tools widely available, low technical barrier |
| **Detection Difficulty** | 4/10 | Basic detection exists, but tuning is challenging |
| **Overall Likelihood** | High | 85% probability in 6-month period |

## Detection Strategy

### Primary Detection Points
1. **Authentication Logs:** Failed login attempts (Windows Event ID 4625)
2. **Account Lockouts:** Security policy triggers (Event ID 4740)
3. **Network Traffic:** Authentication protocol patterns
4. **Temporal Analysis:** Unusual login times/frequencies

### Detection Challenges
- **False Positives:** Legitimate user errors, service account issues
- **Evasion Techniques:** Slow attacks, distributed sources
- **Logging Gaps:** Missing or misconfigured log sources

## Countermeasures Implemented

### Preventive Controls
- Account lockout policies (5 attempts, 30-minute duration)
- Strong password requirements
- Multi-factor authentication (simulated in lab)

### Detective Controls
- Real-time alerting on threshold breaches
- Correlation with geographic anomalies
- Integration with threat intelligence feeds

### Response Playbook
1. **Alert triggers** → 2. **Investigation** → 3. **Containment** → 4. **Eradication** → 5. **Recovery**

## Success Criteria

### Detection Requirements
- **Detection Rate:** >95% of brute-force attempts
- **False Positive Rate:** <15% after tuning
- **Mean Time to Detect:** <10 minutes
- **Mean Time to Respond:** <30 minutes

### Validation Methods
1. Controlled attack simulations
2. Manual testing of detection logic
3. Historical log analysis
4. Peer review of detection rules

## References
- MITRE ATT&CK: T1110.001
- NIST SP 800-53: IA-5, AC-7
- CIS Controls: 5.1, 5.2, 5.3
