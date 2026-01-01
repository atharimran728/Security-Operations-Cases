# Case 002 - Suspicious PowerShell Execution

**Case Type:** Incoming Alert  
**Severity (Initial):** Medium  
**Status:** Investigated → Decision Made  
 
---

## Alert Summary

An alert triggered when PowerShell was executed with an encoded or obfuscated command line. The host is a Windows workstation used by a standard user. No other immediate anomalies were detected.

Such behavior may indicate script-based attacks, malware execution, or post-exploitation activity, but could also represent legitimate admin or automated tasks.

---

## Detection Hypothesis

If PowerShell is executed with encoded or obfuscated command-line arguments outside of known administrative contexts, it may indicate malicious or suspicious activity.

**Assumptions:**

- Execution is unusual for the host and user role  
- Encoded or obfuscated commands are not part of approved scripts  
- Detection is single-execution sensitive; one occurrence can be suspicious  

---

## Required Logs

**Minimum logs for validation:**

- PowerShell Operational Logs (**Event ID 4104**)  
- Windows Security Event Logs (**Event ID 4688 – process creation**)  
- Sysmon Event Logs (**Event ID 1 – process creation**)  

**Optional enrichment:**

- Endpoint context (user role, host purpose)  
- Threat intelligence on parent processes, child processes, or network connections  

---

## Filtering Logic

To reduce false positives:

- Process name = `powershell.exe`  
- Command line contains encoding flags (e.g., `-EncodedCommand`) or obfuscation  
- Exclude known automation or admin scripts  
- Exclude scheduled system tasks  

---

## Aggregation Logic

- Single execution is high-signal  
- No aggregation required unless multiple hosts execute the same suspicious command in a short window (then flag as potential coordinated attack)  

---

## Investigation Steps and Pivots

### 1. Command Analysis
- Decode the encoded command  
- Identify scripts, functions, or payloads executed  

### 2. User & Host Context
- Is the user an admin or standard user?  
- Is the host a server or workstation?  
- Does this execution align with the host’s intended function?  

### 3. Parent & Child Processes
- Identify parent process to determine execution origin  
- Track child processes spawned for persistence or lateral movement  

### 4. Network & File Activity
- Check for outbound connections after execution  
- Look for downloaded files or modified system files  

### 5. Persistence Artifacts
- Registry keys, scheduled tasks, startup folder changes  

### 6. Threat Intelligence (Last)
- Reputation of external connections  
- Known malware hashes or IoCs  

---

## Example Outcomes

| Outcome | Example Scenario | Rationale |
|---------|-----------------|-----------|
| True Positive | Encoded PowerShell executed by malware dropped from phishing email | Detection correctly identifies malicious execution; host context confirms risk; immediate escalation warranted |
| False Positive | Encoded PowerShell used by legitimate admin script for automation | Execution is unusual in general, but context confirms benign; alert correctly fired, but action is to close |
| True Negative | Normal PowerShell commands executed with no obfuscation | No alert triggered, correct behavior |
| False Negative | Malware executed without obfuscation or encoding | Detection misses attack due to simple command usage; gap noted for improvement |

---

## Decision Logic

- **Escalate:** Encoded/obfuscated command from non-admin user on standard workstation, with suspicious child processes or network activity  
- **Monitor:** Execution appears unusual, but context is unclear; collect additional data and watch for follow-on activity  
- **Close / False Positive:** Admin script or known automation; no suspicious outcome  

**Example Decision for This Case:** Monitor  

- User execution flagged  
- No child processes or network activity  
- Host is standard workstation; pending further review  

---

## Lessons Learned

- Context is critical; encoded commands alone are not always malicious  
- Parent/child process analysis significantly improves confidence  
- Single-execution detection is necessary but insufficient alone; always pivot  
- Threat intelligence supports, but does not replace, contextual analysis
