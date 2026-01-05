# Case 007 - Abnormal Privilege Escalation Attempt

**Case Type:** Detection Model  
**Difficulty:** SOC L1 → L2  
**Mapped To:** MITRE ATT&CK **TA0004 - Privilege Escalation**

---

## Scenario Overview

A non-administrative user account attempts to gain elevated privileges on a Windows host.

This may indicate:

- Credential abuse  
- Misuse of administrative tools  
- Local privilege escalation attempt  
- Exploitation of misconfigured permissions  

This case focuses on **behavior**, not malware signatures.

---

## Detection Hypothesis

A standard user account should not suddenly request or receive administrative privileges.  
When a user who normally operates without admin rights attempts elevation, the activity is suspicious and should be investigated.

---

## Required Logs

### Windows Security Logs
- **Event ID 4672** — Special privileges assigned to new logon  
- **Event ID 4688** — Process creation  
- **Event ID 4624** — Successful logon  

### Sysmon (Optional but Strong)
- **Event ID 1** — Process creation  
- **Event ID 10** — Process access (token manipulation indicators)  

---

## Filters (Conceptual)

**Include:**
- User account **not** in Administrators group  
- Privileged logon type  

**Processes commonly used for elevation:**
- `cmd.exe`  
- `powershell.exe`  
- `runas.exe`  
- `psexec.exe`  

**Exclude:**
- Known IT admin accounts  
- Scheduled maintenance windows  

---

## Aggregation Logic

**Group by:**
- Username  
- Host  

**Time window:**
- 5–10 minutes  

**Look for:**
- Privileged logon followed by process execution  

---

## Investigation Pivots

- Is this user normally privileged?
- Was a helpdesk task or ticket raised?
- Source of authentication (local vs remote)
- Parent process of elevated execution
- Any credential dumping or LSASS access?
- Persistence added after elevation?

---

## Outcomes & Rationale

### True Positive

**Outcome:**  
A standard employee account gains elevated privileges and launches PowerShell.

**Rationale:**  
User behavior deviates from baseline, and execution follows elevation. Strong indicator of compromise or misuse.

---

### False Positive

**Outcome:**  
Helpdesk technician temporarily elevated via approved IT process.

**Rationale:**  
Elevation aligns with ticketing system records and normal operational activity.

---

### False Negative

**Outcome:**  
Attacker already had admin credentials; no suspicious elevation event logged.

**Rationale:**  
Detection relies on elevation events. Pre-compromised admin accounts bypass this logic.

---

### True Negative

**Outcome:**  
Standard user activity without privilege change.

**Rationale:**  
No abnormal elevation observed.

---

## Analyst Notes

- Privilege escalation is often quiet, not noisy
- Always validate user role and baseline behavior
- Elevation alone isn’t malicious, context decides
