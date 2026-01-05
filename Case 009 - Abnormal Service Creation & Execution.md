# Case 009 - Abnormal Service Creation & Execution

**Case Type:** Behavioral Detection  
**Difficulty:** SOC L1 → L2  
**Mapped To:** MITRE ATT&CK TA0003 / TA0006 (Persistence / Credential Access via Services)

---

## Scenario Overview

A Windows endpoint reports the creation of a new service or modification of an existing service that is uncommon for the host. The service runs under unusual privileges or points to a binary in a non-standard location (e.g., user-writable directories).

Attackers often abuse Windows services to:

- Maintain persistence across reboots  
- Execute malicious code with SYSTEM privileges  
- Evade detection by masquerading as legitimate services  

Legitimate use exists, but deviations from baseline behavior are **high-signal indicators**.

---

## Detection Hypothesis

If a service is created or modified outside normal administrative workflows, pointing to a binary in a user-writable path or running unexpected commands, it may indicate **malicious persistence**.

**Key assumptions:**

- Normal services follow enterprise-defined naming, path, and timing conventions  
- User accounts should not create services  
- Known service creation tools (e.g., `sc.exe`, PowerShell `New-Service`) are often abused  

---

## Required Logs

### Windows Security Event Logs
- **Event ID 4698** — Scheduled task creation (if service triggers tasks)  
- **Event ID 7045** — Service installed / created  
- **Event ID 4688** — Process creation (who executed the service creation)  

### Sysmon
- **Event ID 1** — Process creation  
- **Event ID 13** — Registry modification (if service configured via registry)  

**Optional enrichment:**

- Host baseline of known services  
- File hashes of service binaries  
- User role and historical activity  

---

## Filtering Logic

**Focus on:**  
- New or modified services  

**Exclude:**  
- Approved software installation  
- Vendor maintenance tasks  
- Services in standard system paths (`C:\Windows\System32`) if expected  

**Prioritize:**  
- Binaries in user-writable locations (AppData, Temp)  
- Services created by non-admin users  
- Services running scripts, PowerShell commands, or unknown binaries  

---

## Aggregation Logic

- **Group by:** Host, User, Service name  
- **Trigger when:** Service creation/modification deviates from baseline  
- **Optional:** Aggregate if multiple hosts create similar suspicious services  

---

## Investigation Steps & Paths

### Event Logs
- Check **Event ID 7045** for service creation  
- Check **Event ID 4688** for the process that created the service  

### Binary Verification
- Path: `ImagePath` in service configuration  
- File hash, size, creation date  
- Compare to baseline or known software  

### User & Host Context
- Who created the service? Admin vs standard user  
- Host role: workstation vs server  
- Timing: normal business hours vs off-hours  

### Parent Process & Commands
- Parent process of `sc.exe` or `New-Service`  
- Command-line flags, encoded PowerShell usage  

### Persistence & Follow-On Behavior
- Does the service auto-start after reboot?  
- Child processes spawned after start?  
- Outbound connections, registry changes, or file writes  

### Threat Intelligence
- Binary hash check  
- Destination IPs or URLs if the service connects externally  

---

## Example Outcomes & Rationale

| Outcome | Scenario | Rationale |
|---------|---------|-----------|
| **True Positive** | New service created by a standard user pointing to a binary in AppData, auto-starting, with outbound connections | Malicious persistence confirmed; detection correct |
| **False Positive** | Vendor update service installed via installer in Program Files | Service creation is legitimate; detection triggered due to uncommon event but context clears |
| **True Negative** | System service running from System32 installed at baseline | Detection not triggered; correct |
| **False Negative** | Attacker modifies an existing service to point to malicious binary in place of legitimate executable | Detection based on creation misses this; highlights coverage gap |

---

## Decision Logic

- **Escalate:** Service created/modified by non-admin user, binary in unusual path, auto-start, outbound connections or child processes  
- **Monitor:** Service created by admin but path or timing unusual; further observation needed  
- **Close / False Positive:** Approved software/service; event aligns with baseline  

---

## Lessons Learned

- Attackers leverage legitimate OS mechanisms like services for stealth  
- Standard baseline for services is critical to reduce noise  
- Parent process, path, and user context drive investigation decisions  
- Alerts alone do not equal incidents - correlation is key  

---

