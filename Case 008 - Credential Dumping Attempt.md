## Case 008 - Credential Dumping Attempt

**Case Type:** Behavioral Detection  
**Difficulty:** SOC L1 → L2  
**Mapped To:** MITRE ATT&CK TA0006 (Credential Access)

---

## Scenario Overview

An endpoint shows behavior consistent with attempts to extract credentials from memory or protected system stores.

Credential dumping is typically used to:

- Harvest passwords or hashes
- Enable lateral movement
- Escalate privileges
- Maintain long-term access

Attackers often target LSASS or use built-in Windows utilities to avoid dropping malware.

---

## Detection Hypothesis (Plain English)

Normal applications do not access sensitive credential storage processes.  
If a user-level process attempts to read LSASS memory or execute known credential-dumping utilities, it is highly suspicious.

---

## Required Logs

### Windows Security

- **Event ID 4688** — Process creation  
- **Event ID 4673** — Sensitive privilege use  

### Sysmon

- **Event ID 1** — Process creation  
- **Event ID 10** — Process access (critical)  
- **Event ID 11** — File creation (dump files)

---

## Filters (Conceptual)

### Process Indicators

Access to:
- `lsass.exe`

Known dumping tools or patterns:
- `mimikatz`
- `procdump`
- `comsvcs.dll`

Suspicious flags:
- `-ma lsass`
- `MiniDump`

### Exclusions

- Endpoint protection software
- Approved forensic tools (rare, tightly controlled)

---

## Aggregation Logic

- Single event may be sufficient (high signal)

Correlate:
- Process access → file dump creation

Group by:
- Host
- User

Time window:
- 1–2 minutes

---

## Investigation Pivots

- Which process accessed LSASS?
- Was the user already privileged?
- Parent process (PowerShell, cmd, service)?
- Was a dump file created?
- Any outbound authentication attempts afterward?
- Lateral movement shortly after?

---

## Outcomes & Rationale

### True Positive

**Outcome:**  
`procdump.exe` accesses `lsass.exe` and creates a `.dmp` file.

**Rationale:**  
Direct credential dumping behavior. Very high confidence.

---

### False Positive

**Outcome:**  
EDR or security tooling accesses LSASS.

**Rationale:**  
Security products legitimately inspect LSASS. Must be allowlisted carefully.

---

### False Negative

**Outcome:**  
Attacker uses kernel-level or signed tool that evades Sysmon logging.

**Rationale:**  
Some advanced techniques bypass user-mode visibility.

---

### True Negative

**Outcome:**  
Normal endpoint activity with no sensitive process access.

**Rationale:**  
No credential access behavior detected.

---

## Analyst Notes

- Credential dumping is often the turning point in attacks
- Treat LSASS access as guilty until proven innocent
- Alert fatigue here is dangerous, tune, don’t silence
