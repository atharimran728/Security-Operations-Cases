# Case 004 - Suspicious Scheduled Task Creation (Persistence)

**Case Type:** Incoming Alert  
**Severity (Initial):** Medium  
**Status:** Investigated → Decision Made  

---

## Alert Summary

An alert was generated for the creation of a new scheduled task on a Windows host. The task was created outside of known maintenance windows and does not match standard enterprise task naming or execution patterns.

Scheduled tasks are commonly abused by attackers to establish persistence, but are also widely used for legitimate automation and system management.

---

## Detection Hypothesis

If a scheduled task is created on an endpoint outside of approved administrative workflows, especially if it executes scripts or binaries from unusual locations, the activity may indicate persistence related to malicious execution.

**Assumptions:**

- Legitimate scheduled tasks follow predictable naming and timing patterns  
- Persistence mechanisms often reference user-writable or non-standard paths  
- Task creation timing and execution target matter more than existence alone  

---

## Required Logs

**Minimum logs required for investigation:**

- **Windows Security Event Logs**
  - Event ID **4698** — Scheduled task created  

- **Task Scheduler Operational Logs**
  - Task creation and execution events  

- **Sysmon**
  - Event ID **1** — Process creation (task execution)  
  - Event ID **13** — Registry modifications (pivot)  

**Optional context:**

- Change management records  
- Asset role and owner  

---

## Filtering Logic

To reduce noise:

- Focus on newly created tasks  

**Exclude:**
- Known enterprise tasks  
- Vendor update and maintenance tasks  
- Tasks created during approved change windows  

**Prioritize:**
- Tasks executing from user directories  
- Tasks running scripts or interpreters (PowerShell, `cmd`, `wscript`)  
- Tasks configured to run at logon or high frequency  

---

## Aggregation Logic

- Aggregation is **event-driven**, not volume-based  

**Trigger when:**
- Task is newly created  
- Task execution command deviates from baseline  

**Optional aggregation:**
- Same task name or command observed on multiple hosts  

---

## Investigation Steps and Pivots

### 1. Task Metadata Analysis
- Task name and description  
- Trigger type (logon, startup, scheduled interval)  
- Run frequency and timing  
- Execution command and arguments  

### 2. Execution Context
- User account used to create and run the task  
- Privilege level (SYSTEM vs user)  
- Whether the task runs interactively or silently  

### 3. Execution Target
- Script or binary path  
- Location (system directory vs user-writable path)  
- File creation and modification timestamps  

### 4. Parent Activity Correlation
- Was PowerShell or unusual process execution observed earlier?  
- Any suspicious process spawning around task creation time?  

### 5. Follow-On Behavior
- Network connections when task executes  
- File writes or registry changes  
- Attempted credential access  

### 6. Threat Intelligence (Last)
- Hash or command reputation  
- Used only to validate conclusions  

---

## Example Outcomes

### Outcome 1 — True Positive

**Scenario:**  
A scheduled task is created that runs an encoded PowerShell command from a user’s AppData directory at logon.

**Rationale:**  
Task timing, execution target, and script obfuscation strongly indicate malicious persistence.

---

### Outcome 2 — False Positive

**Scenario:**  
An IT-deployed monitoring agent creates a scheduled task during system enrollment.

**Rationale:**  
Although task creation was flagged, documentation and context confirm legitimate automation.

---

### Outcome 3 — True Negative

**Scenario:**  
Routine Windows maintenance task created during system update cycle.

**Rationale:**  
No alert triggered; behavior aligns with expected system activity.

---

### Outcome 4 — False Negative

**Scenario:**  
Attacker modifies an existing scheduled task instead of creating a new one.

**Rationale:**  
Creation-based detection fails to observe modification, highlighting a gap in coverage.

---

## Decision Logic

### Escalate
- Task executes scripts or binaries from user-writable paths  
- Task created by non-admin user  
- Correlation with prior suspicious execution  

### Monitor
- New task with unclear context  
- No immediate malicious follow-on behavior  

### Close / False Positive
- Known enterprise task  
- Approved change or automation  
- Behavior matches baseline  

---

## Example Decision for This Case

**Decision:** Escalate  

**Rationale:**  
Task created outside change window, executing encoded PowerShell from a non-standard directory, with a suspicious execution chain.

---

## Lessons Learned

- Persistence indicators significantly increase confidence in malicious activity  
- Task creation timing and execution path are high-signal features  
- Correlating with prior execution events reduces false positives  
- Modification of existing tasks remains a detection blind spot
