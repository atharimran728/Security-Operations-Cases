# Case 003 - Unusual Process Execution on Endpoint

**Case Type:** Incoming Alert  
**Severity (Initial):** Low → Medium (context-dependent)  
**Status:** Investigated → Decision Made  

---

## Alert Summary

An alert was generated for a process execution that is uncommon for the affected host. The process is not typically observed running on this system based on historical behavior.

Unusual process execution may indicate malware, living-off-the-land abuse, or user misuse, but can also result from legitimate software installation, administrative activity, or one-time user behavior.

---

## Detection Hypothesis

If a process executes on a host where it is not typically observed, and the execution does not align with the host’s role or user context, the activity may be suspicious.

This hypothesis relies on **baseline deviation**, not known-bad indicators.

**Assumptions:**

- The host has an established behavioral baseline  
- The process is not part of standard OS or enterprise tooling  
- Context determines severity more than the process name itself  

---

## Required Logs

**Minimum logs required for investigation:**

- **Windows Security Event Log**
  - Event ID **4688** — Process creation  

- **Sysmon**
  - Event ID **1** — Process creation  
  - Event ID **3** — Network connections (pivot)  

**Optional context:**

- Asset inventory (host role)  
- Software allowlist or application inventory  

---

## Filtering Logic

To reduce noise:

- Focus on newly observed or rare processes  

**Exclude:**
- Known OS binaries  
- Approved enterprise software  
- Known admin tools on admin-designated systems  

**Prioritize:**
- User-writable paths  
- Temp directories  
- Unexpected execution locations  

Filtering is critical because most process executions are benign.

---

## Aggregation Logic

- Aggregation is **baseline-driven**, not count-based  

**Trigger when:**
- A process is first-seen on a host  
- A process deviates from normal execution paths  

**Optional aggregation:**
- Same unusual process executed across multiple hosts in a short time window  

---

## Investigation Steps and Pivots

### 1. Process Context
- What is the process name?  
- Execution path (system directory vs user directory)  
- File metadata (creation time vs execution time)  

### 2. Host Role Alignment
- Is this a workstation, server, or admin system?  
- Does this process make sense for that role?  

### 3. Parent Process Analysis
- What spawned the process?  

**Common parents:**
- Office applications  
- Browsers  
- Script interpreters  

Unexpected parent-child relationships increase suspicion.

### 4. User Context
- Which user executed the process?  
- Admin vs standard user  
- Interactive vs background execution  

### 5. Post-Execution Behavior
- Network connections initiated?  
- Files dropped or modified?  
- Persistence mechanisms created?  

### 6. Threat Intelligence (Last)
- Hash or process reputation  
- Used only to confirm or strengthen conclusions  

---

## Example Outcomes

### Outcome 1 - True Positive

**Scenario:**  
A binary executes from a user’s Temp directory, spawned by a document viewer, and initiates outbound connections.

**Rationale:**  
Execution path, parent process, and follow-on behavior indicate malicious activity. Detection correctly identified abnormal behavior.

---

### Outcome 2 - False Positive

**Scenario:**  
A legitimate application installer runs once from the Downloads directory during user-initiated installation.

**Rationale:**  
Behavior is unusual but expected during software installation. Context invalidates risk.

---

### Outcome 3 - True Negative

**Scenario:**  
Standard OS process executes repeatedly within expected paths and baseline behavior.

**Rationale:**  
No alert triggered. Correct non-detection.

---

### Outcome 4 - False Negative

**Scenario:**  
Malware masquerades as a common process name and executes within a trusted directory.

**Rationale:**  
Baseline-only detection fails due to name and path mimicry. Highlights need for behavioral and chain-based detection.

---

## Decision Logic

### Escalate
- Rare process  
- Unexpected execution path  
- Suspicious parent process  
- Network or persistence activity observed  

### Monitor
- First-seen process  
- Legitimate-looking behavior  
- No follow-on activity  

### Close / False Positive
- User-initiated install  
- Known software update  
- Behavior aligns with host function  

---

## Example Decision for This Case

**Decision:** Close - False Positive  

**Rationale:**  
Process execution aligned with a legitimate application installation initiated by the user. No malicious follow-on behavior observed.

---

## Lessons Learned

- Baseline deviation is powerful but noisy without context  
- Execution path and parent process matter more than process name  
- Unusual does not mean malicious  
- Follow-on behavior determines true risk
