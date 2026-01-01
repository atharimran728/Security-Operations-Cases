# Case 005 - Suspicious Outbound Network Beaconing

**Case Type:** Incoming Alert  
**Severity (Initial):** Medium  
**Status:** Investigated → Decision Made  

---

## Alert Summary

An alert was generated for repeated outbound network connections from a single host to an external destination at regular intervals. The traffic volume is low, but the periodic nature of the connections deviates from normal user or application behavior.

Such patterns are commonly associated with command-and-control (C2) beaconing, but may also be caused by legitimate software update checks, telemetry, or misconfigured applications.

---

## Detection Hypothesis

If a host makes repeated outbound connections to the same external destination at consistent time intervals with low data volume, the activity may indicate beaconing behavior related to malware command-and-control.

**Assumptions:**

- Legitimate applications usually show variable timing or higher data transfer  
- Regularity and persistence matter more than volume  
- Context determines whether the destination is expected  

---

## Required Logs

**Minimum logs required for investigation:**

- **Network logs**
  - Firewall or proxy logs  
  - NetFlow or equivalent connection metadata  

- **Endpoint telemetry**
  - Sysmon Event ID **3** — Network connections  
  - Process execution logs (to identify beaconing process)  

**Optional context:**

- DNS query logs  
- Asset role and owner  
- Application inventory  

---

## Filtering Logic

To reduce benign noise:

- Focus on outbound connections  

**Exclude:**
- Known enterprise update servers  
- Cloud service providers used by approved applications  
- High-volume or highly variable traffic  

**Prioritize:**
- Low data transfers  
- Rare or newly observed destinations  
- Direct IP connections without DNS resolution  

---

## Aggregation Logic

To detect beacon-like behavior:

**Group by:**
- Source host  
- Destination IP or domain  

**Measure:**
- Connection frequency  
- Time interval consistency  

**Time window:**
- 10–60 minutes (depending on environment)  

**Trigger when:**
- Connections occur at regular intervals  
- Traffic volume remains consistently low  

---

## Investigation Steps and Pivots

### 1. Destination Analysis
- Is the destination IP or domain known or previously seen?  
- Newly registered or rarely contacted domains?  
- Is DNS used or is the connection direct to IP?  

### 2. Timing Analysis
- Are intervals consistent (e.g., every 60 seconds)?  
- Does the pattern persist over long durations?  

### 3. Process Attribution
- Which process initiated the connections?  
- Does the process align with host and user role?  
- Was the process previously flagged in earlier cases?  

### 4. Host Context
- Is this a user workstation or server?  
- Any recent suspicious execution or persistence events?  

### 5. Lateral Indicators
- Do other hosts exhibit similar beaconing to the same destination?  
- Is this isolated or campaign-like behavior?  

### 6. Threat Intelligence (Last)
- Domain/IP reputation  
- Known C2 infrastructure correlation  

---

## Example Outcomes

### Outcome 1 — True Positive

**Scenario:**  
A workstation repeatedly connects to a newly registered domain every 90 seconds using a process previously flagged for suspicious PowerShell execution.

**Rationale:**  
Consistent timing, rare destination, and correlated execution strongly indicate C2 beaconing.

---

### Outcome 2 — False Positive

**Scenario:**  
A legitimate endpoint management agent checks in periodically with a vendor-controlled server.

**Rationale:**  
Timing is regular, but destination and process are expected and approved.

---

### Outcome 3 — True Negative

**Scenario:**  
Normal web browsing and application traffic with irregular timing and variable data volume.

**Rationale:**  
Detection does not trigger, which is correct behavior.

---

### Outcome 4 — False Negative

**Scenario:**  
Beaconing traffic is jittered to avoid regular interval detection.

**Rationale:**  
Interval-based detection fails, highlighting the need for behavioral and entropy-based models.

---

## Decision Logic

### Escalate
- Regular low-volume outbound connections  
- Rare or newly observed destination  
- Suspicious process attribution  
- Correlation with prior execution or persistence alerts  

### Monitor
- Regular traffic but destination or process not fully understood  
- No additional malicious indicators  

### Close / False Positive
- Known application behavior  
- Approved infrastructure  
- Documented baseline activity  

---

## Example Decision for This Case

**Decision:** Escalate  

**Rationale:**  
Beaconing pattern observed to a rare domain, attributed to a previously suspicious process, with no business justification.

---

## Lessons Learned

- Regularity is more important than volume in beacon detection  
- Process attribution drastically improves confidence  
- Correlation across endpoint and network telemetry reduces false positives  
- Beaconing detection must account for jittered and stealthy variants
