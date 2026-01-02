# Case 006 - Anomalous Data Exfiltration via Legitimate Channel

**Case Type:** Incoming Alert  
**Severity (Initial):** Medium  
**Status:** Investigated → Decision Made  

---

## Alert Summary

An alert was generated for unusually high outbound data transfer from a user workstation to an external cloud storage service. The destination is a legitimate and commonly used platform, but the volume and timing of the transfer deviate from the user’s historical behavior.

Such activity may indicate data exfiltration, but could also represent legitimate business use such as backups, large uploads, or data migration.

---

## Detection Hypothesis

If a host or user transfers an unusually large volume of data to an external destination using legitimate protocols or services, and the activity deviates from established baseline behavior, it may indicate data exfiltration.

**Assumptions:**

- Attackers often exfiltrate data using trusted services to blend in  
- Volume, timing, and user context are stronger signals than destination alone  
- Legitimate tools can still be abused  

---

## Required Logs

**Minimum logs required for investigation:**

- **Network logs**
  - Firewall, proxy, or secure web gateway logs  

- **Endpoint telemetry**
  - Process execution logs  
  - File access logs (if available)  

- **Authentication logs**
  - To confirm user identity and session timing  

**Optional context:**

- Data classification policies  
- User role and department  
- Historical transfer baselines  

---

## Filtering Logic

To reduce noise:

- Focus on outbound data transfers  

**Exclude:**
- Known backup servers  
- Approved data transfer jobs  
- Scheduled sync services on approved systems  

**Prioritize:**
- User workstations  
- Upload actions vs downloads  
- Transfers outside business hours  

---

## Aggregation Logic

Detection relies on **baseline deviation**, not absolute thresholds.

**Aggregate by:**
- User  
- Host  
- Destination service  

**Measure:**
- Total bytes uploaded  
- Duration of transfer  
- Frequency over time  

**Trigger when:**
- Upload volume exceeds the user’s historical baseline  
- Activity occurs at unusual times  
- New destination or service is used  

---

## Investigation Steps and Pivots

### 1. User Context
- Role and department  
- Is this user expected to handle large datasets?  
- Any recent role change or offboarding indicators?  

### 2. Data Characteristics
- Types of files accessed or transferred  
- Sensitive or classified data involved?  
- Sudden access to a large number of files?  

### 3. Destination Analysis
- Is the service approved?  
- Personal vs corporate account?  
- First-time use by this user?  

### 4. Process Attribution
- Which application performed the upload?  
- Browser-based vs sync client vs script?  
- Any prior suspicious execution tied to this process?  

### 5. Timing & Behavior
- Business hours vs off-hours  
- One-time spike vs sustained behavior  
- Correlation with other alerts (PowerShell, persistence, beaconing)  

### 6. Threat Intelligence (Last)
- Mostly irrelevant for legitimate platforms  
- Only useful if destination infrastructure itself is suspicious  

---

## Example Outcomes

### Outcome 1 — True Positive

**Scenario:**  
User uploads a large volume of sensitive documents to a personal cloud storage account late at night shortly before resignation.

**Rationale:**  
Volume deviation, timing, destination ownership, and user context indicate intentional data exfiltration.

---

### Outcome 2 — False Positive

**Scenario:**  
A developer uploads a large dataset to approved cloud storage for a legitimate project.

**Rationale:**  
Behavior is unusual but justified by role and project context.

---

### Outcome 3 — True Negative

**Scenario:**  
Regular cloud sync activity from an approved endpoint within expected volume ranges.

**Rationale:**  
Detection does not trigger; baseline holds.

---

### Outcome 4 — False Negative

**Scenario:**  
An attacker slowly exfiltrates data in small chunks over an extended period.

**Rationale:**  
Volume-based detection fails, highlighting the need for long-term behavioral monitoring.

---

## Decision Logic

### Escalate
- Sensitive data involved  
- Personal or unapproved destination  
- Off-hours activity  
- User role does not justify behavior  

### Monitor
- Unusual but plausible business justification  
- One-time spike with no additional indicators  

### Close / False Positive
- Approved process  
- Expected user behavior  
- Documented project activity  

---

## Example Decision for This Case

**Decision:** Escalate  

**Rationale:**  
Significant deviation from baseline combined with sensitive file access and an unapproved external destination.

---

## Lessons Learned

- Legitimate services are common exfiltration paths  
- Volume alone is insufficient without context  
- User role and timing dramatically affect severity  
- Slow exfiltration remains a major detection challenge
