# Case 001 - Suspected Brute Force Authentication Attempt

**Case Type:** Incoming Alert  
**Severity (Initial):** Medium  
**Status:** Investigated → Decision Made    

---

## Alert Summary

An alert was generated indicating multiple failed authentication attempts against a Windows host within a short time window. The failures originated from a single source IP and targeted the same user account.

This pattern may indicate a brute force or password spraying attempt, but could also represent misconfiguration, user error, or automated service behavior.

---

## Detection Hypothesis

If multiple authentication failures occur from the same source against the same account or host within a short time window, this may indicate an attempt to guess credentials through repeated login attempts.

This hypothesis assumes:

- The failures are abnormal for the asset  
- The source is not a known internal service  
- The volume and timing exceed normal user behavior  

---

## Required Logs

Minimum logs required to validate or dismiss the alert:

- **Windows Security Event Log**
  - Event ID **4625** -- Failed logon attempts  

Optional but helpful:

- Event ID **4624** -- Successful logons (to check for follow-on success)
- Asset inventory or CMDB context (host role, owner)

---

## Initial Filtering Logic

To reduce noise and focus on meaningful failures:

**Action**
- Failed authentication only

**Logon Types**
- Network
- Remote (RDP, SMB, WinRM)

**Exclusions**
- Machine accounts (`*$`)
- Known service accounts
- Known internal authentication scanners or management systems

This filtering removes expected background noise and focuses the alert on human-driven or external behavior.

---

## Aggregation Logic

To identify brute-force patterns rather than isolated failures:

- Count failed logon attempts  
- Group by:
  - Source IP
  - Target username  

**Time Window**
- 1 to 5 minutes

**Threshold**
- Tuned over time based on baseline behavior

Aggregation is necessary here because single failed logons are common and low signal.

---

## Investigation Steps and Pivots

Once the alert fired, the following pivots were considered:

### Source Context
- Is the source IP internal or external?
- Does the IP belong to VPN infrastructure, proxy, or cloud provider?
- Has this IP been seen authenticating successfully before?

### Account Context
- Does the target account exist?
- Is it a privileged account or standard user?
- Is the account used interactively or by a service?

### Authentication Outcome
- Any successful logon (4624) following the failures?
- If yes, from the same source IP?

### Lateral Movement Indicators
- Authentication attempts against multiple hosts?
- Same source attempting different accounts?

### Threat Intelligence (Last Step)
- Reputation check on the source IP  
- Used only to add confidence, not to drive the decision

---

## Assessment

The alert represents a plausible brute force attempt, but confidence depends heavily on context:

- External source + repeated failures + follow-on success → **High Risk**
- Internal source + service account + no success → **Likely benign or misconfigured**
- User workstation + mistyped credentials → **False positive**

At this stage, evidence must drive the outcome, not the alert name.

---

## Decision Logic

### Escalate
- External source
- High failure count
- Privileged account
- Any successful authentication observed

### Monitor
- Internal source
- Moderate failure volume
- No successful authentication
- Unclear context

### Close as False Positive
- Known service or admin behavior
- User error confirmed
- Pattern matches baseline behavior

---

## Final Decision (Example Outcome)


### Outcome 1 — True Positive (Confirmed Brute Force)

**Outcome:** True Positive  
**Action:** Escalate → Contain → Reset credentials  

**Rationale:**

- Source IP is external  
- High volume of failed logons within 2 minutes  
- Target account exists and is privileged  
- A successful logon (Event ID 4624) occurred immediately after failures  
- Same source IP used for both failures and success  

This confirms credential guessing followed by successful authentication.  
Detection intent matches reality.

---

### Outcome 2 — False Positive (Benign Activity)

**Outcome:** False Positive  
**Action:** Close → Tune detection  

**Rationale:**

- Source IP is internal  
- Account is a known service account  
- Failures occurred during scheduled task execution  
- No successful interactive logon observed  
- Pattern appears regularly in historical logs  

The alert fired correctly, but contextual evidence invalidated risk.  
This is normal SOC noise, not detection failure.

---

### Outcome 3 — True Negative (Correct Non-Detection)

**Outcome:** True Negative  
**Action:** None  

**Rationale:**

- Multiple failed logons occurred  
- Failures were spread across long time intervals  
- Different source IPs involved  
- User confirmed repeated password typos  
- Volume never crossed aggregation threshold  

The detection did not fire, and this is correct behavior.  
Alerting here would only increase analyst fatigue.

---

### Outcome 4 — False Negative (Missed Attack)

**Outcome:** False Negative  
**Action:** Detection gap identified → Improve logic  

**Rationale:**

- Attacker used a low-and-slow approach  
- Failures spread across a long time window  
- Each burst stayed below aggregation threshold  
- Same source IP eventually authenticated successfully  
- No alert triggered due to aggressive tuning  

The attack succeeded, but the detection model failed to catch it.


---

## Lessons Learned

- Brute force detection is highly context-dependent
- Aggregation without asset context leads to noise
- Successful authentication after failures dramatically changes severity
- Threat intelligence should support conclusions, not replace analysis
