# Case 010 - Abnormal Scheduled Credential Use via Legacy Protocol

**Case Type:** Behavioral Detection  
**Difficulty:** SOC L1 → L2  
**Mapped To:** MITRE ATT&CK T1078 / TA0006 (Valid Accounts / Credential Access)

---

## Scenario Overview

A workstation or service account is observed making automated logins over a legacy protocol (e.g., IMAP, POP3, SMBv1, or Basic Authentication) outside of normal business hours.  

The frequency is unusual for the account, and the destination or target is uncommon.

**Attacker Perspective:**

- Steal or reuse valid credentials without triggering standard MFA  
- Use legacy protocols to bypass modern security controls  
- Schedule repeated automated access to sensitive data  

**Why it matters:**

- Alerts are subtle; legacy protocols generate noisy but low-signal logs  
- SOCs often ignore “normal-looking” scheduled logins  
- Can indicate early-stage compromise or insider misuse  

---

## Detection Hypothesis

If a user account performs scheduled or automated logins over legacy protocols outside normal usage patterns, it may indicate **credential abuse or potential compromise**.

**Assumptions:**

- Business systems rarely require legacy protocol automation  
- Regular users rarely log in via IMAP/POP/SMBv1 at night  
- Sudden spikes or off-hours access from endpoints or unusual locations are high-signal  

---

## Required Logs

### Authentication / AD Logs
- **Event ID 4624** — Successful logon  
- **Event ID 4625** — Failed logon attempts  

### Network / Proxy / Mail Logs
- IMAP/POP/SMB authentication attempts  
- Source IP, destination, protocol  

### Optional Endpoint Logs
- Scheduled task or script execution logs  

---

## Filtering Logic

**Focus on:**

- Off-hours login activity  
- Legacy / less-secure protocols  

**Exclude:**

- Known backup accounts  
- Service accounts with scheduled business tasks  
- Expected remote access patterns  

**Prioritize:**

- High-frequency logins from the same account  
- Access to sensitive mailboxes or file shares  
- First-time access to specific endpoints  

---

## Aggregation Logic

**Group by:**

- User account  
- Source IP / Host  
- Protocol  

**Measure:**

- Number of logins per hour  
- Timing pattern consistency  

**Trigger when:**

- Volume or frequency exceeds baseline  
- Logins occur outside business hours  
- New source location is used  

---

## Investigation Steps & Pivots

### Authentication Logs
- Identify account, host, and time of logins  
- Check success vs failure patterns  

### Protocol / Source Analysis
- Confirm protocol (legacy vs modern)  
- Identify source IP / endpoint  

### User Context
- Check user role and normal working hours  
- Any recent changes in role or remote work pattern  

### Follow-On Behavior
- Any subsequent file access, download, or email activity?  
- Correlation with other alerts (PowerShell, service creation, persistence)?  

### Threat Intelligence / External Correlation
- Is the destination known for data exfiltration?  
- Any anomalies in location or ISP?  

---

## Example Outcomes & Rationale

| Outcome | Scenario | Rationale |
|---------|---------|-----------|
| **True Positive** | Standard user account logs in via POP3 at 3 AM to a rarely used mailbox from an endpoint previously unseen | Suspicious scheduled credential use; potential account compromise |
| **False Positive** | Backup account performs off-hours login to archive mailbox | Legitimate automated behavior; documentation clears alert |
| **True Negative** | User logs in during business hours via approved modern protocols | No detection triggered; expected behavior |
| **False Negative** | Attacker uses scheduled legacy protocol access but spreads logins over multiple endpoints to evade thresholds | Detection threshold missed; highlights coverage gap |

---

## Decision Logic

- **Escalate:** Off-hours legacy protocol login, unusual endpoint, frequency deviation, sensitive resource access  
- **Monitor:** Off-hours login but low-risk mailbox / known host / service account  
- **Close / False Positive:** Documented automation, backup account, or approved scheduled tasks  

---

## Lessons Learned

- Legacy protocols are often overlooked but abused for credential theft  
- Scheduled or automated activity deviating from baseline is high-signal  
- Small deviations can indicate early-stage compromise  
- Alerts alone are not incidents; context is critical
