# Case 011 - Suspicious Mailbox Forwarding / Rule Creation

**Case Type:** Behavioral Detection  
**Difficulty:** SOC L1 → L2  
**Mapped To:** MITRE ATT&CK T1114 / TA0005 (Collection / Initial Access via Mailbox)

---

## Scenario Overview

A user mailbox shows creation of auto-forwarding rules or inbox rules to external addresses, especially personal or unknown domains. This can allow attackers or insiders to silently exfiltrate sensitive information.

**Why it matters:**

- No malware involved; completely “legitimate” in Outlook or Exchange  
- Alerts are subtle and easy to ignore  
- Often associated with business email compromise (BEC) campaigns or insider threats  

**Attacker Perspective:**

- Gain long-term visibility into email communications  
- Redirect sensitive data without touching the endpoint  
- Avoid triggering DLP or endpoint alerts  

---

## Detection Hypothesis (Plain English)

If a mailbox creates forwarding rules to external addresses not approved by company policy, especially after unusual activity (off-hours login, unusual IP), it may indicate **compromise or insider misuse**.

**Assumptions:**

- Legitimate internal forwards are allowed, but external forwards are restricted  
- Rule creation outside business hours is suspicious  
- High-sensitivity mailboxes (finance, legal, IP) are high-risk  

---

## Required Logs

### Exchange / Office 365 Mailbox Audit Logs
- Mailbox rule creation / modification  
- Forwarding to external recipients  

### Authentication Logs
- Login events for mailbox (check IP, location, device)  

### Optional Correlation
- DLP logs for sensitive data sent externally  
- SIEM alerts for unusual logins  

---

## Filtering Logic

**Focus on:**

- External forwarding rules  

**Exclude:**

- Approved internal forwarding  
- IT or shared mailboxes used for business workflow  

**Prioritize:**

- Rules created by standard users  
- Rule creation outside normal hours  
- Multiple rules or high-volume auto-forwards  

---

## Aggregation Logic

**Group by:**

- Mailbox owner  
- Destination email domain  
- Creation time  

**Trigger when:**

- New external forward is created  
- Unusual combination of account, IP, and time window  

---

## Investigation Steps & Pivots

### Audit Logs
- Event: Mailbox rule creation  
- Check target email addresses (external vs internal)  
- Check who created the rule  

### User Context
- Role and business need for external forwarding  
- Any recent unusual activity (off-hours login, new device, impossible travel)  

### Follow-Up Behavior
- Any emails sent immediately after rule creation  
- Large or sensitive attachments automatically forwarded  
- Correlation with DLP or SIEM alerts  

### Threat Intelligence / External Checks
- Are external domains suspicious? Free email services or unknown domains?  

---

## Example Outcomes & Rationale

| Outcome | Scenario | Rationale |
|---------|---------|-----------|
| **True Positive** | User mailbox creates forward to personal@gmail.com late at night; sensitive attachments follow | High-risk; confirms potential insider or compromised account |
| **False Positive** | IT user creates temporary forwarding rule to consultant’s domain for approved project | Legitimate business use; context clears alert |
| **True Negative** | No new forwarding rules created; mailbox behaves normally | Correctly no alert |
| **False Negative** | Attacker creates rule using compromised admin account without triggering mailbox audit | Detection misses; highlights need for monitoring multiple account vectors |

---

## Decision Logic

- **Escalate:** External forward to unapproved domain, off-hours, sensitive mailbox, correlated unusual login  
- **Monitor:** External forward with plausible business justification  
- **Close / False Positive:** Internal-only forwarding, approved workflows  

---

## Lessons Learned

- Not all “alerts” are obvious threats; subtle misconfigurations can be abused  
- Focus on **behavior + context + user role**, not just event type  
- Early detection of insider compromise or BEC can prevent massive data leaks  
- Alerts + investigation steps + attacker mindset = SOC-grade reasoning
