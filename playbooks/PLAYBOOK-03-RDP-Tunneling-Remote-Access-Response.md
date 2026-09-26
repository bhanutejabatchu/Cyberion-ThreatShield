\# PLAYBOOK-03: RDP Tunneling \& Remote Access Response



\## 1. Purpose



This playbook provides a structured procedure for investigating suspicious Remote Desktop Protocol (RDP) activity, tunneling, port forwarding, and unauthorized changes that may enable remote access.



It supports SOC analysts during detection validation, investigation, containment, recovery, and documentation.



\---



\## 2. Trigger Conditions



Start this playbook when one or more of the following are observed:



\- Suspicious process activity involving RDP or port forwarding.

\- `plink.exe` forwarding traffic toward TCP port 3389.

\- `netsh.exe` configuring port forwarding involving port 3389.

\- RDP-related configuration or tooling changes.

\- RDPWrap installation or execution.

\- Firewall changes that allow inbound RDP traffic.

\- Suspicious RDP logon activity combined with related process or network activity.



Relevant MITRE ATT\&CK techniques observed in the investigation include:



\- T1021.001 — Remote Services: Remote Desktop Protocol

\- T1090 — Proxy



The exact technique mapping should be validated against the specific evidence available during an investigation.



\---



\## 3. Initial Triage



The SOC analyst should:



1\. Record the affected hostname.

2\. Record the alert timestamp.

3\. Identify the user account involved.

4\. Identify the process that generated the activity.

5\. Review the command line.

6\. Identify source and destination IP addresses where available.

7\. Identify network ports involved.

8\. Review related RDP authentication events.

9\. Check for firewall or configuration changes.

10\. Search for additional related activity around the same timestamp.



\---



\## 4. Evidence Collection



Collect and preserve the following information.



\### Process Information



Record:



\- Process name

\- Process ID

\- Parent Process ID

\- Parent process name

\- Command line

\- User account

\- Process creation timestamp



\### Network Information



Record:



\- Source IP

\- Destination IP

\- Source port

\- Destination port

\- Protocol

\- Connection timestamp



Pay particular attention to TCP port:



`3389`



\### RDP Information



Review available:



\- Successful RDP logons

\- RDP connection events

\- Remote Desktop configuration changes

\- RDP-related services

\- RDP-related tools



\### Firewall Information



Review commands or events associated with:



\- `netsh`

\- Windows Firewall rules

\- Inbound TCP 3389 access



\---



\## 5. Investigation Procedure



\### Step 1 — Validate the Detection



Review the triggering process or network event and determine why it was detected as suspicious.



\### Step 2 — Identify Port Forwarding



Look for commands involving:



\- `plink.exe`

\- `netsh`

\- Port forwarding

\- TCP 3389



Document the source and destination of the forwarding activity.



\### Step 3 — Review RDP Activity



Check for successful RDP logons and related Remote Desktop events.



Determine whether the account, source system, and timing are expected.



\### Step 4 — Review RDP-Related Tools



Investigate suspicious tools such as RDPWrap when present.



Determine:



\- How the tool was executed

\- Which user executed it

\- When it was executed

\- Whether related configuration changes occurred



\### Step 5 — Review Firewall Changes



Investigate commands that create or modify firewall rules allowing inbound RDP access.



\### Step 6 — Correlate Events



Build a timeline connecting:



\- Process creation

\- Port forwarding

\- RDP activity

\- RDP-related tooling

\- Firewall modification

\- Authentication events



\### Step 7 — Determine Scope



Search for the same indicators across available logs and identify whether similar activity occurred on other systems.



\---



\## 6. Containment



If the activity is determined to be unauthorized:



1\. Isolate the affected endpoint according to the organization's incident-response procedure.

2\. Preserve relevant evidence.

3\. Disable unauthorized remote-access mechanisms.

4\. Remove or disable unauthorized port-forwarding configurations.

5\. Review and restrict suspicious firewall rules.

6\. Review potentially compromised accounts.

7\. Escalate to the incident-response team when required.



\---



\## 7. Eradication and Recovery



After containment:



1\. Remove unauthorized RDP-related tools.

2\. Remove unauthorized port-forwarding configurations.

3\. Review Remote Desktop configuration.

4\. Review firewall rules for unauthorized changes.

5\. Check for persistence mechanisms.

6\. Review other systems for the same indicators.

7\. Reset credentials when exposure is confirmed or required by policy.

8\. Restore approved remote-access configuration.

9\. Continue monitoring for recurrence.



\---



\## 8. Detection Opportunities



Recommended detection opportunities include:



\- Process creation involving `plink.exe` with RDP-related port forwarding.

\- `netsh.exe` commands involving port forwarding.

\- Process creation involving RDPWrap.

\- Firewall rule creation allowing inbound TCP 3389.

\- Successful RDP logons correlated with suspicious process activity.

\- RDP network connections to TCP port 3389.

\- Correlation of remote-access tooling, port forwarding, and firewall changes.



\---



\## 9. Evidence From Cyberion Dataset



During Threat Hunt #2, the supplied EVTX dataset contained several events associated with RDP tunneling and remote-access tampering.



Observed activity included:



\- `plink.exe` reverse forwarding toward RDP port 3389.

\- `netsh.exe` port-forwarding activity involving port 3389.

\- RDPWrap installation or execution.

\- `netsh advfirewall` activity adding an inbound TCP 3389 rule.

\- `cmd.exe` launching an RDPWrap installer.



These observations were correlated as suspicious RDP tunneling or remote-access tampering activity within the supplied dataset.



The dataset evidence does not by itself establish a real-world compromise, attacker identity, or successful unauthorized remote access.



\---



\## 10. Analyst Documentation



The analyst should document:



\- Alert ID

\- Hostname

\- Username

\- Timestamp

\- Process name

\- Process ID

\- Parent process

\- Command line

\- Source IP

\- Destination IP

\- Source port

\- Destination port

\- Related RDP events

\- Firewall changes

\- Investigation findings

\- Containment actions

\- Recovery actions

\- Final disposition



\---



\## 11. Escalation Criteria



Escalate the investigation when:



\- Unauthorized RDP access is suspected.

\- Port forwarding is confirmed without an approved business purpose.

\- RDP-related tools are installed or executed without authorization.

\- Firewall rules are modified to enable remote access.

\- Suspicious RDP authentication is correlated with other attack activity.

\- Multiple systems show the same indicators.

\- The analyst cannot determine whether the activity is legitimate.



\---



\## 12. Expected Outcome



The objective of this playbook is to provide a repeatable process for:



\*\*Detect → Validate → Investigate → Contain → Eradicate → Recover → Document\*\*



The playbook should help SOC analysts consistently investigate suspicious RDP tunneling and remote-access activity while preserving relevant evidence.

