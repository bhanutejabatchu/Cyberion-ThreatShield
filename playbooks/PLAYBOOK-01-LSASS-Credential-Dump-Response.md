\# PLAYBOOK-01: LSASS Credential Dump Response



\## 1. Purpose



This playbook provides a structured response procedure for detecting and investigating suspected LSASS credential-dumping activity on Windows systems.



The playbook is designed to support SOC analysts during initial triage, evidence collection, containment, and recovery.



\---



\## 2. Trigger Conditions



Start this playbook when one or more of the following detections occur:



\- PowerShell accesses the `lsass.exe` process.

\- PowerShell Script Block Logging (Event ID 4104) contains:

&#x20; - `Get-Process lsass`

&#x20; - `MiniDumpWriteDump`

&#x20; - `MiniDumpWithFullMemory`

\- A file is created with a name associated with an LSASS memory dump.

\- A process accesses `lsass.exe` and generates a high-severity detection.



Relevant MITRE ATT\&CK technique:



\- T1003.001 — LSASS Memory



\---



\## 3. Initial Triage



The SOC analyst should:



1\. Record the hostname and affected system.

2\. Record the alert timestamp.

3\. Identify the user account associated with the activity.

4\. Identify the process that accessed `lsass.exe`.

5\. Review the command line and PowerShell Script Block contents.

6\. Check whether a memory-dump file was created.

7\. Identify the parent process and related process activity.

8\. Check for other alerts occurring around the same timestamp.



\### Important



The presence of an LSASS-related event should be treated as suspicious activity requiring investigation. The alert alone does not prove that credentials were successfully extracted.



\---



\## 4. Evidence Collection



Collect and preserve the following information:



\### Windows Event Logs



\- Security Event Logs

\- PowerShell Script Block Logging

\- Sysmon logs, if available



\### Process Information



\- Process name

\- Process ID

\- Parent Process ID

\- Parent process name

\- Command line

\- User account



\### File Information



Search for possible dump files such as:



\- `lsass.dmp`

\- `lsass.exe\_\*`

\- `dumpert.dmp`

\- `minidump\_\*`



Record:



\- File path

\- Creation time

\- File hash

\- File size



\---



\## 5. Investigation Procedure



\### Step 1 — Validate the Detection



Review the triggering event and confirm whether the activity contains LSASS access or memory-dump behavior.



\### Step 2 — Identify the Process



Determine which process initiated the access to `lsass.exe`.



\### Step 3 — Review PowerShell Activity



If PowerShell is involved, inspect Event ID 4104 for commands or scripts related to memory dumping.



\### Step 4 — Check for Dump Files



Search the host for recently created LSASS dump files.



\### Step 5 — Build a Timeline



Correlate:



\- Process creation

\- PowerShell activity

\- LSASS access

\- File creation

\- User logon activity

\- Related network activity



\### Step 6 — Look for Related Activity



Check for additional indicators such as credential access, lateral movement, suspicious PowerShell execution, or other security alerts.



\---



\## 6. Containment



If the investigation identifies suspicious or unauthorized activity:



1\. Isolate the affected endpoint according to the organization's incident-response procedure.

2\. Preserve relevant evidence before making destructive changes where possible.

3\. Disable or reset potentially exposed credentials according to organizational policy.

4\. Prevent further execution of the identified malicious process or tool.

5\. Escalate the incident to the appropriate incident-response team.



\---



\## 7. Eradication and Recovery



After containment:



1\. Remove unauthorized tools or files identified during the investigation.

2\. Verify that persistence mechanisms have not been created.

3\. Review other endpoints for the same indicators.

4\. Reset credentials where exposure is confirmed or required by policy.

5\. Restore affected systems using approved recovery procedures.

6\. Continue monitoring for recurrence.



\---



\## 8. Detection Opportunities



Recommended detections include:



\- PowerShell Event ID 4104 containing `MiniDumpWriteDump`.

\- PowerShell access to `lsass.exe`.

\- Sysmon Event ID 10 targeting `lsass.exe`.

\- Sysmon Event ID 11 creating suspected LSASS dump files.

\- Correlation of LSASS access followed by dump-file creation.



\---



\## 9. Evidence From Cyberion Dataset



During the Cyberion ThreatShield investigation, the dataset contained a PowerShell Script Block Logging event associated with LSASS memory-dump behavior.



Observed indicators included:



\- `Get-Process lsass`

\- `MiniDumpWriteDump`

\- `MiniDumpWithFullMemory`



The dataset sample was mapped to:



\*\*MITRE ATT\&CK T1003.001 — LSASS Memory\*\*



This observation comes from the supplied EVTX dataset and does not by itself establish a real-world compromise or successful credential extraction.



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

\- Relevant Event IDs

\- File paths and hashes

\- Investigation findings

\- Containment actions

\- Recovery actions

\- Final disposition



\---



\## 11. Escalation Criteria



Escalate to incident response when:



\- LSASS access is confirmed as unauthorized.

\- A suspicious memory dump is created.

\- Credential exposure is suspected.

\- Additional attack activity is identified.

\- Multiple systems show related indicators.

\- The analyst cannot determine whether the activity is legitimate.



\---



\## 12. Expected Outcome



The objective of this playbook is to provide a repeatable process for:



\*\*Detect → Validate → Investigate → Contain → Eradicate → Recover → Document\*\*



The playbook should help SOC analysts consistently handle suspected LSASS credential-dumping activity while preserving investigation evidence.

