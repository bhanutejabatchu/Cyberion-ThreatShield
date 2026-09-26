\# PLAYBOOK-02: Suspicious Credential Collection Response



\## 1. Purpose



This playbook provides a structured response procedure for investigating suspected credential-collection activity performed through PowerShell.



It supports SOC analysts during alert validation, evidence collection, investigation, containment, recovery, and documentation.



\---



\## 2. Trigger Conditions



Start this playbook when PowerShell activity contains suspicious credential-collection behavior such as:



\- `PromptForCredential`

\- `Get-Credential`

\- `GetNetworkCredential()`

\- `ValidateCredentials()`



Relevant MITRE ATT\&CK technique:



\- T1059.001 — PowerShell



The presence of these commands should be investigated in context. The alert alone does not prove that credentials were successfully stolen.



\---



\## 3. Initial Triage



The SOC analyst should:



1\. Record the hostname of the affected system.

2\. Record the alert timestamp.

3\. Identify the user account involved.

4\. Identify the PowerShell process and parent process.

5\. Review the PowerShell Script Block Logging event.

6\. Identify the exact commands or script content involved.

7\. Check for related authentication or network activity.

8\. Search for additional alerts involving the same host or account.



\---



\## 4. Evidence Collection



Collect and preserve the following information.



\### PowerShell Logs



Review:



\- Event ID 4104 — PowerShell Script Block Logging

\- PowerShell command content

\- Script execution timestamp

\- EventRecordID



\### Process Information



Record:



\- Process name

\- Process ID

\- Parent Process ID

\- Parent process name

\- Command line

\- User account



\### Authentication Information



Where available, review:



\- Successful logons

\- Failed logons

\- Target username

\- Source IP address

\- Logon type

\- Related authentication events



\---



\## 5. Investigation Procedure



\### Step 1 — Validate the Detection



Review the Event ID 4104 event and confirm whether credential-related PowerShell commands are present.



\### Step 2 — Identify Credential-Collection Behavior



Look for commands or functions such as:



\- `PromptForCredential`

\- `Get-Credential`

\- `GetNetworkCredential()`

\- `ValidateCredentials()`



\### Step 3 — Identify the User Context



Determine which account executed the PowerShell activity.



\### Step 4 — Review Related Events



Check activity before and after the triggering event for:



\- Process creation

\- Logon events

\- Additional PowerShell execution

\- Network connections

\- Other credential-access activity



\### Step 5 — Determine Scope



Search for the same:



\- Hostname

\- Username

\- PowerShell command

\- Script pattern

\- Indicators



across the available dataset.



\---



\## 6. Containment



If the activity is determined to be unauthorized:



1\. Isolate the affected endpoint according to the organization's incident-response procedure.

2\. Preserve relevant evidence.

3\. Prevent further execution of the suspicious script.

4\. Review potentially affected accounts.

5\. Reset credentials when exposure is confirmed or required by organizational policy.

6\. Escalate to the incident-response team when appropriate.



\---



\## 7. Eradication and Recovery



After containment:



1\. Remove unauthorized scripts or tools identified during investigation.

2\. Check for persistence mechanisms.

3\. Review other systems for the same indicators.

4\. Reset potentially exposed credentials according to policy.

5\. Restore affected systems using approved procedures.

6\. Continue monitoring for repeated credential-collection activity.



\---



\## 8. Detection Opportunities



Recommended detection opportunities include:



\- PowerShell Event ID 4104 containing `PromptForCredential`.

\- PowerShell Event ID 4104 containing `Get-Credential`.

\- PowerShell Event ID 4104 containing `GetNetworkCredential()`.

\- PowerShell Event ID 4104 containing `ValidateCredentials()`.

\- Correlation of suspicious PowerShell credential collection with unusual authentication activity.



\---



\## 9. Evidence From Cyberion Dataset



During the Cyberion ThreatShield investigation, the dataset contained PowerShell Event ID 4104 activity associated with credential collection.



Observed indicators included:



\- `PromptForCredential`

\- `Get-Credential`

\- `GetNetworkCredential()`

\- `ValidateCredentials()`



The activity was observed in:



`phish\_windows\_credentials\_powershell\_scriptblockLog\_4104.evtx`



Two related Event ID 4104 records were observed in the sample.



The activity was documented as suspicious credential-collection behavior.



This observation comes from the supplied EVTX dataset and does not by itself establish successful credential theft, attacker identity, initial access, or system compromise.



\---



\## 10. Analyst Documentation



The analyst should document:



\- Alert ID

\- Hostname

\- Username

\- Timestamp

\- Event ID

\- EventRecordID

\- PowerShell process

\- Parent process

\- Command or script content

\- Related authentication events

\- Investigation findings

\- Containment actions

\- Recovery actions

\- Final disposition



\---



\## 11. Escalation Criteria



Escalate the investigation when:



\- Credential collection appears unauthorized.

\- Credentials may have been exposed.

\- Additional suspicious activity is identified.

\- Multiple systems show the same behavior.

\- The same account appears across multiple suspicious events.

\- The analyst cannot determine whether the activity is legitimate.



\---



\## 12. Expected Outcome



The objective of this playbook is to provide a repeatable process for:



\*\*Detect → Validate → Investigate → Contain → Eradicate → Recover → Document\*\*



The playbook should help SOC analysts consistently investigate suspicious PowerShell credential-collection activity while preserving relevant evidence.

