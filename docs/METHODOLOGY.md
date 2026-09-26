\# Cyberion ThreatShield — Methodology



\## 1. Purpose



This document describes the methodology followed during the Cyberion ThreatShield detection engineering and threat hunting engagement.



The methodology covers:



\- Log analysis

\- Detection engineering

\- MITRE ATT\&CK mapping

\- Threat hunting

\- Incident investigation

\- Detection tuning

\- IOC research

\- Incident-response playbook development



\---



\## 2. Data Sources



The primary dataset used for the engagement was the supplied:



`EVTX-ATTACK-SAMPLES`



The dataset contains Windows event-log samples organized across multiple ATT\&CK-related categories.



The analysis focused on Windows telemetry including:



\- Windows Security events

\- PowerShell Script Block Logging

\- Sysmon process events

\- Sysmon network events

\- Sysmon file events

\- Other Windows event telemetry available in the dataset



\---



\## 3. Log Analysis Process



The investigation began by parsing and examining the available EVTX metadata and event records.



The analysis included:



1\. Identifying available event fields.

2\. Reviewing Event IDs.

3\. Examining Windows telemetry sources.

4\. Counting events by tactic and event type.

5\. Identifying high-value security events.

6\. Reviewing filenames and associated ATT\&CK tactics.

7\. Selecting behaviors suitable for detection engineering and threat hunting.



Python and pandas were used to support dataset analysis.



\---



\## 4. Field Analysis



Relevant fields examined during analysis included:



\- EventID

\- EventRecordID

\- Channel

\- ProviderName

\- Computer

\- ProcessName

\- ParentProcessName

\- ProcessId

\- ParentProcessId

\- CommandLine

\- SubjectUserName

\- TargetUserName

\- SourceIp

\- DestinationIp

\- SourcePort

\- DestinationPort

\- Image

\- ParentImage

\- TargetFilename

\- ServiceName

\- TaskName

\- ScriptBlockText

\- Hashes

\- PipeName

\- ShareName

\- EVTX\_FileName

\- EVTX\_Tactic



These fields were used to identify behavioral patterns and construct detection logic.



\---



\## 5. Detection Engineering Methodology



Detection development followed this process:



1\. Select a security behavior.

2\. Identify the relevant telemetry.

3\. Identify useful event fields.

4\. Determine the applicable MITRE ATT\&CK technique.

5\. Draft the Sigma detection.

6\. Define the detection selection and condition.

7\. Assign severity.

8\. Document potential false positives.

9\. Validate the Sigma rule.

10\. Add the rule to the ATT\&CK coverage matrix.



The detection rules were designed around observable behavior rather than relying only on individual filenames or static indicators.



\---



\## 6. MITRE ATT\&CK Mapping



MITRE ATT\&CK techniques were selected based on the behavior represented by the available telemetry.



Examples included:



\- T1059.001 — PowerShell

\- T1003.001 — LSASS Memory

\- T1021.001 — Remote Services: Remote Desktop Protocol

\- T1021.002 — SMB/Windows Admin Shares

\- T1053.005 — Scheduled Task/Job

\- T1033 — System Owner/User Discovery

\- T1547.001 — Registry Run Keys / Startup Folder

\- T1543.003 — Windows Service

\- T1112 — Modify Registry

\- T1129 — Shared Modules



Mappings were refined when the available dataset evidence provided more specific behavioral context.



\---



\## 7. Threat Hunting Methodology



Threat hunting followed a hypothesis-driven approach.



\### Hunt Process



1\. Define a threat hypothesis.

2\. Identify relevant telemetry.

3\. Filter the dataset to the required events.

4\. Search for suspicious behavioral indicators.

5\. Correlate related events.

6\. Review supporting evidence.

7\. Document findings.

8\. Identify detection opportunities.



Two primary hunts were completed:



\- PowerShell credential access and LSASS activity

\- RDP tunneling and remote-access tampering



\---



\## 8. Incident Investigation Methodology



Incident investigations were performed using available event evidence and timelines.



The investigation process included:



1\. Identify the triggering event.

2\. Collect related events.

3\. Build a chronological timeline.

4\. Identify relevant processes and users.

5\. Map observed behavior to ATT\&CK.

6\. Assess potential impact.

7\. Identify detection opportunities.

8\. Document containment and response actions.

9\. Clearly distinguish observed evidence from assumptions.



The investigations covered:



\- PowerShell LSASS memory-dump activity

\- PowerShell credential-collection activity



\---



\## 9. Correlation Methodology



Multiple related events were correlated to provide additional investigation context.



The correlation approach considered:



\- Hostname

\- User context

\- Timestamp

\- Process

\- Parent process

\- Command line

\- Network information

\- File activity

\- Authentication activity



Three correlation scenarios were documented:



1\. PowerShell credential access chain

2\. RDP tunneling and remote-access chain

3\. LSASS access to dump-file creation chain



\---



\## 10. Detection Tuning Methodology



Detection tuning followed these steps:



1\. Review the initial rule.

2\. Identify overly broad conditions.

3\. Examine actual dataset telemetry.

4\. Identify fields providing stronger behavioral context.

5\. Add specific conditions.

6\. Consider legitimate use cases.

7\. Document potential false positives.

8\. Validate the updated rule.



Three rules were tuned:



\- SMB Windows Admin Share Access

\- RDP Network Connection

\- Windows User Discovery via Whoami



\---



\## 11. IOC Research Methodology



IOC research focused on observable indicators found during the investigation.



The research included:



\- PowerShell command patterns

\- LSASS-related strings

\- Suspected dump-file names

\- RDP-related tools

\- Network ports

\- Administrative shares

\- Windows discovery commands



Indicators were documented together with their associated telemetry and ATT\&CK context.



An indicator was not automatically treated as malicious without supporting investigation evidence.



\---



\## 12. Incident Response Methodology



Response playbooks were developed using the following lifecycle:



\*\*Detect → Validate → Investigate → Contain → Eradicate → Recover → Document\*\*



Three playbooks were developed for:



1\. LSASS credential-dump activity

2\. Suspicious PowerShell credential collection

3\. RDP tunneling and remote access



The playbooks include investigation steps, evidence collection, containment, recovery, detection opportunities, and escalation criteria.



\---



\## 13. Validation



Sigma rules were locally validated using Sigma CLI.



Validation focused on:



\- Rule syntax

\- Detection conditions

\- Required fields

\- Rule structure



The local validation was completed with the online ATT\&CK metadata check excluded because the external metadata lookup was unavailable during validation.



\---



\## 14. Documentation and Reproducibility



Project artifacts were organized into dedicated directories:



\- `detections/`

\- `hunts/`

\- `incidents/`

\- `playbooks/`

\- `correlations/`

\- `docs/`

\- `data/`

\- `reports/`



The project was version-controlled using Git and maintained in GitHub.



Dataset files were excluded from Git tracking through `.gitignore`.



\---



\## 15. Limitations



The analysis was performed using the supplied EVTX-ATTACK-SAMPLES dataset.



Therefore:



\- Findings represent observations within the dataset.

\- Dataset observations do not establish a real-world compromise.

\- Root cause may not be determinable from the available telemetry.

\- Attacker identity cannot be established from the dataset alone.

\- Successful credential theft cannot be assumed without supporting evidence.

\- Detection performance in a production SIEM was not evaluated.



\---



\## 16. Expected Outcome



The methodology provides a repeatable process for transforming Windows security telemetry into:



\- Sigma detection rules

\- MITRE ATT\&CK coverage

\- Threat hunts

\- Incident investigations

\- Correlation logic

\- Detection tuning

\- IOC research

\- Incident-response playbooks



The overall workflow supports structured SOC detection engineering and threat-hunting activities.

