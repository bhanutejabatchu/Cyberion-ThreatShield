\# Cyberion ThreatShield

\## Detection Engineering \& Threat Hunting Engagement



\---



\## 1. Executive Summary



Cyberion ThreatShield is a detection engineering and threat hunting engagement focused on Windows security telemetry.



The project used the supplied EVTX-ATTACK-SAMPLES dataset to develop practical SOC-oriented detection content, perform structured threat hunts, investigate suspicious activity, create correlation logic, tune detections, research indicators, and develop incident-response playbooks.



The project produced 15 Sigma detection rules, an ATT\&CK coverage matrix, two threat hunts, two incident investigations, three correlation rules, three tuned detections, IOC research, and three incident-response playbooks.



All project artifacts are maintained in Git and hosted in the project GitHub repository.



\---



\## 2. Project Objectives



The project objectives were to:



\- Analyze Windows security telemetry.

\- Identify security-relevant behaviors.

\- Develop Sigma detection rules.

\- Map detections to MITRE ATT\&CK.

\- Perform structured threat hunting.

\- Investigate suspicious activity.

\- Develop incident-response playbooks.

\- Research indicators of compromise.

\- Tune detection logic.

\- Document false-positive considerations.

\- Maintain reproducible project documentation.



\---



\## 3. Scope



\### In Scope



\- Windows EVTX security telemetry

\- PowerShell logging

\- Sysmon telemetry

\- Windows Security events

\- Sigma detection engineering

\- MITRE ATT\&CK mapping

\- Threat hunting

\- Incident investigation

\- Detection correlation

\- Detection tuning

\- IOC research

\- Incident-response playbooks

\- Documentation



\### Out of Scope



\- Custom application development

\- Production SIEM deployment

\- Live production monitoring

\- Real-world endpoint deployment

\- Live organizational logs



The analysis was performed using the supplied dataset.



\---



\## 4. Tools and Technologies



The project used:



\- Python

\- pandas

\- Jupyter Notebook

\- Sigma

\- Sigma CLI

\- MITRE ATT\&CK

\- Windows Event Logs

\- Sysmon

\- Git

\- GitHub

\- Markdown

\- PowerShell



\---



\## 5. Dataset Analysis



The primary dataset used was:



`EVTX-ATTACK-SAMPLES`



The dataset contains Windows event-log samples organized across ATT\&CK-related categories.



The analysis identified telemetry including:



\- Windows Security events

\- PowerShell Script Block Logging

\- Sysmon process creation

\- Sysmon network connections

\- Sysmon file creation

\- Sysmon process access

\- Registry activity

\- Authentication activity



Python and pandas were used to inspect the dataset and identify useful fields, event IDs, tactics, and security behaviors.



\---



\## 6. Data Dictionary



Important fields analyzed included:



| Field | Purpose |

|---|---|

| EventID | Windows/Sysmon event identifier |

| EventRecordID | Unique event record reference |

| Channel | Windows event-log channel |

| ProviderName | Event provider |

| Computer | Hostname |

| ProcessName | Process associated with event |

| ParentProcessName | Parent process |

| ProcessId | Process identifier |

| ParentProcessId | Parent process identifier |

| CommandLine | Process command line |

| SubjectUserName | User associated with event |

| TargetUserName | Target account |

| SourceIp | Source IP address |

| DestinationIp | Destination IP address |

| SourcePort | Source network port |

| DestinationPort | Destination network port |

| Image | Process image |

| ParentImage | Parent process image |

| TargetFilename | File target |

| ServiceName | Windows service |

| TaskName | Scheduled task |

| ScriptBlockText | PowerShell script content |

| Hashes | File/process hashes |

| PipeName | Named pipe |

| ShareName | Network share |

| EVTX\_FileName | Source EVTX file |

| EVTX\_Tactic | Associated tactic |



\---



\## 7. Detection Engineering



A total of 15 Sigma detection rules were developed.



\### Detection Rules



| # | Detection | ATT\&CK | Event ID | Severity |

|---|---|---|---|---|

| 1 | PowerShell Credential Collection | T1059.001 | 4104 | High |

| 2 | PowerShell LSASS Memory Dump | T1003.001 | 4104 | High |

| 3 | Scheduled Task Creation | T1053.005 | 4698 | Medium |

| 4 | RDP Successful Logon | T1021.001 | 4624 | Medium |

| 5 | SMB Windows Admin Share Access | T1021.002 | 5145 | Medium |

| 6 | Windows DLL Module Load | T1129 | 7 | Medium |

| 7 | PowerShell Script Block Logging | T1059.001 | 4104 | Low |

| 8 | Windows User Discovery via Whoami | T1033 | 1 | Medium |

| 9 | RDP Network Connection | T1021.001 | 3 | Medium |

| 10 | Windows Command Shell Execution | T1059.003 | 1 | Medium |

| 11 | LSASS Memory Dump File Creation | T1003.001 | 11 | High |

| 12 | Registry Run Keys Modification | T1547.001 | 13 | Medium |

| 13 | Suspicious LSASS Process Access | T1003.001 | 10 | High |

| 14 | Windows Service Installation | T1543.003 | 7045 | Medium |

| 15 | Windows Registry Modification | T1112 | 13 | Medium |



\---



\## 8. MITRE ATT\&CK Coverage



The detection library covers 11 distinct ATT\&CK techniques across 6 tactics.



Major techniques include:



\- T1059.001 — PowerShell

\- T1059.003 — Windows Command Shell

\- T1003.001 — LSASS Memory

\- T1021.001 — Remote Desktop Protocol

\- T1021.002 — SMB/Windows Admin Shares

\- T1053.005 — Scheduled Task/Job

\- T1033 — System Owner/User Discovery

\- T1547.001 — Registry Run Keys / Startup Folder

\- T1543.003 — Windows Service

\- T1112 — Modify Registry

\- T1129 — Shared Modules



The ATT\&CK coverage matrix is maintained in:



`docs/ATTACK\_COVERAGE\_MATRIX.md`



\---



\## 9. Sigma Validation



The Sigma rules were locally validated using Sigma CLI.



Validation focused on:



\- Rule syntax

\- Detection conditions

\- Rule structure

\- Required fields



The online ATT\&CK metadata check was excluded during validation because the external metadata lookup was unavailable at the time.



Local validation completed without rule errors.



\---



\## 10. Threat Hunt 1 — PowerShell Credential Access



\### Objective



Investigate PowerShell activity associated with credential collection and LSASS access.



\### Telemetry



PowerShell Event ID 4104.



\### Observations



The investigation identified:



\- `PromptForCredential`

\- `Get-Credential`

\- `GetNetworkCredential()`

\- `ValidateCredentials()`

\- `Get-Process lsass`

\- `MiniDumpWriteDump`

\- `MiniDumpWithFullMemory`



\### Outcome



Two suspicious behavior patterns were documented:



1\. PowerShell credential collection.

2\. PowerShell LSASS memory-dump behavior.



The hunt is documented in:



`hunts/HUNT-01-PowerShell-Credential-Access.md`



\---



\## 11. Threat Hunt 2 — RDP Tunneling and Tampering



\### Objective



Investigate suspicious RDP tunneling, port forwarding, and remote-access configuration changes.



\### Observations



The investigation identified:



\- `plink.exe` forwarding activity toward TCP 3389

\- `netsh.exe` port-forwarding activity

\- RDPWrap execution

\- Firewall modification involving TCP 3389

\- `cmd.exe` launching an RDPWrap installer



\### Outcome



The activity was documented as suspicious RDP tunneling or remote-access tampering within the supplied dataset.



The hunt is documented in:



`hunts/HUNT-02-RDP-Tunneling-Tampering.md`



\---



\## 12. Incident Investigation 1 — LSASS Memory Dump



\### Evidence



The investigation examined:



`Powershell\_4104\_MiniDumpWriteDump\_Lsass.evtx`



Relevant events included PowerShell Script Block Logging containing:



\- `Get-Process lsass`

\- `MiniDumpWriteDump`

\- `MiniDumpWithFullMemory`



\### ATT\&CK



T1003.001 — LSASS Memory



\### Assessment



The activity represents suspicious LSASS memory-dump behavior within the supplied dataset.



The sample does not by itself establish successful credential extraction or a real-world compromise.



The full investigation is documented in:



`incidents/INCIDENT-01-PowerShell-LSASS-Dump.md`



\---



\## 13. Incident Investigation 2 — Credential Collection



\### Evidence



The investigation examined:



`phish\_windows\_credentials\_powershell\_scriptblockLog\_4104.evtx`



Relevant PowerShell activity included:



\- `PromptForCredential`

\- `Get-Credential`

\- `GetNetworkCredential()`

\- `ValidateCredentials()`



\### Assessment



The activity represents suspicious credential-collection behavior within the supplied dataset.



The sample alone does not establish successful credential theft, attacker identity, initial access, or system compromise.



The full investigation is documented in:



`incidents/INCIDENT-02-PowerShell-Credential-Collection.md`



\---



\## 14. Correlation Rules



Three correlation scenarios were documented.



\### Correlation 1 — PowerShell Credential Access Chain



Correlates PowerShell Script Block Logging with credential-collection or LSASS-related indicators.



\### Correlation 2 — RDP Tunneling and Remote Access Chain



Correlates port forwarding, RDP-related activity, remote-access tooling, and firewall changes.



\### Correlation 3 — LSASS Access to Dump-File Creation Chain



Correlates LSASS process access with subsequent suspected dump-file creation.



The complete documentation is maintained in:



`correlations/CORRELATION-RULES.md`



\---



\## 15. Detection Tuning



Three detections were tuned.



\### SMB Windows Admin Share Access



The detection was narrowed from generic Event ID 5145 activity to administrative shares such as:



\- `\\ADMIN$`

\- `\\C$`

\- `\\IPC$`



\### RDP Network Connection



The detection was refined to Sysmon Event ID 3 with destination port 3389.



\### Windows User Discovery via Whoami



The detection was refined to Sysmon Event ID 1 with `whoami.exe`.



The tuning process and false-positive considerations are documented in:



`docs/DETECTION-TUNING.md`



\---



\## 16. IOC Research



IOC research covered:



\- PowerShell credential-collection strings

\- LSASS memory-dump indicators

\- Suspected dump-file names

\- RDP-related tools

\- TCP port 3389

\- Windows administrative shares

\- `whoami.exe`

\- Firewall modification activity



The complete IOC research is documented in:



`docs/IOC-RESEARCH.md`



\---



\## 17. Incident-Response Playbooks



Three response playbooks were developed.



\### Playbook 1



\*\*LSASS Credential Dump Response\*\*



Covers detection, triage, evidence collection, investigation, containment, recovery, and escalation.



\### Playbook 2



\*\*Suspicious Credential Collection Response\*\*



Covers PowerShell credential-collection activity and related investigation procedures.



\### Playbook 3



\*\*RDP Tunneling \& Remote Access Response\*\*



Covers suspicious RDP activity, port forwarding, RDP-related tooling, and firewall modification.



\---



\## 18. Methodology



The project followed this workflow:



\*\*Telemetry → Detection → ATT\&CK Mapping → Threat Hunt → Investigation → Correlation → Tuning → Response → Documentation\*\*



The methodology included:



1\. Dataset analysis

2\. Field identification

3\. Behavioral analysis

4\. Sigma rule development

5\. ATT\&CK mapping

6\. Threat hunting

7\. Incident investigation

8\. Correlation

9\. Detection tuning

10\. IOC research

11\. Playbook development

12\. Documentation and version control



The detailed methodology is documented in:



`docs/METHODOLOGY.md`



\---



\## 19. Repository Structure



```text

Cyberion-ThreatShield/

│

├── detections/

├── hunts/

├── incidents/

├── playbooks/

├── correlations/

├── docs/

├── data/

├── reports/

├── datasets/

│

└── .gitignore

