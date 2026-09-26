\# Cyberion ThreatShield — Executive Summary



\## 1. Project Overview



Cyberion ThreatShield is a detection engineering and threat hunting engagement focused on Windows security telemetry.



The project transforms publicly available Windows event-log data into practical SOC detection content, threat-hunting investigations, incident reports, correlation logic, and incident-response playbooks.



The project was performed using the supplied EVTX-ATTACK-SAMPLES dataset.



\---



\## 2. Objectives



The main objectives were to:



\- Analyze Windows security telemetry.

\- Identify security-relevant behaviors.

\- Develop Sigma detection rules.

\- Map detections to MITRE ATT\&CK.

\- Perform structured threat hunts.

\- Investigate suspicious activity.

\- Develop incident-response playbooks.

\- Research indicators of compromise.

\- Tune detections and document false-positive considerations.

\- Maintain reproducible project documentation.



\---



\## 3. Detection Engineering Results



The project produced:



\- 15 Sigma detection rules

\- 11 distinct MITRE ATT\&CK techniques

\- Coverage across 6 ATT\&CK tactics

\- 3 correlation rules

\- Detection tuning for 3 rules

\- Local Sigma validation of the detection rules



The detections cover behaviors including:



\- PowerShell activity

\- LSASS memory access

\- Credential collection

\- Scheduled task creation

\- RDP activity

\- SMB administrative shares

\- DLL module loading

\- User discovery

\- Windows command shell execution

\- Registry modification

\- Windows service installation



\---



\## 4. Threat Hunting Results



Two structured threat hunts were completed.



\### Hunt 1 — PowerShell Credential Access



The investigation examined PowerShell Event ID 4104 activity and identified:



\- Credential-collection behavior

\- LSASS memory-dump behavior



Observed indicators included:



\- `PromptForCredential`

\- `Get-Credential`

\- `GetNetworkCredential()`

\- `Get-Process lsass`

\- `MiniDumpWriteDump`

\- `MiniDumpWithFullMemory`



\### Hunt 2 — RDP Tunneling and Remote Access



The investigation examined process activity associated with RDP tunneling and remote-access tampering.



Observed activity included:



\- `plink.exe` port forwarding

\- `netsh.exe` port forwarding

\- RDPWrap activity

\- Firewall modification involving TCP 3389

\- RDP-related command execution



\---



\## 5. Incident Investigation Results



Two incident investigations were documented.



\### Incident 1 — PowerShell LSASS Memory Dump



The investigation identified PowerShell Script Block Logging containing LSASS memory-dump behavior.



The activity was mapped to:



\*\*T1003.001 — LSASS Memory\*\*



The evidence was documented with a timeline, key indicators, potential impact, response actions, and detection opportunities.



\### Incident 2 — PowerShell Credential Collection



The investigation identified PowerShell Script Block Logging containing credential-collection functions.



Observed indicators included:



\- `PromptForCredential`

\- `Get-Credential`

\- `GetNetworkCredential()`

\- `ValidateCredentials()`



The investigation documented the evidence, timeline, potential impact, response actions, and detection opportunities.



\---



\## 6. Incident-Response Playbooks



Three response playbooks were developed:



1\. LSASS Credential Dump Response

2\. Suspicious Credential Collection Response

3\. RDP Tunneling \& Remote Access Response



Each playbook includes:



\- Trigger conditions

\- Initial triage

\- Evidence collection

\- Investigation procedure

\- Containment

\- Eradication and recovery

\- Detection opportunities

\- Escalation criteria

\- Analyst documentation requirements



\---



\## 7. Correlation and Detection Tuning



Three correlation scenarios were documented:



1\. PowerShell Credential Access Chain

2\. RDP Tunneling and Remote Access Chain

3\. LSASS Access to Dump-File Creation Chain



Three detections were also tuned to improve behavioral specificity:



\- SMB Windows Admin Share Access

\- RDP Network Connection

\- Windows User Discovery via Whoami



False-positive considerations were documented for each tuned detection.



\---



\## 8. IOC Research



IOC research documented observable indicators related to:



\- PowerShell credential collection

\- LSASS memory dumping

\- RDP tunneling

\- RDP-related tooling

\- SMB administrative shares

\- Windows user discovery

\- Firewall modification



The indicators were linked to relevant telemetry and ATT\&CK context.



\---



\## 9. Key Technical Outcomes



The project demonstrates a complete detection-engineering workflow:



\*\*Telemetry → Detection → ATT\&CK Mapping → Threat Hunt → Investigation → Correlation → Tuning → Response\*\*



The work also demonstrates practical use of:



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



\---



\## 10. Limitations



The analysis was performed using the supplied EVTX-ATTACK-SAMPLES dataset.



Therefore, the documented findings represent observations within the dataset.



The project does not independently establish:



\- A real-world compromise

\- Attacker identity

\- Successful credential theft

\- Successful unauthorized remote access

\- Initial access method

\- Real-world business impact



Additional production telemetry and investigation evidence would be required to establish those conclusions.



\---



\## 11. Project Repository



Project repository:



`https://github.com/bhanutejabatchu/Cyberion-ThreatShield`



The repository contains the detection rules, threat hunts, incident investigations, playbooks, correlation rules, and supporting documentation.



\---



\## 12. Final Outcome



Cyberion ThreatShield produced a structured SOC-oriented detection and threat-hunting knowledge base based on Windows security telemetry.



The resulting artifacts provide reusable detection logic, investigation procedures, response guidance, and documentation that can support future security monitoring and threat-hunting exercises.

