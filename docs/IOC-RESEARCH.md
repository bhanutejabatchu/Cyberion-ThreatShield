\# Cyberion ThreatShield — IOC Research and Notes



\## 1. Purpose



This document records indicators and observable artifacts identified during the Cyberion ThreatShield threat-hunting and incident-investigation activities.



The focus is on indicators that can support detection, investigation, and correlation of suspicious Windows activity.



\---



\## 2. IOC Categories



The investigation considered the following IOC categories:



\- File names and paths

\- Process names

\- Command-line patterns

\- IP addresses

\- Network ports

\- PowerShell script content

\- Windows Event IDs

\- Registry locations

\- User and authentication activity



\---



\## 3. PowerShell Credential Collection Indicators



\### Observed Indicators



The following PowerShell strings were observed in the supplied dataset:



\- `PromptForCredential`

\- `Get-Credential`

\- `GetNetworkCredential()`

\- `ValidateCredentials()`



\### Relevant Telemetry



\- Event ID: 4104

\- Log type: PowerShell Script Block Logging

\- Dataset file:

&#x20; `phish\_windows\_credentials\_powershell\_scriptblockLog\_4104.evtx`



\### ATT\&CK Context



\- T1059.001 — PowerShell



\### Investigation Use



These strings can be used as search terms when investigating suspicious PowerShell activity.



\---



\## 4. LSASS Memory-Dump Indicators



\### Observed Indicators



The investigation identified PowerShell content containing:



\- `Get-Process lsass`

\- `MiniDumpWriteDump`

\- `MiniDumpWithFullMemory`



\### Related File Indicators



The dataset also contained dump-file naming patterns such as:



\- `lsass.dmp`

\- `lsass.exe\_\*`

\- `dumpert.dmp`

\- `minidump\_\*`



\### Relevant Telemetry



\- Event ID 4104 — PowerShell Script Block Logging

\- Event ID 10 — Process Access

\- Event ID 11 — File Creation



\### ATT\&CK Context



\- T1003.001 — LSASS Memory



\### Investigation Use



These indicators can support correlation between LSASS access, PowerShell activity, and suspected memory-dump file creation.



\---



\## 5. RDP and Remote-Access Indicators



\### Observed Indicators



The threat hunt identified activity involving:



\- `plink.exe`

\- `netsh.exe`

\- RDPWrap

\- TCP port `3389`

\- `netsh advfirewall`



\### Related Activity



Observed activity included:



\- Port forwarding toward TCP 3389

\- RDP-related tooling

\- Firewall activity allowing inbound TCP 3389



\### ATT\&CK Context



\- T1021.001 — Remote Services: Remote Desktop Protocol

\- T1090 — Proxy



\### Investigation Use



These indicators can be correlated with RDP authentication, process creation, and firewall events.



\---



\## 6. Windows Administrative Share Indicators



\### Observed Indicators



The SMB detection was tuned to identify administrative shares including:



\- `\\ADMIN$`

\- `\\C$`

\- `\\IPC$`



\### Relevant Telemetry



\- Event ID 5145



\### ATT\&CK Context



\- T1021.002 — SMB/Windows Admin Shares



\### Investigation Use



Administrative-share access can be reviewed alongside user, host, process, and authentication information to determine whether the activity is expected.



\---



\## 7. User Discovery Indicator



\### Observed Indicator



The dataset contained execution of:



`whoami.exe`



Example command observed during analysis:



`whoami.exe /user`



\### Relevant Telemetry



\- Event ID 1 — Process Creation



\### ATT\&CK Context



\- T1033 — System Owner/User Discovery



\### Investigation Use



Search for `whoami.exe` execution and correlate it with the parent process, user account, command line, and surrounding activity.



\---



\## 8. RDP Firewall Indicator



\### Observed Indicator



The threat hunt identified:



`netsh advfirewall`



with activity associated with allowing inbound TCP port 3389.



\### Investigation Use



Review firewall modification events together with RDP logons and process activity to determine whether the configuration change was authorized.



\---



\## 9. IOC Handling Guidance



An indicator should not automatically be treated as malicious.



Analysts should:



1\. Validate the indicator.

2\. Identify the host and user context.

3\. Review the timestamp.

4\. Correlate related events.

5\. Check whether the activity has an authorized explanation.

6\. Search for the indicator across available telemetry.

7\. Document supporting evidence.

8\. Escalate when the combined evidence indicates suspicious activity.



\---



\## 10. Cyberion Dataset Limitations



The indicators documented here were derived from the supplied EVTX-ATTACK-SAMPLES dataset.



The dataset observations should not be interpreted as proof of a real-world compromise.



In particular, the indicators alone do not establish:



\- Attacker identity

\- Successful credential theft

\- Successful unauthorized RDP access

\- Initial access method

\- Persistence

\- Real-world impact



Additional telemetry and investigation evidence would be required to establish those conclusions.



\---



\## 11. IOC-to-Detection Mapping



| Indicator | Telemetry | Detection |

|---|---|---|

| `PromptForCredential` | PowerShell 4104 | Credential collection |

| `Get-Credential` | PowerShell 4104 | Credential collection |

| `MiniDumpWriteDump` | PowerShell 4104 | LSASS memory dump |

| `Get-Process lsass` | PowerShell 4104 | LSASS access |

| `lsass.dmp` | File Creation 11 | LSASS dump file |

| `plink.exe` | Process Creation 1 | RDP tunneling |

| TCP 3389 | Network/Process telemetry | RDP activity |

| `RDPWrap` | Process Creation 1 | RDP-related tooling |

| `\\ADMIN$` | Security 5145 | SMB admin share |

| `whoami.exe` | Process Creation 1 | User discovery |



\---



\## 12. Expected Outcome



The IOC research provides a structured reference for analysts investigating:



\- PowerShell credential collection

\- LSASS memory dumping

\- RDP tunneling

\- Remote access

\- SMB administrative-share activity

\- Windows user discovery



These indicators can be combined with Sigma detections, threat hunts, incident investigations, and correlation rules to improve investigation context.

