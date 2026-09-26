\# Cyberion ThreatShield — Detection Tuning



\## Purpose



This document records tuning performed on three detection rules to improve detection context and reduce unnecessary alerts.



The tuning is based on the telemetry and examples observed in the supplied EVTX-ATTACK-SAMPLES dataset.



\---



\## Tuning 1 — SMB Windows Admin Share Access



\### Rule



`detections/smb\_windows\_admin\_share\_access.yml`



\### Original Logic



The initial rule detected Windows Security Event ID 5145.



\### Tuning Change



The rule was narrowed to administrative shares:



\- `\\ADMIN$`

\- `\\C$`

\- `\\IPC$`



\### Reason for Tuning



Event ID 5145 can represent many legitimate network-share access events.



Restricting the detection to commonly used Windows administrative shares provides more specific context for remote administrative activity.



\### ATT\&CK Mapping



T1021.002 — SMB/Windows Admin Shares



\### Severity



Medium



\### False-Positive Considerations



Potential legitimate activity includes:



\- Authorized system administration

\- IT support

\- Software deployment

\- Backup operations

\- Domain administration



\### Expected Improvement



The tuned rule provides more focused detection of administrative-share access instead of alerting on every 5145 event.



\---



\## Tuning 2 — RDP Network Connection



\### Rule



`detections/windows\_network\_connection.yml`



\### Original Logic



The initial network-connection detection was broader and could identify Windows network connection events without sufficient RDP context.



\### Tuning Change



The rule was refined to:



\- Sysmon Event ID 3

\- Destination port `3389`



\### Reason for Tuning



TCP port 3389 is commonly associated with Remote Desktop Protocol.



Adding the destination-port condition provides stronger RDP-specific context.



\### ATT\&CK Mapping



T1021.001 — Remote Services: Remote Desktop Protocol



\### Severity



Medium



\### False-Positive Considerations



Potential legitimate activity includes:



\- Authorized remote administration

\- Help-desk activity

\- Remote system management

\- Approved RDP sessions



\### Expected Improvement



The tuned rule focuses on network connections associated with RDP rather than generic Windows network connections.



\---



\## Tuning 3 — Windows User Discovery via Whoami



\### Rule



`detections/windows\_process\_creation.yml`



\### Original Logic



The initial process-creation detection was too broad and did not identify a specific discovery behavior.



\### Tuning Change



The rule was refined to:



\- Sysmon Event ID 1

\- Process image ending with `\\whoami.exe`



\### Reason for Tuning



The dataset contained actual `whoami.exe` execution associated with user-discovery behavior.



Restricting the detection to `whoami.exe` provides clearer behavioral context.



\### ATT\&CK Mapping



T1033 — System Owner/User Discovery



\### Severity



Medium



\### False-Positive Considerations



`whoami.exe` can be legitimately executed by:



\- System administrators

\- Troubleshooting scripts

\- IT automation

\- Security tools

\- Users checking their current account context



\### Expected Improvement



The tuned rule focuses on a specific user-discovery command rather than generic process creation.



\---



\## Tuning Summary



| Rule | Tuning | Purpose |

|---|---|---|

| SMB Windows Admin Share Access | Administrative share filtering | Improve remote-share specificity |

| RDP Network Connection | Destination port 3389 | Improve RDP-specific context |

| Windows User Discovery via Whoami | `whoami.exe` filtering | Improve discovery detection specificity |



\---



\## Tuning Methodology



The tuning process followed:



1\. Review the original detection logic.

2\. Examine actual dataset telemetry.

3\. Identify overly broad conditions.

4\. Identify fields providing stronger behavioral context.

5\. Add specific conditions.

6\. Consider legitimate use cases and false positives.

7\. Validate the updated Sigma rule.

8\. Document the tuning decision.



\---



\## Validation



The tuned Sigma rules were locally validated using Sigma CLI.



Validation was performed with the local ATT\&CK tag check excluded because the online MITRE metadata lookup was unavailable during validation.



The local Sigma syntax and condition validation completed without rule errors.



\---



\## Expected Outcome



Detection tuning should improve alert quality by increasing behavioral specificity while documenting legitimate activity that may produce false positives.



Tuning should be reviewed periodically as additional telemetry and analyst feedback become available.

