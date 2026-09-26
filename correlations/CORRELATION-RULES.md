\# Cyberion ThreatShield — Correlation Rules



\## Purpose



These correlation rules combine related security events to improve detection context and reduce isolated-alert investigation.



\---



\## Correlation Rule 1 — PowerShell Credential Access Chain



\### Objective



Identify suspicious PowerShell activity associated with credential collection or LSASS access.



\### Event Sequence



1\. PowerShell Script Block Logging — Event ID 4104

2\. Credential-collection keywords or LSASS memory-dump behavior

3\. Optional supporting authentication or process activity



\### Key Indicators



\- `PromptForCredential`

\- `Get-Credential`

\- `GetNetworkCredential()`

\- `ValidateCredentials()`

\- `Get-Process lsass`

\- `MiniDumpWriteDump`

\- `MiniDumpWithFullMemory`



\### ATT\&CK Mapping



\- T1059.001 — PowerShell

\- T1003.001 — LSASS Memory



\### Severity



High



\### Investigation Value



Correlating PowerShell execution with credential-access indicators provides stronger context than evaluating a generic PowerShell event alone.



\---



\## Correlation Rule 2 — RDP Tunneling and Remote Access Chain



\### Objective



Identify suspicious remote-access activity involving RDP, port forwarding, and related configuration changes.



\### Event Sequence



1\. Process creation involving `plink.exe` or `netsh.exe`

2\. Port-forwarding activity involving TCP 3389

3\. RDP-related process or authentication activity

4\. Optional firewall modification allowing inbound TCP 3389



\### Key Indicators



\- `plink.exe`

\- `netsh.exe`

\- TCP port `3389`

\- RDPWrap

\- `netsh advfirewall`

\- Inbound Remote Desktop firewall rule



\### ATT\&CK Mapping



\- T1021.001 — Remote Services: Remote Desktop Protocol

\- T1090 — Proxy



\### Severity



High



\### Investigation Value



Combining tunneling, RDP, and firewall activity can help analysts identify a coordinated remote-access pattern instead of treating each event independently.



\---



\## Correlation Rule 3 — LSASS Access to Dump-File Creation Chain



\### Objective



Identify a potential credential-dumping sequence by correlating process access to LSASS with creation of a suspected memory-dump file.



\### Event Sequence



1\. Sysmon Event ID 10 — Process access targeting `lsass.exe`

2\. Sysmon Event ID 11 — File creation

3\. File name or path associated with an LSASS memory dump



\### Key Indicators



\- Target image ending in `\\lsass.exe`

\- `lsass.dmp`

\- `lsass.exe\_\*`

\- `dumpert.dmp`

\- `minidump\_\*`



\### ATT\&CK Mapping



\- T1003.001 — LSASS Memory



\### Severity



High



\### Investigation Value



Correlating LSASS process access with subsequent dump-file creation provides stronger evidence for investigation than either event considered independently.



\---



\## Correlation Workflow



The SOC analyst should follow:



\*\*Event → Correlation → Context → Investigation → Response\*\*



For each correlation:



1\. Identify the triggering event.

2\. Search for related events within the relevant investigation timeframe.

3\. Correlate hostname and user context.

4\. Compare process and command-line information.

5\. Record supporting evidence.

6\. Determine whether the activity is authorized or suspicious.

7\. Escalate according to the applicable incident-response procedure.



\---



\## False-Positive Considerations



Potential legitimate activity may include:



\- Authorized administrative PowerShell usage.

\- Approved RDP connections.

\- IT troubleshooting.

\- Security testing.

\- Authorized system administration tools.

\- Approved forensic or debugging activity.



Correlation results should therefore be investigated in context rather than treated as automatic proof of compromise.



\---



\## Cyberion Dataset Evidence



The correlation logic is based on behaviors observed during analysis of the supplied EVTX-ATTACK-SAMPLES dataset, including:



\- PowerShell credential-collection activity.

\- PowerShell LSASS memory-dump behavior.

\- RDP tunneling and port-forwarding activity.

\- RDPWrap execution.

\- Firewall modification involving TCP 3389.

\- LSASS process-access and dump-file creation telemetry.



These observations represent activity within the supplied dataset and do not independently establish a real-world compromise.



\---



\## Expected Outcome



The three correlation rules provide multi-event detection logic covering:



\- Credential access

\- Remote access and tunneling

\- LSASS memory dumping



They are intended to improve analyst context and support structured threat investigation.

