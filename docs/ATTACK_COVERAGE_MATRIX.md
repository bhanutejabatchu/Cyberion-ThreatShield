# MITRE ATT&CK Coverage Matrix

## Cyberion ThreatShield — Detection Engineering

| Rule | MITRE Technique | Tactic | Event ID | Severity |
|---|---|---|---:|---|
| #1 PowerShell Credential Collection | T1059.001 | Execution | 4104 | High |
| #2 PowerShell LSASS Memory Dump | T1003.001 | Credential Access | 4104 | High |
| #3 Scheduled Task Creation | T1053.005 | Execution / Persistence | 4698 | Medium |
| #4 RDP Successful Logon | T1021.001 | Lateral Movement | 4624 | Medium |
| #5 SMB Windows Admin Share Access | T1021.002 | Lateral Movement | 5145 | Medium |
| #6 Windows DLL Module Load | T1129 | Execution | 7 | Medium |
| #7 PowerShell Script Block Logging | T1059.001 | Execution | 4104 | Low |
| #8 Windows User Discovery via Whoami | T1033 | Discovery | 1 | Medium |
| #9 RDP Network Connection | T1021.001 | Lateral Movement | 3 | Medium |
| #10 Windows Command Shell Execution | T1059.003 | Execution | 1 | Medium |
| #11 LSASS Memory Dump File Creation | T1003.001 | Credential Access | 11 | High |
| #12 Registry Run Keys Modification | T1547.001 | Persistence | 13 | Medium |
| #13 Suspicious LSASS Process Access | T1003.001 | Credential Access | 10 | High |
| #14 Windows Service Installation | T1543.003 | Persistence | 7045 | Medium |
| #15 Windows Registry Modification | T1112 | Defense Evasion | 13 | Medium |

## Summary

- Total Sigma rules: **15**
- ATT&CK techniques represented: **11**
- Tactics represented: **6**
- Primary log telemetry: **Windows Security, PowerShell, and Sysmon**
- Validation status: **All 15 rules locally validated with Sigma CLI**
