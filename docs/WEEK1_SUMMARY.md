
# Cyberion ThreatShield — Week 1 Summary

## Dataset
- Dataset: EVTX-ATTACK-SAMPLES
- Primary log type: Windows EVTX Event Logs
- Analysis: Python and pandas
- Notebook: EVTX_Metadata.ipynb

## Week 1 Activities
- Parsed Windows EVTX samples
- Analyzed Event IDs and log sources
- Reviewed important security log fields
- Analyzed ATT&CK tactic distribution
- Selected and documented five ATT&CK technique mappings
- Created a security-focused data dictionary

## ATT&CK Technique Mapping

1. SMB/Windows Admin Shares — T1021.002
   Evidence: LM_5145_Remote_FileCopy.evtx
   Key Event: 5145

2. PowerShell — T1059.001
   Evidence: PowerShell EVTX samples
   Key Event: 4104

3. Remote Desktop Protocol — T1021.001
   Evidence: RDP / Terminal Services samples
   Key Events: 4624 / 1149

4. Scheduled Task — T1053.005
   Evidence: temp_scheduled_task_4698_4699.evtx
   Key Events: 4698 / 4699

5. DLL Search Order Hijacking — T1574.001
   Evidence: Sysmon 7 Update Session Orchestrator DLL Hijack.evtx
   Key Event: 7

## Data Dictionary
A 27-field security data dictionary was created covering:
Event IDs, log channels, providers, hosts, processes,
command lines, users, network addresses, ports, files,
services, scheduled tasks, PowerShell script blocks,
hashes, named pipes, shares, EVTX filenames, and ATT&CK tactics.

## Additional Analysis
Two threat-hunting findings were documented:
- LSASS memory-dump related PowerShell activity
- Suspicious credential-collection activity through PowerShell Event ID 4104

These findings will be developed further during the threat-hunting and incident-investigation stages.
