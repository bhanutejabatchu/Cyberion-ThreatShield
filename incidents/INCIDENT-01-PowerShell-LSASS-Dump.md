# Incident Investigation 01 — PowerShell LSASS Memory Dump

## 1. Incident Overview

This investigation analyzes a Windows EVTX sample containing PowerShell Script Block Logging associated with LSASS memory-dump activity.

The investigation is based on the supplied EVTX-ATTACK-SAMPLES dataset.

## 2. Data Source

- EVTX File: `Powershell_4104_MiniDumpWriteDump_Lsass.evtx`
- Primary Event ID: 4104
- Telemetry: PowerShell Script Block Logging
- Investigation focus: LSASS memory access and memory dumping

## 3. Timeline

| Time | Event ID | Event Record ID | Observation |
|---|---:|---:|---|
| 2020-06-30 14:23:58.394424 | 40961 | 968 | Preceding event in the sample |
| 2020-06-30 14:23:58.440338 | 53504 | 969 | Preceding event in the sample |
| 2020-06-30 14:23:58.532114 | 40962 | 970 | Preceding event in the sample |
| 2020-06-30 14:24:08.254604 | 4104 | 971 | PowerShell Script Block containing LSASS memory-dump logic |

## 4. Key Evidence

The Event ID 4104 ScriptBlockText contains:

- `Get-Process lsass`
- `MiniDumpWriteDump`
- `MiniDumpWithFullMemory`
- Creation of a dump file through `FileStream`

The script obtains the LSASS process and invokes the `MiniDumpWriteDump` method with full-memory dumping enabled.

## 5. Observed Attack Behavior

The telemetry is consistent with PowerShell-based LSASS memory-dump activity.

MITRE ATT&CK mapping:

- Technique: OS Credential Dumping
- Sub-technique: LSASS Memory
- ID: T1003.001
- Tactic: Credential Access

## 6. Investigation Assessment

The Event ID 4104 record provides strong evidence that the PowerShell script attempted to access the LSASS process and create a memory dump.

The surrounding events occur immediately before the 4104 event and are retained as part of the incident timeline.

## 7. Potential Impact

LSASS memory contains authentication-related material. A successful memory-dump operation may expose credential material.

However, this dataset does not by itself establish that credentials were successfully extracted or used after the dump.

## 8. Root Cause Assessment

The exact initial access or root cause cannot be determined from this EVTX sample alone.

The available evidence establishes the observed PowerShell LSASS-dump behavior but does not provide sufficient information to determine how the activity was initiated.

## 9. Recommended Response Actions

1. Validate whether the PowerShell activity was authorized security testing.
2. Preserve the relevant PowerShell and Windows event logs.
3. Investigate the created dump-file path if available.
4. Review surrounding process-creation and authentication telemetry.
5. Investigate any subsequent credential use or lateral-movement activity.
6. If unauthorized, isolate the affected host according to the organization's incident-response procedure.
7. Review PowerShell Script Block Logging and LSASS-access detections for additional related activity.

## 10. Detection Opportunities

The investigation supports detection for:

- PowerShell Event ID 4104 referencing `Get-Process lsass`.
- `MiniDumpWriteDump` in PowerShell ScriptBlockText.
- `MiniDumpWithFullMemory` in PowerShell ScriptBlockText.
- Correlation with LSASS dump-file creation.
- Correlation with suspicious process access to LSASS.

## 11. Conclusion

The investigated EVTX sample contains a PowerShell Script Block Logging event that demonstrates LSASS memory-dump behavior.

The strongest evidence occurs at:

`2020-06-30 14:24:08.254604`

Event ID `4104`, EventRecordID `971`.

The evidence supports investigation as potential credential-access activity. The sample alone does not establish attacker identity, initial access, successful credential extraction, or real-world impact.
