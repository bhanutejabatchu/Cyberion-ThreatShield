# Threat Hunt 01 — PowerShell Credential Access

## 1. Hunt Objective

Investigate Windows PowerShell Script Block Logging events for activity associated with credential collection and LSASS memory access.

## 2. Hunt Hypothesis

An attacker or unauthorized tool may use PowerShell to collect user credentials or access LSASS memory. Such activity should produce PowerShell Event ID 4104 Script Block Logging telemetry containing credential-collection or LSASS memory-dump indicators.

## 3. Data Source

- Dataset: EVTX-ATTACK-SAMPLES
- Log type: Windows Event Logs
- Event ID: 4104
- Telemetry: PowerShell Script Block Logging

## 4. Hunt Logic

Search Event ID 4104 ScriptBlockText for indicators including:

- PromptForCredential
- GetNetworkCredential
- ValidateCredentials
- Get-Credential
- Get-Process lsass
- MiniDumpWriteDump
- MiniDumpWithFullMemory

## 5. Hunt Execution

The dataset contained 3 PowerShell Event ID 4104 events.

Two events originated from:

`phish_windows_credentials_powershell_scriptblockLog_4104.evtx`

One event originated from:

`Powershell_4104_MinidumpWriteDump_Lsass.evtx`

## 6. Finding 1 — PowerShell Credential Collection

The credential-related script contains:

- `PromptForCredential`
- `GetNetworkCredential().password`
- `ValidateCredentials()`
- `Get-Credential`

The script creates a credential prompt and retrieves credential information including username, domain, and password.

### Assessment

This behavior is consistent with credential-collection activity and warrants investigation when observed outside an authorized security-testing context.

## 7. Finding 2 — LSASS Memory Dump Activity

The second relevant PowerShell script contains:

- `Get-Process lsass`
- `MiniDumpWriteDump`
- `MiniDumpWithFullMemory`

The script obtains the LSASS process and invokes a memory-dump function against the process.

### Assessment

This is strong evidence of LSASS memory-access/dumping behavior and should be investigated as potential credential-access activity unless authorized as security testing or incident-response activity.

## 8. Detection Opportunities

The hunt supports detection logic for:

1. PowerShell Event ID 4104 containing credential-collection functions.
2. PowerShell Event ID 4104 referencing `lsass`.
3. PowerShell Event ID 4104 containing `MiniDumpWriteDump`.
4. PowerShell Event ID 4104 containing `MiniDumpWithFullMemory`.

## 9. Conclusion

The hunt identified two distinct credential-access behaviors in the dataset:

- PowerShell-based credential collection.
- PowerShell-based LSASS memory dumping.

Both findings provide useful detection-engineering evidence for the Cyberion ThreatShield Sigma rule library.

These observations come from the supplied EVTX-ATTACK-SAMPLES dataset and should not be interpreted as evidence of a real-world incident.
