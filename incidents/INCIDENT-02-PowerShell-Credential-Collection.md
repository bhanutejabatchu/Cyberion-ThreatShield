# Incident Investigation 02 — PowerShell Credential Collection

## 1. Incident Overview

This investigation analyzes a Windows EVTX sample containing PowerShell Script Block Logging associated with credential collection through a credential prompt.

The investigation is based on the supplied EVTX-ATTACK-SAMPLES dataset.

## 2. Data Source

- EVTX File: `phish_windows_credentials_powershell_scriptblockLog_4104.evtx`
- Primary Event ID: 4104
- Telemetry: PowerShell Script Block Logging
- Investigation focus: suspicious credential collection

## 3. Timeline

| Time | Event ID | Event Record ID | Observation |
|---|---:|---:|---|
| 2019-09-09 13:35:08.655802 | 4104 | 1122 | PowerShell Script Block event containing encoded/decompressed script content |
| 2019-09-09 13:35:09.315229 | 4104 | 1123 | Script creates a credential prompt and processes supplied credentials |

## 4. Key Evidence

The Event ID 4104 ScriptBlockText contains:

- `PromptForCredential`
- `Get-Credential`
- `GetNetworkCredential()`
- `ValidateCredentials()`
- A Windows Security credential prompt
- Collection of username, domain, and password values

The script repeatedly prompts for credentials when validation fails and processes the resulting credential object.

## 5. Observed Attack Behavior

The telemetry is consistent with PowerShell-based credential collection through a deceptive or unauthorized credential prompt.

The supplied dataset identifies this activity as a credential-collection scenario.

## 6. Investigation Assessment

The Event ID 4104 record provides evidence of PowerShell code that prompts a user for credentials and processes the resulting credential information.

The script also validates the supplied credentials against a machine account-management context.

## 7. Potential Impact

If unauthorized, credential collection could expose user authentication material and potentially enable subsequent unauthorized access.

However, this EVTX sample alone does not establish that a real user's credentials were successfully obtained or subsequently used.

## 8. Root Cause Assessment

The exact initial access method and execution chain cannot be determined from this EVTX sample alone.

The available evidence establishes the observed PowerShell credential-collection behavior but does not identify the original delivery mechanism.

## 9. Recommended Response Actions

1. Determine whether the PowerShell script was part of authorized security testing.
2. Preserve the relevant PowerShell Script Block logs.
3. Identify the host and user associated with the activity if available from surrounding telemetry.
4. Review authentication logs for unusual credential use following the event.
5. Search for related PowerShell execution and process-creation activity.
6. If unauthorized, investigate possible credential exposure and follow the organization's credential-reset procedure.
7. Review other systems for the same script or related indicators.

## 10. Detection Opportunities

Potential detection logic includes:

- PowerShell Event ID 4104 containing `PromptForCredential`.
- `GetNetworkCredential()` in ScriptBlockText.
- `ValidateCredentials()` combined with credential prompting.
- `Get-Credential` followed by credential-processing logic.
- Correlation with subsequent authentication activity.

## 11. Conclusion

The investigated EVTX sample contains PowerShell Script Block Logging that demonstrates credential-prompting and credential-processing behavior.

The strongest observed event occurs at:

`2019-09-09 13:35:09.315229`

Event ID `4104`, EventRecordID `1123`.

The evidence supports investigation as suspicious credential-collection activity. The sample alone does not establish successful credential theft, the identity of an attacker, the initial access method, or subsequent account compromise.
