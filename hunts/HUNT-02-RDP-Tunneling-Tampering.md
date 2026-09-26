# Threat Hunt 02 — RDP Tunneling and Remote Desktop Tampering

## 1. Hunt Objective

Investigate Windows process-creation telemetry for activity associated with RDP tunneling, port forwarding, and modification of Remote Desktop configuration.

## 2. Hunt Hypothesis

An attacker may attempt to establish or modify Remote Desktop access by using tunneling tools, port-forwarding utilities, RDP configuration tools, or firewall rules. These behaviors may appear in process creation telemetry through command-line indicators.

## 3. Data Source

- Dataset: EVTX-ATTACK-SAMPLES
- Log type: Windows Event Logs
- Event ID: 1
- Telemetry: Windows/Sysmon process creation

## 4. Hunt Logic

Search Event ID 1 process-creation events for indicators including:

- plink.exe
- netsh.exe
- RDPWrap
- Remote Desktop firewall configuration
- Port-forwarding parameters
- Commands referencing TCP port 3389

## 5. Hunt Execution

The RDP/SMB dataset subset contained 1,436 events.

Five process-creation events were identified as potential RDP tunneling or Remote Desktop configuration/tampering activity.

## 6. Finding 1 — RDP Port Forwarding Through Plink

File:

`DE_sysmon-3-rdp-tun.evtx`

The process-creation event shows `plink.exe` being used with reverse forwarding toward an RDP service on TCP port 3389.

### Assessment

The command-line behavior is consistent with tunneling traffic to an RDP endpoint. This is a high-value hunting indicator when observed on systems where such tunneling is not authorized.

## 7. Finding 2 — Netsh Port Forwarding

File:

`de_portforward_netsh_rdp_sysmon_13_1.evtx`

The event shows `netsh.exe` being used to configure port forwarding involving TCP port 3389.

### Assessment

Port-forwarding configuration can provide an alternate path to an RDP service and should be investigated when unexpected.

## 8. Finding 3 — RDPWrap Installation and Execution

File:

`sysmon_13_rdp_settings_tampering.evtx`

The telemetry shows:

- `cmd.exe` launching an RDPWrap installation script.
- `RDPWInst.exe` being executed with installation-related parameters.

### Assessment

The activity indicates modification or installation of software associated with Remote Desktop configuration.

## 9. Finding 4 — RDP Firewall Rule Modification

The same dataset contains a `netsh.exe` command adding a firewall rule named `Remote Desktop` and allowing inbound TCP traffic on local port 3389.

### Assessment

Unexpected firewall modification combined with RDP-related activity is a useful correlation signal for investigation.

## 10. Hunt Correlation

The strongest hunting pattern is the combination of:

1. RDP-related process execution.
2. Port-forwarding configuration.
3. RDPWrap installation or execution.
4. Firewall modification involving TCP 3389.

A single indicator may have legitimate administrative explanations, but multiple indicators occurring together provide stronger investigative context.

## 11. Detection Opportunities

Potential detection logic includes:

- Process creation involving `plink.exe` with RDP-related forwarding.
- `netsh.exe` commands configuring port forwarding to TCP 3389.
- RDPWrap installation or execution.
- Firewall-rule creation allowing inbound TCP 3389.
- Correlation of RDP configuration changes with unusual process execution.

## 12. Conclusion

The hunt identified multiple RDP-related tunneling and configuration-modification behaviors in the supplied EVTX dataset.

The evidence demonstrates useful detection opportunities around process creation, command-line analysis, port forwarding, RDP configuration, and firewall modification.

These observations originate from the EVTX-ATTACK-SAMPLES dataset and should not be interpreted as evidence of a real-world incident.
