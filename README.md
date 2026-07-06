# Enterprise-SIEM-detection-Triage-Dashboard

---
## Overview
This project demonstrates the deployment of a small Enterprise Security Operations Centre (SOC) using Microsoft Azure' Sentinel, Azure Monitor Agent (AMA), Sysmon, Windows Security Events, and Kusto Query Language (KQL).

The goal here was to build an end-to-end SIEM environment with capacity to:
- Collect Windows Security Events
- Collect Sysmon telemetry
- Detect password spray attack
- Detect brute-force logons
- Create Sentinel Analytics Rules
- Build a SOC Workbook dashboard and
- Investigate incidents within Microsoft Sentinel

---
## Architecture

```
Windows 11
      │
      │ RDP
      ▼
Windows Server 2025
      │
Azure Monitor Agent (AMA)
      │
Data Collection Rule (DCR)
      │
Azure Monitor
      │
Log Analytics Workspace
      │
Microsoft Sentinel
      │
Analytics Rules
      │
Workbook Dashboard
```

---
## Technologies Used

- Microsoft Azure
- Microsoft Sentinel
- Azure Monitor Agent (AMA)
- Azure Arc
- Log Analytics Workspace
- Data Collection Rules (DCR)
- Sysmon
- Windows Event Viewer
- Kusto Query Language (KQL)

---
## Lab Components

### Windows Security Events

Collected via:
- Azure Monitor Agent
- Data Collection Rule
- Windows Security Events Connector

Events collected include:
- Event ID 4624 (Successful Logon)
- Event ID 4625 (Failed Logon)

---
### Sysmon

Installed Sysmon on Windows Server 2025.

Collected events include:
- Process Creation
- Network Connections
- PowerShell Activity
- Parent/Child Processes

---
### Sentinel Analytics

Created custom detections including:

### Password Spray

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts=count() by IpAddress, TargetAccount, bin(TimeGenerated,5m)
| where FailedAttempts >= 5
```

---
### Multiple Failed Logons

```kql
SecurityEvent
| where EventID == 4625
| summarize Count=count() by Account, IpAddress
```

---
### Successful Logons

```kql
SecurityEvent
| where EventID == 4624
```

---
## Workbook

Created a Sentinel Workbook showing:
- Failed Logons
- Successful Logons
- Password Spray Attempts
- Security Events Timeline
- Top Targeted Accounts
- Event Volume    
[Documentation: Workbook Screenshots](docs/WorkbookSOCLab.pdf)

---
## Major Troubleshooting

Engineering a deployment between hybrid physical networks and cloud spaces always introduces real-world system friction, and technical hurdles are always exciting. Anyway, this project involved significant troubleshooting that reflects real-world SOC engineering.

---
### Problem 1
No Windows Security Events appearing in Sentinel
#### Cause

Although Azure Monitor Agent fragmented during installation so it was uninstalled and reinstalled successfully then no Data Collection Rule was associated with the VM.

#### Resolution
Reinstalled Azure Monitor Agent
Created a Data Collection Rule that included:
- Windows Security Events
- Event IDs
- Connected the DCR to the VM
After several minutes, SecurityEvent logs began flowing.

---
### Problem 2
SecurityEvent table returned no results
Example:
```kql
SecurityEvent| take 5
```
returned zero rows.

#### Cause
Windows Security Events connector had not yet begun ingesting data because no DCR was linked.

#### Resolution
Created and linked the correct DCR.

Verified using:
```kql
SecurityEvent| take 5
```

---
### Problem 3
No Event ID 4625

Repeated failed RDP logins produced no events.

#### Cause
Audit Policy was not fully enabled.

#### Resolution
Verified Advanced Audit Policy:
```LogonSuccessFailure```
Generated failed logons directly on the Windows Server console instead of RDP.
4625 events then appeared.

---
### Problem 4
Password Spray Analytics returned no results
#### Cause
Insufficient failed logon events existed within the query time window.

#### Resolution
Generated multiple failed logons from the server and reran the query.

---
### Problem 5
Azure Arc could not onboard Ubuntu 25.10
#### Cause
Ubuntu 25.10 is currently unsupported by Azure Arc.

#### Resolution
Continued the project using Windows Server only.
Syslog collection from Ubuntu was omitted.

---
### Problem 6
RDP Logon Restrictions via Cloud Policies
When attempting to initiate authentication attacks from the Windows 11 administrator workstation or the Ubuntu attacking machine via Remote Desktop Protocol (RDP), the connection failed instantly.

#### Error Message
> "The system administrator has restricted the types of logon (network or interactive) that you may use. For assistance, contact system administrator or technical support."

#### Cause
Because the target machine (`SRV-DV01`) was registered via Azure Arc, cloud-native enterprise security guidelines (**AzureWindowsBaseline** and **Windows DefenderExploitGuard**) were automatically pushed down to the host. These baselines strictly enforced Remote Credential Guard and restricted standard interactive network logons for local, non-domain accounts. Plus, local RDP permissions hadn't been assigned to default lab user profiles.

#### Resolution
1. **Updated Local Group Policy Rights:** Modified the local schema on `SRV-DV01` via `gpedit.msc` under `Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> Allow log on through Remote Desktop Services` to explicitly allow the connection footprint.
2. **Loosened Security Layer Requirements:** Changed the active session host parameters to process low-level validation requests by setting `Require use of specific security layer for remote (RDP) connections` to **RDP** and disabling Network Level Authentication (NLA) constraints during the active attack phase.
3. **Bypassed CredSSP Client Restrictions:** Appended `enablecredsspsupport:i:0` to the local `.rdp` configuration file on the Windows 11 client system to force standard username/password prompt interaction.

---
## Lessons Learned

This project provided practical experience with:
- Microsoft Sentinel deployment
- Azure Monitor Agent
- Data Collection Rules
- Windows Event Logging
- Sysmon deployment
- KQL detection engineering
- SOC troubleshooting
- Incident investigation
- Workbook creation

One of the biggest lessons re-enforced here is understanding that successful data collection depends on the complete telemetry pipeline:
Windows Server → AMA → DCR → Log Analytics Workspace → Microsoft Sentinel

Missing a single component prevents telemetry from reaching Sentinel.

[Documentation: Screenshots](docs/SOCDetectionLab.pdf)

---
## Future Improvements
Would be to:
- Add Linux Syslog collection
- Onboard Microsoft Defender for Endpoint
- Configure UEBA
- Add Threat Intelligence indicators
- Implement Microsoft Defender XDR integration
- Build custom Hunting Queries
- Automate response using Sentinel Playbooks
- Integrate Logic Apps for incident response

---
## Skills Demonstrated
> "Microsoft Sentinel | Azure Monitor | Azure Monitor Agent | Data Collection Rules | Log Analytics | Sysmon | Windows Security | Kusto Query Language (KQL) | SIEM Engineering | Detection Engineering | SOC Operations | Incident Investigation | Azure Administration | Security Monitoring."

---
AVGVSTJNE
