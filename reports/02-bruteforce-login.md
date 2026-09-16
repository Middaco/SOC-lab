# 2. Brute Force Log In Attempts
## Report:
  - What: Multiple attempts of log in have been spotted on the same machine and under the same username, all in a short amount of time. 
  - When: Sep 16, 2026 12:49:56 PM
  - Where: SOC, Windows 11 VM
  - Who: SOC/victim
  - Why: Multiple failed attempts of log in may suggest that an attacker tries to brute force its way inside the system, either by manual typing or through automation scripts. Such a behavior gets suspicious especially if the actions were executed in a short time span.

## Screenshots:
1. 4 consecutive failed attempts of log in have been detected for the same user
<img width="821" height="426" alt="image" src="https://github.com/user-attachments/assets/21c7dbb9-6334-45fc-a724-a60a6c399270" />

## Attack simulation
In order to simulate this attack, on the Windows Hello page were introduced multiple wrong passwords. These attempts were logged by the Windows OS and sent to Sentinel.

## Telemetrics & KQL Investigation
As a prerequisite, in order for the Windows OS to register these attempts of failed and successful logins, it was needed to configure the Local Security Policy of the VM. After editing the Local Security Policy > Security Settings > Local Policies > Audit Policy > Audit logon events policy to record the Success and Failure attempts, the Events were registered inside the Windows machine and delivered to Sentinel.

In order to identify the failed (4625) and successful (4624) attempts of login, the following KQL script was used:
```kql
SecurityEvent 
| where EventID == 4624 or EventID == 4625
| project TimeGenerated, Account, EventID, Activity
| order by TimeGenerated
```

## SIEM Analytics Rule
In order to notify the SOC analysts about a potential threat in the log in phase, the event has tot occur a minimum of 5 times in a minute under the same username. The next KQL interrogation represents the Analytics Rule created to detect Brute Force Log In attempts:
```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
| summarize 
    FailedAttempts = count(), 
    StartWindow = min(TimeGenerated), 
    EndWindow = max(TimeGenerated), 
    EventIDs = make_set(EventID),
    Details = make_set(Activity) 
    by TargetUserName, Computer, IpAddress
| where FailedAttempts > 5
| project StartWindow, EndWindow, TargetUserName, Computer, IpAddress, FailedAttempts, EventIDs, Details
| sort by FailedAttempts desc
```
