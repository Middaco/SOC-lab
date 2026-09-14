# 1. Powershell Encoded Execution
## Report:
- What: A possibly malicious command was executed in PowerShell with the -EncodedCommand flag set, fact which allows execution of base64 encoded code. This could be malicious code executed or an attacker trying to get into the system by running encoded code. Since no brute force was attempt was found inside the logs, this could be either the true user or an attacker that got the user's password
- When: 2026-09-14T09:18:22.906468Z
- Where: Windows 11 VM
- Who: victim
- Why: No further actions were triggered by the execution of the command, the code turned out to be unharmful. After analyzing it, the given code was decoded in just a command that printed a message on the screen.

## Screenshots:
1. KQL interogation to find the event
   <img width="1335" height="552" alt="image" src="https://github.com/user-attachments/assets/3d240deb-8c36-4a6b-ae0f-f1ade738588d" />
2. Details of the latest incident found, where User and the executed command can be found
    <img width="1920" height="1040" alt="image" src="https://github.com/user-attachments/assets/a6a8121f-abb6-42b1-b94c-8cd28bf9973f" />

 
## Attack simulation:
For this case the attacker was actually the currently logged user that wanted to try execute an encoded command. The command 'Write-Output 'Hello, World!'' was placed in cyberchef and encoded as a Base64 command with UTF16LE encoding, otherwise the script wouldn't run in PowerShell. After getting the result in cyberchef, opening the powershell and executing the command was the last thing to do. 
```powershell
powershell -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAEgAZQBsAGwAbwAsACAAVwBvAHIAbABkACEAJwA=
```
## Telemetrics && KQL Investigation
```kql
SecurityEvent
| where EventID == 4688
| where CommandLine contains "powershell.exe" and CommandLine contains "-EncodedCommand"
```
## SIEM Analytics Rule
The previous KQL Investigation was saved as an Analytics Rule in order to trigger an alert every time a user executes an encoded command via PowerShell.

##Resolve and Recommendations
Further employee instruction could be conducted in order to advice them not to execute encoded commands on work-place systems.
