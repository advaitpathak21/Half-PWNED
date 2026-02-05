 - CIA Triad
 - ![](/attachments/Pasted-image-20250205111738.png)

<hr>

# AD Hardening Measures
## LAPS
- Local Admin Password Solution - randomize and rotate admin passwords on a fixed interval

## Audit Policy Settings
- Log and monitor setup to detect and react to changes and activities that are suspicious.

## Group Policy Security Settings
- Account Policy - user interaction with domains
- Local Policy - specific computer policy and audits.
- Software Restriction - what sw can run on a host
- App Restriction - which app can be run by which (**restrict from running executables**)  
- Advanced Audit Policy

## Advanced Audit Policy

## Update Management
- Windows Server Update Server (WSUS)
- System Center Config manager (SCCM)

## Group Manager Service Accounts (gMSA)
- high priv account to manage services with non-interactive apps

## Security Groups
- assign access to network resources
- Built-in groups 
	- ![](/attachments/Pasted-image-20250205133713.png)

## Account Seperation
- 2 accounts
	- 1 for day-to-day work
	- 1 for admin work

## Password Complexity Policies + Passphrases + 2FA

## Limiting Domain Admin Account Usage
- Domain admins only to DC
## Periodically Auditing and Removing Stale Users and Objects

## Auditing Permissions and Access | Policies and Logging

## Using Restricted Groups

## Limiting Server Roles
- ![](/attachments/Pasted-image-20250205134528.png)
https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory
