- Local Systems (non-AD joined) and Systems in AD can have users for persons or programs (services) that can access the computer
- User can login using a username and password. The server will then provide a token
- This token will have the security content based on the privileges of the user and the groups he is a part of

## Local Accounts
- stored locally on a server or workstation
- individual or group membership rights on the host
- EG local accounts created on a windows system
	- **Administrator** : Default with installation
	- **guest** : disabled by default
	- **System** : SERVICE account to perform internal functions like ROOT
		- Does not have a profile in `C:\Users` but has permissions over almost everything
		- cannot be added to groups
	- **Network Service** : predefined local account used by the Service Control Manager.
		- present creds to remote services
	- **Local Service** : used by SCM. 
		- minimal privileges, presents anonymous creds to the network.

## Domain Users
- granted rights from the domain to access different resources within the domain like - file servers, printers, intranet hosts, other objects
- Domain user accounts can log into any host in the domain (unlike local accounts).
- `KRBTGT` account is different
	- This account acts as a service account for the Key Distribution service providing authentication and access for domain resources.
	- This account is a common target of many attackers since gaining control or access will enable an attacker to have unconstrained access to the domain. 
	- It can be leveraged for privilege escalation and persistence in a domain through attacks such as the [Golden Ticket](https://attack.mitre.org/techniques/T1558/001/) attack.
- ![](/attachments/Pasted-image-20250203222116.png)

### AD COMMANDS:
**Get common user attributes in an AD**
- `Get-ADUser -Identity htb-student`
- https://docs.microsoft.com/en-us/windows/win32/ad/user-object-attributes

## Domain joined vs Non domain joined
![](/attachments/Pasted-image-20250203222358.png)


## Using NT Authority\System for enum
![](/attachments/Pasted-image-20250203222420.png)

