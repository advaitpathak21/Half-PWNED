## Exchange Related Group Membership
- a default installation of Microsoft Exchange within an AD env (with bo split-administration model) opens up many attack vectors
- exchange is granted considerable privileges
- `Exchange Windows Permissions` is not listed as a protected group, but members are granted the ability to write a DACL to the domain object.
	- This can allow us to give users DCSync privileges
- An attacker can add accounts to this group by leveraging a DACL misconfiguration (possible) or by leveraging a compromised account that is a member of the **Account Operators** group
- https://github.com/gdedrouas/Exchange-AD-Privesc
<br>
- Exchange group `Organization Management` - powerful
	- can access mailbox of all domain users
	- sysadmins could be a part of this group
	-  full control of the OU called `Microsoft Exchange Security Groups`, which contains the group `Exchange Windows Permissions`.
- If we can compromise an Exchange server, this will often lead to Domain Admin privileges. Additionally, dumping credentials in memory from an Exchange server will produce 10s if not 100s of cleartext credentials or NTLM hashes. This is often due to users logging in to Outlook Web Access (OWA) and Exchange caching their credentials in memory after a successful login.

<hr>

## PrivExchange
- PushSubscription feature of Exchange
- Allows any domain user with a mailbox to force the Exchange server to authenticate to any host provided by the client over HTTP
- ![](/attachments/Pasted-image-20250228222402.png)

<hr>

## PrinterBug
- The spooler service runs as SYSTEM and is installed by default in Windows servers running Desktop Experience. This attack can be leveraged to relay to LDAP and grant your attacker account DCSync privileges to retrieve all password hashes from AD.
- http://web.archive.org/web/20200919080216/https://github.com/cube0x0/Security-Assessment
- https://github.com/NotMedic/NetNTLMtoSilverTicket
- This flaw can be used to compromise a host in another forest that has Unconstrained Delegation enabled, such as a domain controller. It can help us to attack across forest trusts once we have compromised one forest.

### Enum for MS-PRN Printer Bug
- `Import-Module .\SecurityAssessment.ps1`
- `Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL`

<hr>

## MS14-068
- https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek
- https://app.hackthebox.com/machines/98

<hr>

## Sniffing LDAP Credentials
- https://grimhacker.com/2018/03/09/just-a-printer/

<hr>

## Enum DNS Records
- https://github.com/dirkjanm/adidnsdump
	- dump all DNS records in a domain using a valid domain user account
- If host names are non-descriptive of their function, it is hard to know what to attack
- DNS can help us map names
- The tool works because, by default, all users can list the child objects of a DNS zone in an AD environment.
- https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/
### adidnsdump
- `adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 `
### view contents
- `head records.csv`
### Resolve unknown records
- `adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r`
- `head records.csv` 

<hr>

# Other Misconfigs
### Password in Description Field
- `Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}`
### PASSWD_NOTREQD Field
- If this field is set in the `userAccountControl` attribute, the password policy length is not checked
	- can have shorter or no password
#### Enum accounts with PASSWD_NOTREQD 
- `Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol`

<hr>

## Credentials in SMB Shares and SYSVOL Scripts
- SYSVOL can have different batch, VBS, PS scripts
## Group Policy Preference (GPP) passwords
- When a new GPP is created, an .xml file is created in the SYSVOL share.
- The `cpassword` attribute value is AES-256 bit encrypted, but Microsoft [published the AES private key on MSDN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be?redirectedfrom=MSDN),
- Patched in 2014 - https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevation-of-privilege-may-13-2014-60734e15-af79-26ca-ea53-8cd617073c30
- The patch does not remove existing **Groups.xml files** with passwords from SYSVOL.
### Decrypting the password found in `Groups.xml` from `SYSVOL`
- `gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE`

### Enum GPP Passwords
- https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1
- `crackmapexec smb -L | grep gpp`
### Enum using gpp_autologin
- find passwords in files such as Registry.xml when autologon is configured via Group Policy.
- `nxc smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin`
- https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPAutologon.ps1
### Enum using gpp_password
- `nxc smb 172.16.2.5 -u jbercov -p myspace7 -M gpp_password`
- 

<hr>

## Group Policy Object (GPO) Abuse
- https://github.com/FSecureLABS/SharpGPOAbuse
- GPO misconfigurations can be abused to perform the following attacks:
	- Adding additional rights to a user (such as SeDebugPrivilege, SeTakeOwnershipPrivilege, or SeImpersonatePrivilege)
	- Adding a local admin user to one or more hosts
	- Creating an immediate scheduled task to perform any number of actions
- Enum using - PowerView, BloodHound, [group3r](https://github.com/Group3r/Group3r), [ADRecon](https://github.com/sense-of-security/ADRecon), [PingCastle](https://www.pingcastle.com/)
### Enum GPO Names with PowerView
- `Get-DomainGPO |select displayname`
### Enum GPO Names with built-in
- `Get-GPO -All | Select DisplayName`
### Enum Domain User GPO Rights
- `$sid=Convert-NameToSid "Domain Users"`
- `Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}`
### Convert GPO-ID to name
- `Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532`
