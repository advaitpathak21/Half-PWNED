- Could also provide information for reporting and not just attack paths
- When landing on a Windows host in a domain, especially one an admin uses, you will find tools and scripts on the host

## AD Powershell Module
- has powershell cmdlets for AD

**Discover Modules**
- `Get-Module`

**Load AD Module**
- `Add-WindowsFeature RSAT-AD-PowerShell`
	- OR
- `Enable-WindowsOptionalFeature -FeatureName ActiveDirectory-Powershell -Online -All`
<br>
- `Import-Module ActiveDirectory`
- `Get-Module`

**Get Domain Info**
- `Get-ADDomain`

**Get ADUser**
- `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName`

**Check Trust Relationships**
- `Get-ADTrust -Filter *`

**Group Enumeration**
- `Get-ADGroup -Filter * | select name`

**Detailed Group Info**
- `Get-ADGroup -Identity "Backup Operators"`

**Group Membership**
- `Get-ADGroupMember -Identity "Backup Operators"`

<hr>

## PowerView
- https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon
- like bloodhound but not gui.
- ![](/attachments/Pasted-image-20250212160217.png)
- ![](/attachments/Pasted-image-20250212160228.png)
- ![](/attachments/Pasted-image-20250212160238.png)

### Domain User Information
- `Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol`

### Recursive Group Information
- `Get-DomainGroupMember -Identity "Domain Admins" -Recurse`
- If another group `Secadmins` is a member of this group (NESTED GROUP), the user in `Secadmins` can escalate to `Domain Admins`

### Trust Enumeration
- `Get-DomainTrustMapping`

### Test for Local Admin Access
- `Test-AdminAccess -ComputerName ACADEMY-EA-MS01`

### Find users with SPN Set - **kerberoasting**
- `Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName`

<hr>

## SharpView
- .NET port of Powerview
- good for evasion if powershell is blocked
- `.\SharpView.exe Get-DomainUser -Help`

**Enumerate a User**
- `.\SharpView.exe Get-DomainUser -Identity forend`

<hr>

## Snaffler
- https://github.com/SnaffCon/Snaffler
- get creds or sensitive data in an AD env
- obtains a list of hosts within a domain and enumerate them for shares and readable directories.
- REQUIRED TO BE RUN FROM A DOMAIN-JOINED HOST

### Execution
- `Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data`
	- `-s` print results on std out
	- `-o` output to files
	- `-v data` : display verbose data on screen

<hr>

## BloodHound
- authenticate as a **domain user**
- https://github.com/SpecterOps/SharpHound

### Run SharpHound
- `.\SharpHound.exe -c All --zipfilename ILFREIGHT`
- Copy the zip file to our own VM
