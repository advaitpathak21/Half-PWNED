- Kerberoasting and ASREPRoasting can be performed across trusts based on the trust directions.
- when you cannot escalate privileges in the current domain, but can obtain a KRB ticket and crack a hash for an admin user in another domain that has Domain/Enterprise Admin privs in both domains.
## Workflow
### Find Accounts with SPNs using Get-DomainUser
- `Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName`
	- `-Domain` - Target Domain
### Enumerating the account
- `Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc |select samaccountname,memberof`
	- we can see that `mssqlsvc` is a part of domain admins for `FREIGHTLOGISTICS.LOCAL`
### Kerberoasting with Rubeus using /domain flag
- `.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap`
- hashcat to crack hash

<hr>

## Admin Password Re-Use & Group Membership
- we'll run into a situation where there is a bidirectional forest trust managed by admins from the same company
- If we can take over Domain A and obtain password or NT hash for the built-in admin or enterprise/domain admin in Domain A; and Domain B has a high priv account with the same name, then we can check for password reuse.
	- EG: Domain A would have a user named `adm_bob.smith` in the Domain Admins group, and Domain B had a user named `bsmith_admin`.
	- we own Domain A and if same password is used, we can get full admin rights to Domain B
- we may see users/admins from Domain A as members of groups in Domain B
- `Domain Local Group` allow security principals from outside its forest
	- We may see a Domain Admin or Enterprise Admin from Domain A as a member of the built-in Administrators group in Domain B in a bidirectional forest trust relationship
### Enumerate Foreign Group Members in a Domain
- `Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL`
	- returns the Group name
	- Memberdomain
	- MemberName in SID
	- built-in Administrators group in `FREIGHTLOGISTICS.LOCAL` has the built-in Administrator account for the `INLANEFREIGHT.LOCAL` domain as a member
- `Convert-SidToName S-1-5-21-3842939050-3880317879-2865463114-500`
	- convert above SID to get `domain/name`
### Access the account using PSSession
- `Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator`
	- we successfully authenticated to the Domain Controller in the `FREIGHTLOGISTICS.LOCAL` domain using the Administrator account from the `INLANEFREIGHT.LOCAL` domain across the bidirectional forest trust

<hr>

## SID History Abuse - Cross Forest
- sid history can also be abused in a forest trust
- If a user is migrated from one forest to another and SID Filtering is not enabled, we can add a SID from the other forest, and this SID will be added to the user's token when authenticating across the trust
- ![](/attachments/Pasted-image-20250302115255.png)
- 
