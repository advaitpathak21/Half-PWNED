# PowerView
- `Find-InterestingDomainAcl` - huge information dumped
- We can streamline this process

### Setup
- start with `wley` - from llmnr linux
- `Import-Module .\PowerView.ps1`
- `$sid = Convert-NameToSid wley`
### Get-DomainObjectACL
- `Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}`
	- might take time to load results
	- without `ResolveGUIDs` - no clear picture of ACLs
	- `ObjectAceType` - contains the `GUID` value
- With `GUID` value:
	- search google for the `GUID` value
	- Reverse search  & map guid value
		- `$guid= "00299570-246d-11d0-a768-00aa006e0529"`
		- `Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl`
- Instead of above, use the `ResolveGUIDs` flag

**MAIN COMMAND**
- `Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} `

<hr>

# Without PowerShell, using System Tools
- using `Get-Acl` and `Get-ADUser`
### Create a List of Domain Users
- `Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt`
### Get-ADUser for loop
- `foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}`
	- This will output an `ObjectType` having a GUID

<hr>

- With above results, we know that as user `wley` we have control over the user `damundsen` via `User-Force-Change-Password`
- `Get-ADUser -Filter 'Name -like "Dana Amundsen"' -Properties * `
## Further Enumeration
### Enum user ACL
- `$sid2 = Convert-NameToSid damundsen`
- `Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose`
	- `damundsen` has `GenericWrite` over `Help Desk Level 1`
	- we can add any users to this group and inherit rights
### Domain Group Enum
- `Get-DomainGroup -Identity "Help Desk Level 1"`
	- If nothing interesting here, check the nested groups for inheritance
- `Get-DomainGroup -Identity "Help Desk Level 1" | select memberof`
### Enum User Group for ACLs
- `$itgroupsid = Convert-NameToSid "Information Technology"`
- `Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose`
- `damundsen` has `GenericAll` over `adunn`
### Enum `adunn` access
- `$adunnsid = Convert-NameToSid adunn `
- `Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $adunnsid} -Verbose`
- `adunn` has  `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-In-Filtered-Set` over objects
	- USE `DCSync` attack

<hr>

## ACLs with BloodHound
- `Sharphound` ingestor upload data on `BloodHound`
- Set `wley` as a `Starting node` in BloodHound
- In `Node Info` > `Outbound Control Rights`
	- Shows objects we have control over directly
- In `Node Info` > `Transitive Object Control`
	- shows number of objects that our user could lead to us controlling
- Use pre-built queries to confirm the DCSync on `adunn`

<hr>
