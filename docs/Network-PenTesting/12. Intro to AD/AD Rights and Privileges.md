- Rights given to users or groups define:
	- access: to an object like file
- privilege: perform an action 
	- can be assigned to an user or groups
	- eg: SeLoadDriverPrivilege
		- SeBackupPrivilege

![](/attachments/Pasted-image-20250204114313.png)
![](/attachments/Pasted-image-20250204114324.png)
![](/attachments/Pasted-image-20250204114339.png)

**Get Server Operator Group Details**
- `Get-ADGroup -Identity "Server Operators" -Properties *`

**Get Domain ADmin members**
- `Get-ADGroup -Identity "Domain Admins" -Properties * | select DistinguishedName,GroupCategory,GroupScope,Name,Members`


<hr>
# User Rights Assignment
- https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment
- Scenario: we have right access over a GPO (Group Policy Object) that is applied to an OU of which we have comprised a user.
	- We can use tools like https://github.com/FSecureLABS/SharpGPOAbuse or `Bloody-AD` to assign rights/privilege to a user
- ![](/attachments/Pasted-image-20250204162224.png)
- https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e
- https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.html

## Viewing a User's Privilege
- `whoami /priv`

- We have Elevated and Non-Elevated rights
- **Elevated** - running powershell/cmd as admin
- **Non-Elevated** - not running as admin

