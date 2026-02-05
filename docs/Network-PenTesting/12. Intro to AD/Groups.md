- place similar users together to mass assign rights and access
- built-in groups for AD - https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#about-active-directory-groups
- can provide lax permissions and grant excessive access to unintended users
<br>
- OUs are useful for grouping users, groups, and computers to ease management and deploying Group Policy settings to specific objects in the domain. 
- Groups are primarily used to assign permissions to access resources.
<br>
- Group **TYPE**: define group's purpose
	- **Security Groups:** Assign Permissions
	- **Distribution Groups:** send messages to group
- Group **SCOPE**: how can the group be used with the domain or forest
	- **Domain Local** - permissions for resources only on Domain
	- **Global Scope** - perms for resources for another domain
	- **Universal Group** - perms for resources across the forest

**Get Scope Of users**
- `Get-ADGroup  -Filter * |select samaccountname,groupscope`

![](/attachments/Pasted-image-20250204111626.png)

![](/attachments/Pasted-image-20250204112650.png)


### Group Attributes
- https://docs.microsoft.com/en-us/windows/win32/ad/group-objects
- ![](/attachments/Pasted-image-20250204112922.png)
- 
