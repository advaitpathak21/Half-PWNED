- ACL misconfigurations can leak permissions to other objects that do not need it.
## ACL Overview
- who has access to which asset/resource 
- the level of access they are provisioned.
- every setting in an ACL is an Access Control Entry (ACE)
- Every ACE maps back to a user, group, process (known as a security principal)
	- defines the rights granted to that principal

## ACL Types:
### DACL - Discretionary ACLs
- defines which security principals are granted or denied access to an object
- made up of ACEs that either allow or deny access
- when an access is attempted, the system checks DACL for the level of access.
	- If DACL does not exist, allow permission to object
	- If DACL exists, deny permission to object
![](/attachments/Pasted-image-20250217130204.png)
### SACL - System ACLs
- allows admins to log access attempts made to secured objects
![](/attachments/Pasted-image-20250217130221.png)

## ACE Types:
- ![](/attachments/Pasted-image-20250217130317.png)
- Each ACE has 4 components:
	- SID or principal name of the user/group having access to an object
	- flag denoting type of ACE (allow, deny, audit)
	- inheritance from
	- access mask (32 bits) defining the rights granted to an object
- View in AD Users and Computers
	- ![](/attachments/Pasted-image-20250217131051.png)
<br>
## Abuse AD permissions with PowerView modules:
- `ForceChangePassword` abused with `Set-DomainUserPassword`
- `Add Members` abused with `Add-DomainGroupMember`
- `GenericAll` abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`
- `GenericWrite` abused with `Set-DomainObject`
- `WriteOwner` abused with `Set-DomainObjectOwner`
- `WriteDACL` abused with `Add-DomainObjectACL`
- `AllExtendedRights` abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`
- `Addself` abused with `Add-DomainGroupMember`
![](/attachments/Pasted-image-20250217131311.png)- ![](/attachments/Pasted-image-20250217132041.png)
