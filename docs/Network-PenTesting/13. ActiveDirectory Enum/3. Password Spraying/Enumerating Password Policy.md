## Linux - Credentialed
- With valid domain creds, we can get it using: **crackmapexec** or **rpcclient**
### CRACKMAPEXEC - *Get/Pull domain password policy with creds*
- `crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol`

### Netexec
- `nxc smb 172.16.5.5 -u UserNAme -p 'PASSWORDHERE' --pass-pol`

<hr>

## Linux - SMB NULL Session
- Without credentials, use an **SMB NULL session** or **LDAP anonymous bind**
- SMB NULL session misconfigs happen when legacy Domain Controllers are updated in place with older configs
	- older windows servers allowed anonymous access to certain shares - used for domain enum
	- SMB NULL session can be enumerated using **enum4linux, CRACKMAPEXEC, rpcclient**

### RPCCLIENT - *to check a DC for SMB Null session access*
- `rpcclient -U "" -N 172.16.5.5` - connect to a DC
- `querydominfo` - in the RPC session, query information
- `getdompwinfo` - get password policy information

### enum4linux
- build around samba suite of tools - nmblookup ,net, rpcclient, smbclient
- ![](/attachments/Pasted-image-20250210160059.png)
- `enum4linux -P 172.16.5.5` - getting password policy
- `enum4linux-ng -P 172.16.5.5 -oA ilfreight` - using **ng** to export data
	- `cat ilfreight.json` - displaying output

<hr>

## Linux - LDAP anonymous bind
- This can get a complete listing of users, groups, computers, user account attributes, and the domain password policy
- Legacy setting. New configs require authentication
- Tools - `windapsearch.py`, `ldapsearch`, `ad-ldapdomaindump.py`

### LDAPSearch
- `ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength`
	- getting password policy

<hr>

# Windows

## Windows - NULL Sessions
- `net use \\DC01\ipc$ "" /u:""` - **DC01** is the host

**Other variations**
- `net use \\DC01\ipc$ "" /u:guest` - use some username
- `net use \\DC01\ipc$ "password" /u:guest` - credentialed

<hr>

## Other:
### net.exe
- If we can authenticate into the domain
- tools - `net.exe`, `PowerView`, `CrackMapExec` ported to Windows, `SharpMapExec`, `SharpView`
- `net accounts`

### PowerView
- `Import-Module .\PowerView.ps1`
- `Get-DomainPolicy`

<hr>

## INFORMATIKS
- `pwdProperties` set to `1`
	- Password complexity is enabled on the particular user
- DEFAULT PASSWORD POLICY when a new domain is created
	- ![](/attachments/Pasted-image-20250210161432.png)
