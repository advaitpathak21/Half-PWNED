## Detailed User Enum
- To mount a password spray, we need a **list of valid domain usernames** and/or **password policy**
- Getting **valid usernames**:
	- **SMB NULL SESSION** - list of domain users
	- **LDAP anonymous bind** - pull domain user list
	- **Kerbrute** - validate usernames from a wordlist 
		- [statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames) GitHub repo, or [linkedin2username](https://github.com/initstring/linkedin2username) to create a list of potentially valid users
	- **set of creds** - found through responder, or provided by the client, or a smaller password spray
- Getting **Password Policy** - previous module
	- If no **password policy** - "Jai Gajanan" password spray is the only option
<br>
- Always keep a **log** of our **password spraying** activities, including, but not limited to:
	- The accounts targeted
	- Domain Controller used in the attack
	- Time of the spray
	- Date of the spray
	- Password(s) attempted

<hr>

## SMB NULL Session - Pull User List
- If on an internal machine without domain creds.
- If you have credentials for a domain user or `SYSTEM` access on a Windows host, you can easily query AD for this information.
	- ![](/attachments/Pasted-image-20250211110815.png)
- Tools - enum4linux, rpcclient, crackmapexec

### RID Brute forcing
- `nxc smb 10.10.11.236 -u 'guest' -p '' --rid-brute`
### enum4linux
- `enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"`

### rpcclient
- `rpcclient -U "" -N 172.16.5.5` - anonymous connect
- `enumdomusers` - list of domain users

### CrackMapExec
- `crackmapexec smb 172.16.5.5 --users`

### netexec
- `netexec smb 172.16.5.5 --users`

<hr>

## LDAP Anonymous - gathering users
- When **LDAP Anonymous Bind** is allowed, we can use [windapsearch](https://github.com/ropnop/windapsearch) and [ldapsearch](https://linux.die.net/man/1/ldapsearch).
### ldapsearch
- `ldapsearch -H 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "`

### windapsearch
- `./windapsearch.py --dc-ip 172.16.5.5 -u "" -U`
	- `-u ""` - anonymous login
	- `-U` - get a list of users

<hr>

## Kerbrute - enum users
- STEALTHY
- ![](/attachments/Pasted-image-20250211112401.png)

### Kerbrute user enum
- get the `jsmith.txt` wordlist from here - https://github.com/insidetrust/statistically-likely-usernames
- `kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt`
	- ![](/attachments/Pasted-image-20250211114035.png)

### GetNPUsers - AS-REP Roasting
- `impacket-GetNPUsers DANTE.ADMIN/ -dc-ip 172.16.2.5 -no-pass -usersfile old-emps.txt`

<hr>

#### If NO Above enumeration method works, we can go back to external research - https://github.com/initstring/linkedin2username

<hr>

## Credentialed Enumeration
### CrackMapExec
- `sudo crackmapexec smb 172.16.5.5 -u username -p password --users`

### Netexec
- `netexec smb 172.16.5.5 -u username -p 'password' --users`

