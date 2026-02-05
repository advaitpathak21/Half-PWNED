```
nmap --min-rate 10 -p- 10.10.11.174 -Pn
Starting Nmap 7.93 ( https://nmap.org ) at 2025-05-25 06:52 EDT
Nmap scan report for 10.10.11.174
Host is up (0.023s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
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
9389/tcp  open  adws
49664/tcp open  unknown
49667/tcp open  unknown
49674/tcp open  unknown
49678/tcp open  unknown
49699/tcp open  unknown
49737/tcp open  unknown
```

- `smbclient -U 'nick' //10.10.11.174/support-tools`
- 
