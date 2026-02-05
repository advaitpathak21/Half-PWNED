```
time nmap 10.10.11.152 --min-rate 10 -Pn 
Starting Nmap 7.93 ( https://nmap.org ) at 2025-04-01 12:51 EDT
Nmap scan report for 10.10.11.152
Host is up (0.33s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
```

