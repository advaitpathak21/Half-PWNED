```
PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
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

- no access to smb shares

- printer admin panel - i believe the creds are being sent to an IP 
- creating my own ldap server
    - failed
- Listen on port 389
- svc-printer:1edFg43012!!

- evil-winrm with above creds

<hr>

- net user svc-printer
- svc-printer is a part of the Server operator Group
- https://www.hackingarticles.in/windows-privilege-escalation-server-operator-group/

- get SYSTEM
