- If we have local admin rights over a host, we perform `Pass-the-Hash` via SMB
- If no local admin rights:
	- RDP
	- PS Remoting - winRM
	- MSSQL Server - if sysadmin privs, we can xp_cmdshell
- Enumerate the above access using PowerView or BloodHound (below):
	- [CanRDP](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canrdp)
	- [CanPSRemote](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canpsremote)
	- [SQLAdmin](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#sqladmin)

<hr>

## Remote Desktop
- **Remote Desktop Users** group
- usually local admin user will have RDP rights
- at least some user might have RDP rights
- Use this host position for:
	- further attacks
	- privesc
	- pillage host for sensitive data or creds
### Enumerate Remote Desktop Users Group
- `Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"`
- Check the **Members** section
	- If **INLANEFREIGHT\Domain Users** is mentioned, this means all the domain users can RDP to this host
- This kind of host might be used as a jump host and can have a lot of sensitive data
- Local priv esc could also be possible

- ### `Checking the Domain Users Group's Local Admin & Execution Rights using BloodHound`
- Find Remote Access Rights -> `Execution Rights` on `Node Info` tab
- `Analysis Tab` -> `Find Workstations where Domain Users can RDP` or `Find Servers where Domain Users can RDP`
- Linux - `xfreerdp` or `Remmina`
- Windows - `rdp` / `mstsc.exe`

<hr>

## WinRM
- **Remote Management Users** group
### Enumerating Remote Management Users Group
- `Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"`
### Cypher query for BloodHound to find Remote Management Users
- `MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2`
### Evil-winrm alternative for Windows = Enter-PSSession
- `$forendpass = ConvertTo-SecureString "Klmcargo" -AsPlainText -Force`
- `$forendcred = New-Object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $forendpass)`
- `Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $forendcred`

<hr>

## SQL Server Admin
- Kerberoasting or LLMNR poisoning
- SNAFFLER - https://github.com/SnaffCon/Snaffler
	- finds `web.config` and other `config files` containing SQL server connection strings
### Cypher code to check SQL Admin rights on BloodHound
- `MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2`
### Enumerating using PowerUpSQL - Windows
- https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet
- `Import-Module .\PowerUpSQL`
- `Get-SQLInstanceDomain`
- `Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'`
### SQL enum using mssqlclient.py - Linux
- `mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth`
