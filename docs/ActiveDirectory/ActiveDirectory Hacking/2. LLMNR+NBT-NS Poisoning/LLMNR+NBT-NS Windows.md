## Inveigh
- https://github.com/Kevin-Robertson/Inveigh
- Similar to responder, written in C# and PowerShell
- Inveigh can listen to IPv4 and IPv6 and several other protocols, including `LLMNR`, DNS, `mDNS`, NBNS, `DHCPv6`, ICMPv6, `HTTP`, HTTPS, `SMB`, LDAP, `WebDAV`, and Proxy Auth.

### **Commands**
#### Powershell - deprecated
- `Import-Module .\Inveigh.ps1`
- `Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y` - start Inveigh for LLMNR, NBT-NS spoofing
- **HELP**
	- `(Get-Command Invoke-Inveigh).Parameters` - check all parameters
	- https://github.com/Kevin-Robertson/Inveigh#parameter-help - check default parameters

#### C# version
- compile it first
- `.\Inveigh.exe`
	- options with `[+]` are enabled by default 
	- options with `[ ]` are disabled.
- Press **ESC** to **enter/exit interactive console**
	- `C(0:0) NTLMv1(0:0) NTLMv2(3:9)> HELP` - enter `HELP` at the terminal
- `GET NTLMV2UNIQUE` - get NTLMv2 hashes
- `GET NTLMV2USERNAMES` - get usernames collected

#### Hash:
- Use `hashcat -m 5600 example.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt`

<hr>

## REMEDIATION

1. Disable LLMNR, NBNS

**disabling LLMNR**
- `We can disable LLMNR in Group Policy by going to Computer Configuration --> Administrative Templates --> Network --> DNS Client and enabling "Turn OFF Multicast Name Resolution."`
- clearly communicate to our clients that they should test these changes heavily to ensure that disabling both protocols does not break anything in the network.

**disabling NBT-NS**
- NBT-NS cannot be disabled via Group Policy but must be disabled locally on each host. We can do this by opening `Network and Sharing Center` under `Control Panel`, clicking on `Change adapter settings`, right-clicking on the adapter to view its properties, selecting `Internet Protocol Version 4 (TCP/IPv4)`, and clicking the `Properties` button, then clicking on `Advanced` and selecting the `WINS` tab and finally selecting `Disable NetBIOS over TCP/IP`.
- powershell script
```powershell
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey |foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}
```

2. Detection
- if you cant disable it, then it is good to detect it
- One way is to use the attack against the attackers by injecting LLMNR and NBT-NS requests for non-existent hosts across different subnets and alerting if any of the responses receive answers which would be indicative of an attacker spoofing name resolution responses. This [blog post](https://www.praetorian.com/blog/a-simple-and-effective-way-to-detect-broadcast-name-resolution-poisoning-bnrp/) explains this method more in-depth.
- 
