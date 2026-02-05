- we should know the defensive state of the host

<hr>

## Windows Defender
- Since Windows 10 May 2020 Update, MS/Windows Defender has been very powerfull
- blocks PowerView

**Check status of Defender**
- `Get-MpComputerStatus`

<hr>

## AppLocker
- app whitelist contains a list of approved software apps or executables that are allowed to be present/run on a system.
- AppLocker does this for Microsoft
- It provides granular control over executables, scripts, Windows installer files, DLLs, packaged apps, and packed app installers
- It is common for organizations to block `cmd.exe` and `PowerShell.exe` and write access to certain directories, but this can all be bypassed. 
	- Organizations also often focus on blocking the `PowerShell.exe` executable, but forget about the other [PowerShell executable locations](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) such as `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` or `PowerShell_ISE.exe`. 
	- We can see that this is the case in the `AppLocker` rules shown below. All Domain Users are disallowed from running the 64-bit PowerShell executable located at:
		- `%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe`
- We can just change and run the location of the executable

**Get-AppLockerPolicy**
- `Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections`

<hr>

## PowerShell Constrained Language Mode
- This mode locks many powershell features, blocks OCM objects, allows approved .NET types, XAML-based workflows, PS classes

**Check PS Language Mode**
- `$ExecutionContext.SessionState.LanguageMode`

<hr>

## LAPS
- LAPS is used to **randomize** and **rotate local administrator passwords** on Windows hosts and prevent lateral movement.
- TOOL - https://github.com/leoloobeek/LAPSToolkit
- enumerate:
	1. what machines have LAPS and which domain users are using it
	2. what machines do not have LAPS
- An account that has joined a computer to a domain receives `All Extended Rights` over that host, and this right gives the account the ability to read passwords.

- https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/laps.html

**Find-LAPSDelegatedGroups**
- `Find-LAPSDelegatedGroups`

**Find-AdmPwdExtendedRights**
- `Find-AdmPwdExtendedRights`
- Check the rights on each computer with LAPS enabled for any groups with read access and users with "All Extended Rights"

**Get-LAPSComputers**
- `Get-LAPSComputers`

