### Enumerate Priveleges
- `net user <username>`
- `whoami /all`
- `whoami /privesc`

### Server Operator Group
- https://www.hackingarticles.in/windows-privilege-escalation-server-operator-group/
### SeBackupPrivileges
- https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/
### SeLoadDriverPrivileges
- https://github.com/JoshMorrison99/SeLoadDriverPrivilege
- https://github.com/k4sth4/SeLoadDriverPrivilege
### SeImpersonatePrivilege & SeAssignPrimaryToken
- can be leveraged in combination with a tool such as [JuicyPotato](https://github.com/ohpe/juicy-potato), [PrintSpoofer](https://github.com/itm4n/PrintSpoofer), or [RoguePotato](https://github.com/antonioCoco/RoguePotato) to escalate to `SYSTEM` level privileges,
