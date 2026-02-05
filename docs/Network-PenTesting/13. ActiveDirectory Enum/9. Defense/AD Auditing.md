## Creating an AD Snapshot with Active Directory Explorer
- AD Explorer can also be used to save snapshots of an AD database for offline viewing and comparison. We can take a snapshot of AD at a point in time and explore it later, during the reporting phase, as you would explore any other database. It can also be used to perform a before and after comparison of AD to uncover changes in objects, attributes, and security permissions.

## PingCastle
- https://www.pingcastle.com/documentation/
- eval the security posture of the AD env
- returns maps and graphs
- different from tools such as PowerView and BloodHound because, aside from providing us with enumeration data that can inform our attacks, it also provides a detailed report of the target domain's security level using a methodology based on a risk assessment/maturity framework - https://en.wikipedia.org/wiki/Capability_Maturity_Model_Integration
- ![](/attachments/Pasted-image-20250302152429.png)
### Running PingCastle
- `PingCastle.exe`
	- drops into a Terminal user Interface (TUI) - interactive mode
- default option -> `healthcheck` run, 
	- will establish a baseline overview of the domain, 
	- provide information to deal with misconfigurations and vulnerabilities.
- Creates an html report

## Group3r
- Group Policy auditing to find vulns
- must be run from a domain-joined host with a domain user
	- `runas /netonly`
- `group3r.exe -f <filepath-name.log>`
	- either `-s` or `-f` : stdout or save to file
	- OUTPUT -> each indentation is a different level, 
		- so no indent will be the GPO, 
		- one indent will be policy settings, 
		- and another will be findings in those settings. 

## ADRecon
- Not stealthy
- https://github.com/adrecon/ADRecon\
- `.\ADRecon.ps1`
- will create HTML and CSV reports
- For Group Policy, the host you run from should have the `GroupPolicy` PowerShell module installed
