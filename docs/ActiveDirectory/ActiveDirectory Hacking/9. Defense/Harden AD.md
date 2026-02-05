## Step One: Document and Audit
- ![](/attachments/Pasted-image-20250302150524.png)
## People, Processes, and Technology
### People
 - weakest link
 - ![](/attachments/Pasted-image-20250302150614.png)
### Protected Users Group
- This group can be used to restrict what members of this privileged group can do in a domain. Adding users to Protected Users prevents user credentials from being abused if left in memory on a host.
- `Get-ADGroup -Identity "Protected Users" -Properties Name,Description,Members`
- ![](/attachments/Pasted-image-20250302151659.png)

### Process
- Enforce policies
- ![](/attachments/Pasted-image-20250302151747.png)

### Technology
- ![](/attachments/Pasted-image-20250302151816.png)
https://enterprise.hackthebox.com/academy-lab/30000/2125/modules/143/1277
