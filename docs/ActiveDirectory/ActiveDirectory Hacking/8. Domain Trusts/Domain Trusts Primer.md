- Large orgs acquire new companies and for ease of use, they establish a trust relationship with the new domain.
- A [trust](https://social.technet.microsoft.com/wiki/contents/articles/50969.active-directory-forest-trust-attention-points.aspx) is used to establish forest-forest or domain-domain (intra-domain) authentication
- Allows users to access resources in another domain, outside of the main domain
- This trust creates a link between the authentication systems of 2 domains and can allow uni or bi-d commz
- ![](/attachments/Pasted-image-20250301143016.png)
- ![](/attachments/Pasted-image-20250301145112.png)
- ![](/attachments/Pasted-image-20250301143313.png)
- ![](/attachments/Pasted-image-20250301145144.png)
- It is not uncommon to be able to perform an attack such as Kerberoasting against a domain outside the principal domain and obtain a user that has administrative access within the principal domain.

<hr>

### Enum Trust Relationships

**activedirectory**
- `Import-Module activedirectory`
- `Get-ADTrust -Filter *`
	- returns `direction`, `name`, `source`, `intra-forest`, `foresttransitive` (external or forest trust)

**PowerView**
- `Import-Module PowerView`
- `Get-DomainTrust`
- `Get-DomainTrustMapping` - like recursive checking
- `Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName` 
	- check users in the child domain `LOGISTICS.INLANEFREIGHT.LOCAL`

**netdom**
- `netdom query /domain:inlanefreight.local trust` - find trust relationships
- `netdom query /domain:inlanefreight.local dc` - find dc
- `netdom query /domain:inlanefreight.local workstation` - find workstations or servers

**BloodHound**
- `Map Domain Trusts` pre-built query

