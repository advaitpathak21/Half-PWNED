- `What` to look for and `Why`?
- ![](/attachments/Pasted-image-20250206115747.png)

- `Where` to look for?
- ![](/attachments/Pasted-image-20250206115807.png)
- **An `ASN/IP` is an Autonomous System (ASN) number that identifies a group of IP addresses that are managed by a single entity**

<hr>

## Finding Address Spaces:
- Hurricane Electric from BGP-toolkit - http://he.net/
- get blocks of ips assigned to an org
	- bigger orgs have their own infra
	- smaller orgs use GCP, AWS, CloudFlare, Azure

## DNS
- find reachable hosts not disclosed in the scoping doc
- https://whois.domaintools.com/
- https://viewdns.info/
- if we find new subdomains, we could bring this list to our client to see if any of them should indeed be included in the scope
- subdomains that were not listed in the scoping documents, but reside on in-scope IP addresses and therefore are fair game.

## Public Data
- Websites might have PII data
- Cloud Services can have creds or notes posted
	- https://github.com/trufflesecurity/truffleHog
	- https://buckets.grayhatwarfare.com/
- Google Dorking - 
	- ![](/attachments/Pasted-image-20250206121914.png)
	- https://gist.github.com/sundowndev/283efaddbcf896ab405488330d1bbc06

## Username Harvesting
- https://github.com/initstring/linkedin2username
- scrap data and add it to our list of potential spraying targets

## Creds Hunting
- https://dehashed.com/
- find leaked creds on the site above or
- `sudo python3 dehashed.py -q inlanefreight.local -p`
- 
