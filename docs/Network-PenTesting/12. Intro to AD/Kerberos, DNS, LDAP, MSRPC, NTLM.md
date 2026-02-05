![](/attachments/Pasted-image-20250203220659.png)

# Kerberos

![](/attachments/Pasted-image-20250203205131.png)
**The Kerberos protocol uses port 88 (both TCP and UDP). When enumerating an Active Directory environment, we can often locate Domain Controllers by performing port scans looking for open port 88 using a tool such as Nmap.**

<hr>

# DNS
- AD DS uses DNS to allow clients to locate the Domain controllers and for DCs to commx amongst themselves
- ![](/attachments/Pasted-image-20250203205610.png)

### DNS lookup
**Forward**
- `nslookup inlanefreight.local`

**Reverse**
- `nslookup 172.16.6.5`

**Find IP of a host**
- `nslookup ACADEMY-EA-DC01`

<hr>

# LDAP
- used for directory lookups
- LDAP is the language of applications communicating with servers that provide directory services.
- The relationship between AD and LDAP can be compared to Apache and HTTP. The same way Apache is a web server that uses the HTTP protocol, Active Directory is a directory server that uses the LDAP protocol.

<hr>

## MSRPC
- lsarpc
- netlogon
- samr
- drsuapi

<hr>

# NTLM

## LM
- LAN Manager or LANMAN
- old hashing
- max 14 chars
- ![](/attachments/Pasted-image-20250203215555.png)

## NTHash (NTLM)
- modern Windows systems using the NTLM hash
- challenge response.
- hashes stored in SAM (local) or NTDS.DIT (AD)
- NT HASH algorithm -> `MD4(UTF-16-LE(password))`

- ![](/attachments/Pasted-image-20250203220005.png)

**Neither LM nor NT use salts**

## NTLMv1 (Net-NTLMv1)
- cant be used for pass the hash
- uses both NT and LM hash

## NTLMv2 (Net-NTLMv2)

## Domain Cached Creds (MSCache2)
- The above methods require commx with the DC
- If the DC is not reachable, tje Domain Cached Credentials (DCC) can be used.
- Cant be used in Pass the hash
- **Hosts save the last `ten` hashes for any domain users that successfully log into the machine in the `HKEY_LOCAL_MACHINE\SECURITY\Cache` registry key.**
- eg: `$DCC2$10240#bjones#e4e938d12fe5974dc42a90120bd9c90f`
