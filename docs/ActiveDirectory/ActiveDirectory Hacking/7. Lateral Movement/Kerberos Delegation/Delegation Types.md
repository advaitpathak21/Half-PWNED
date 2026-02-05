### Understanding Kerberos Delegation

#### [here](https://sn0xs-organization.gitbook.io/sn0x-order.org/hack-the-box-writeups/htb-machines/hard/windows/htb-redelegate-vl#background-three-types-of-delegation-in-active-directory)
Background: Three Types of Delegation in Active Directory
**1. Unconstrained Delegation**
- **How it works:** The computer can store TGTs (Ticket Granting Tickets) of all users who authenticate to it
- **Risk:** Can impersonate ANY user to ANY service
- **Requirements:**
	- TRUSTED_FOR_DELEGATION flag on the AD object
	- SeEnableDelegationPrivilege
    - Ability to create computer accounts (MachineAccountQuota > 0) 

**2. Constrained Delegation (S4U2Proxy)**
- **How it works:** The computer can delegate only to SPECIFIC services on behalf of users
- **Risk:** Limited to defined SPNs, but still powerful
- **Requirements:**
    - TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION flag must be set
    - SPN must be defined in the msDS-AllowedToDelegateTo attribute
    - SeEnableDelegationPrivilege (to configure it)
    
**3. Resource-Based Constrained Delegation (RBCD)**
- **How it works:** The TARGET resource controls who can delegate to it
- **Risk:** Requires GenericWrite on target, but no SeEnableDelegationPrivilege needed
- **Requirements:**
    - GenericWrite or similar permissions on target
    - Modify msDS-AllowedToActOnBehalfOfOtherIdentity attribute
- 
