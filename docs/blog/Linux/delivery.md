# Delivery
<hr>

## NMAP
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 9c40fa859b01acac0ebc0c19518aee27 (RSA)
|   256 5a0cc03b9b76552e6ec4f4b95d761709 (ECDSA)
|_  256 b79df7489da2f27630fd42d3353a808c (ED25519)
80/tcp   open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Welcome
8065/tcp open  unknown
| fingerprint-strings:
|   GenericLines, Help, RTSPRequest, SSLSessionReq, TerminalServerCookie:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 200 OK
|     Accept-Ranges: bytes
|     Cache-Control: no-cache, max-age=31556926, public
|     Content-Length: 3108
|     Content-Security-Policy: frame-ancestors 'self'; script-src 'self' cdn.rudderlabs.com
|     Content-Type: text/html; charset=utf-8
|     Last-Modified: Sun, 02 Nov 2025 22:05:43 GMT
|     X-Frame-Options: SAMEORIGIN
|     X-Request-Id: duibwzy91by1mkdmxwy4yict3a
|     X-Version-Id: 5.30.0.5.30.1.57fb31b889bf81d99d8af8176d4bbaaa.false
|     Date: Sun, 02 Nov 2025 22:08:08 GMT
|     <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=0"><meta name="robots" content="noindex, nofollow"
><meta name="referrer" content="no-referrer"><title>Mattermost</title><meta name="mobile-web-app-capable" content="yes"><meta name="application-name" content="Mattermost"><meta name="format-detection" content="t
elephone=no"><link re
|   HTTPOptions:
|     HTTP/1.0 405 Method Not Allowed
|     Date: Sun, 02 Nov 2025 22:08:08 GMT
|_    Content-Length: 0

```

```

```

<hr>

## Foothold
- found a osTicket site at `helpdesk.delivery.htb`
- found another website at `delivery.htb:8065`

- creating a ticket at helpdesk says that we can access the ticket with the entered email id and the ticket number.
It also creates a new email `123562@delivery.htb` and we can add to our ticket by emailing at this address.

- register a new user at `delivery.htb:8065` with the above email address
- access the ticket to see the registration link
- once we register, we see
```
@developers Please update theme to the OSTicket before we go live.  Credentials to the server are maildeliverer:Youve_G0t_Mail!

Also please create a program to help us stop re-using the same passwords everywhere.... Especially those that are a variant of "PleaseSubscribe!"


root
10:58 AM
PleaseSubscribe! may not be in RockYou but if any hacker manages to get our hashes, they can use hashcat rules to easily crack all variations of common words or phrases.
```
- ssh using `maildeliverer:Youve_G0t_Mail!` to get user.txt - 84a92ce0788a1a6efeff46f2e7e1d5ce

## Privesc

- Login into the OS Ticket `helpdesk.delivery.htb/scp/login.php` using the above `maildeliverer@delivery.htb` creds
- we can see a few hashes instead of usernames
- We know there are `PleaseSubscribe!` combinations for some users
- Running linpeas
```
/etc/mysql/mariadb.cnf
/etc/mysql/mariadb.conf.d/

lrwxrwxrwx 1 root root 22 Dec 26  2020 /etc/alternatives/my.cnf -> /etc/mysql/mariadb.cnf
lrwxrwxrwx 1 root root 24 Dec 26  2020 /etc/mysql/my.cnf -> /etc/alternatives/my.cnf
-rw-r--r-- 1 root root 83 Dec 26  2020 /var/lib/dpkg/alternatives/my.cnf

/etc/mysql/mariadb.conf.d/50-server.cnf

/var/www/osticket/upload/include/ost-config.php

```

- going through the /opt/mattermost config.json file
    - the SQLsettings contain - `mmuser:Crack_The_MM_Admin_PW`
    - this was not seen by me in the first glance. I HATE MYSELF. GENUINELY.

- `mysql -u mmuser -p`

- I FUCKING MISSED THE USERNAME `ROOT` and was trying to crack hashes for other users
- `PleaseSubscribe!21`
- You cannot directly ssh into the box.
- ssh as maildeliverer and then `su root`
    - get the root flag - 2811e0137315014a40fccfa8a4724953
