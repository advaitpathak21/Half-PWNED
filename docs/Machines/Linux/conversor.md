# 10.10.11.92

## NMAP
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0174263947bc6ae2cb128b71849cf85a (ECDSA)
|_  256 3a1690dc74d8e3c45136e208062617ee (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://conversor.htb/
Service Info: Host: conversor.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Foothold
- website uses xml and xslt to display nmap code is a pretty HTML way.
- website has the source code
- sent source code to Claude. Found out that xslt is not parsed properly.
    - ![alt text](image-4.png)
- https://ine.com/blog/xslt-injections-for-dummies
    - to start with
        ```
        <?xml version="1.0" encoding="UTF-8"?>
        <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
        <xsl:output method="html" indent="yes" />

        <xsl:template match="/">
            <html>
            <head>
                <title>Nmap Scan Results</title>
            </head>
            <body>
                <h1>Nmap Scan Report</h1>
                <h3>Version: <xsl:value-of select="system-property('xsl:version')"/> </h3>
                <h3>Version: <xsl:value-of select="system-property('xsl:vendor')"/> </h3>
                <h3>Version: <xsl:value-of select="system-property('xsl:vendor-url')"/> </h3>
                # for each xsl statement here
            </body>
            </html>
        </xsl:template>
        </xsl:stylesheet>

        ```
    - ![alt text](image-5.png)
- Tried a lot but getting `URI NOT FOUND` or `XPath` errors
- reading the `app.wsgi` script - 
```
If you want to run Python scripts (for example, our server deletes all files older than 60 minutes to avoid system overload), you can add the following line to your /etc/crontab.

"""
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
"""
```

- start a nc listener
- upload a python3 socket reverse shell with the name `../scripts/shell.py` because the file is being uploaded to `/uploads` folder from the web root.
- the `convert/` page throws an error that `shell.py` was not readable because it doesnt start with `<`
- however, we get a reverse shell a `www-data` on nc
- upload `linpeas.sh` on the target
- shows `/usr/bin/bash` has suid bit set
- gtfobins shows `bash -p` which gives the root shell
