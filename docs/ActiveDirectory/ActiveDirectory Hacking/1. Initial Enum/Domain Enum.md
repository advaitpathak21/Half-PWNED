- Jot down Key Data Points
	- ![](/attachments/Pasted-image-20250206145556.png)

## TTPs
- AD is HUGE
- create a game plan to enumerate AD in a progressive way
- `passive` identification of any host in the network
- `active` validation to find more about the host (services, names, vulns)
	- probe the host after validation

<hr>

## Identifying Hosts

### Network Sniffing
- "put your ear to the wire" - **WIRESHARE** or **TCPDump**
- If no wiresharm
	-  [tcpdump](https://linux.die.net/man/8/tcpdump), [net-creds](https://github.com/DanMcInerney/net-creds), and [NetMiner](https://www.netminer.com/en/product/netminer.php),
-  `pktmon.exe` - windows 10 network monitoring tool
- Save PCAP files to analyze them later

### Responder
- listen, analyze, poison LLMNR, NBT-NS, MDNS requests and responses.
- **Analyze Mode**
	- `sudo responder -I ens224 -A`
- *We might find new hosts not found already using wireshark*
<br>
- With a few hosts in our bank, we can perform ICMP sweep of the subnet using `fping` - https://fping.org/
- can script using fping and uses round-robin to cycle between hosts.
- **Ping sweep a network using fping**
	- `fping -asgq 172.16.5.0/23`
- We get a list of IPs that are up.

<hr>

## NMAP Scanning
- protocols with *AD* - **DNS, SMB, LDAP, Kerberos**
- Save the above found ips to **hosts.txt**
- **NMAP to enumerate hosts**
	- `sudo nmap -v -A -iL hosts.txt -oN /home/htb-student/Documents/host-enum`

<hr>

## Identifying Users
- If the pentest starts without any creds, we need to find a cleartext password or use an NTLM hash for a user account.
- Some foothold is great to open up opps to perform enum and even attacks

### **Kerbrute** - Internal AD Username enum
- https://github.com/ropnop/kerbrute/releases/latest - **get a binary**
- Kerbrute is silent. Kerberos pre-auth failure is not logged. Used by `Kerbrute`
<br>
- Use `kerbrute` with the likely usernames `jsmith.txt & jsmith2.txt` - https://github.com/insidetrust/statistically-likely-usernames
``` sh
# Installing Kerbrute
sudo git clone https://github.com/ropnop/kerbrute.git
make help
# Get All Binaries (Linux, Win, Mac)
sudo make all
# Binaries present here
cd dist/ 

# Add to our PATH
echo $PATH
sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
```

- **Enumerate users using Kerbrute**
	- `kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users`
- This will output a list of valid usernames
- We can use this list for password spraying

<hr>

## Identifying Potential Vulnerabilities
- **NT AUTHORITY\SYSTEM** - local system account : has highest access in the OS which is used to run most Windows services
- A `SYSTEM` account on a `domain-joined` host will be able to enumerate AD by impersonating the computer account (another user account).
- `SYSTEM` is like `domain user` account
<br>
- GAIN `SYSTEM`
	- ![](/attachments/Pasted-image-20250206213708.png)
- USE `SYSTEM`
	- ![](/attachments/Pasted-image-20250206213734.png)

<hr>

![](/attachments/Pasted-image-20250206214203.png)
