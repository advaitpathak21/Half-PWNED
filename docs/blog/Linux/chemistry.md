# Chemistry

1. CIF File upload
2. CVE-2024-23346 to run a python script flaw in the pymatgen library 
    [cve](https://www.vicarius.io/vsociety/posts/critical-security-flaw-in-pymatgen-library-cve-2024-23346)
3. Get a reverse shell to our machine

<hr>

4. `netstat -tunlp | grep LISTEN` -> A localhost server is running on port 8080
5. `curl -I localhost:8080` -> An AIOHTTP/3.9.1 server is running here
6. CVE-2024-23334 [github bash cript](https://github.com/z3rObyte/CVE-2024-23334-PoC)
7. This script does not give us any output as the `static` folder might not be same in our target machine
8. `curl localhost:8080`
9. Reading through the request, we can see it is fetching data from the `assets` folder.

10. Modify the github exploit to use `assets` as the payload instead of `static`. Run the bash exploit again to get the /root/root.txt flag.
