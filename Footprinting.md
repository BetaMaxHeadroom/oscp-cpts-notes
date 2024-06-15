# Footprinting

# FTP `File Transfer Protocol`

uses port `20` for data and `21` for command

# **FTP**

- uses `TCP`
- is a `clear text protocol` this sniffing is possible
- `anonymous FTP` is possible
- runs within `application layer` of TCP/IP, same layer as HTTP or POP

ftp commands [https://www.serv-u.com/ftp-server-windows/commands](https://www.serv-u.com/ftp-server-windows/commands)

## TFTP

- simpler than FTP and `does not provide user authentication`
- uses `UDP`

## vsFTPd

- default config location  `/etc/vsftpd.conf`

# **SMB**`Server Message Block`

- uses port `445`
- uses `TCP`

`smbmap -H 10.129.22.122//sambashare` → Enumerating smb share

`smbclient --no-pass [//10.129.22.122/sambashare](https://10.129.22.122/sambashare)` → connecting to share

| Command | Description |
| --- | --- |
| smbclient -N -L //<FQDN/IP> | Null session authentication on SMB. |
| smbclient //<FQDN/IP>/<share> | Connect to a specific SMB share. |
| rpcclient -U "" <FQDN/IP> | Interaction with the target using RPC. |
| samrdump.py <FQDN/IP> | Username enumeration using Impacket scripts. |
| smbmap -H <FQDN/IP> | Enumerating SMB shares. |
| crackmapexec smb <FQDN/IP> --shares -u '' -p '' | Enumerating SMB shares using null session authentication. |
| enum4linux-ng.py <FQDN/IP> -A | SMB enumeration using enum4linux. |

rpcclient different query

| Query | Description |
| --- | --- |
| srvinfo | Server information. |
| enumdomains | Enumerate all domains that are deployed in the network. |
| querydominfo | Provides domain, server, and user information of deployed domains. |
| netshareenumall | Enumerates all available shares. |
| netsharegetinfo <share> | Provides information about a specific share. |
| enumdomusers | Enumerates all domain users. |
| queryuser <RID> | Provides information about a specific user. |

# NFS `Network File System`

- Its purpose is to access file systems over a network as if they were local
- uses port `111` for portmapper and `2049` for NFA data

`showmount -e IP` to list the NFS

![Untitled](.gitbook/assets/Footprinting%203286871dc7e44f489db1ce6c4e0f296c/Untitled.png)

`sudo mount -t nfs target_ip:/{share} local_folder_location -o nolock`  to mount into our local device

• **`-o nolock`**: An option to disable file locking. This can be useful if the NFS server does not support locking or if you are facing issues with file locks.

![Untitled](.gitbook/assets/Footprinting%203286871dc7e44f489db1ce6c4e0f296c/Untitled%201.png)

![Untitled](.gitbook/assets/Footprinting%203286871dc7e44f489db1ce6c4e0f296c/Untitled%202.png)

to unmount

`cd ..`

`sudo umount ./foldername`

| Command | Description |
| --- | --- |
| showmount -e <FQDN/IP> | Show available NFS shares. |
| mount -t nfs <FQDN/IP>:/<share> ./target-NFS/ -o nolock | Mount the specific NFS share.umount ./target-NFS |
| umount ./target-NFS | Unmount the specific NFS share. |

# DNS `Domain Name System`

port `53`

Different `DNS records`

| DNS Record | Description |
| --- | --- |
| A or Address  | Returns an IPv4 address of the requested domain as a result. |
| AAAA or quad A | Returns an IPv6 address of the requested domain. |
|  |  |
| CNAME | Resolves a domain or subdomain to another domain name.
This record serves as an alias. If the domain www.hackthebox.eu should point to the same IP, and we create an A record for one and a CNAME record for the other. |
|  |  |
| MX | points to the server where email should be delivered for that domain name.
Returns the responsible mail servers as a result. |
|  |  |
| SOA Start of authority | Provides information about the corresponding DNS zone and email address of the administrative contact. |
|  |  |
| NS | Returns the DNS servers (nameservers) of the domain. |
|  |  |
| TXT | This record can contain various information. The all-rounder can be used, e.g., to validate the Google Search Console or validate SSL certificates. In addition, SPF and DMARC entries are set to validate mail traffic and protect it from spam. |
|  |  |
| PTR | The PTR record works the other way around (reverse lookup). It converts IP addresses into valid domain names. |

DNS Enumeration: 

# SMTP `Simple Mail Transfer Protocol`

-port 25  newer uses port `587`

### **SMTP**

| Command | Description |
| --- | --- |
| telnet <FQDN/IP> 25 |  |
| smtp-user-enum -M VRFY -U footprinting-wordlist.txt -t 10.129.46.181 | smtp username enumeration |

# IMAP`Internet Message Access Protocol`  / POP3 Post Office Protocol

| Command | Description |
| --- | --- |
| curl -k 'imaps://<FQDN/IP>' --user <user>:<password> | Log in to the IMAPS service using cURL. |
| openssl s_client -connect <FQDN/IP>:imaps | Connect to the IMAPS service. |
| openssl s_client -connect <FQDN/IP>:pop3s | Connect to the POP3s service. |

# SNMP `Simple Network Management Protocol`

- it is a protocol for monitoring and managing network devices
- Current version `snmpv3`

For footprinting SNMP, we can use tools like `snmpwalk`, `onesixtyone`, and `braa`

| Command | Description |
| --- | --- |
| snmpwalk -v2c -c <community string> <FQDN/IP> | Querying OIDs using snmpwalk. |
| onesixtyone -c community-strings.list <FQDN/IP> | Bruteforcing community strings of the SNMP service. |
| braa <community string>@<FQDN/IP>:.1.* | Bruteforcing SNMP service OIDs. |

# MySQL and MSSQL

| Command | Description |
| --- | --- |
| mysql -u <user> -p<password> -h <FQDN/IP> | Login to the MySQL server. |

### **MSSQL**

| Command | Description |
| --- | --- |
| mssqlclient.py <user>@<FQDN/IP> -windows-auth | Log in to the MSSQL server using Windows authentication. |

# **Oracle TNS `Oracle Transparent Network Substrate`**

- protocol that facilitates communication between oracle database and applications over networks.
- `1521` port

we can use `odat` to perform scan , retrieve database names, passwords and other data.
then we can use `sqlplus` to connect to oracle data

sqlplus commands ⇒ [https://docs.oracle.com/cd/E11882_01/server.112/e41085/sqlqraa001.htm#SQLQR985](https://docs.oracle.com/cd/E11882_01/server.112/e41085/sqlqraa001.htm#SQLQR985)

| Command | Description |
| --- | --- |
| ./odat.py all -s <FQDN/IP> | Perform a variety of scans to gather information about the Oracle database services and its components. |
| sqlplus <user>/<pass>@<FQDN/IP>/<db> as sydba  | Log in to the Oracle database. as sysdba gives us highest level of admin privileges. |
| ./odat.py utlfile -s <FQDN/IP> -d <db> -U <user> -P <pass> --sysdba --putFile C:\\insert\\path file.txt ./file.txt |  |

# IPMI `Intelligent Platform Management Interface`

IPMI (**Intelligent Platform Management Interface**) is a set of standardized specifications for hardware-based platform management systems that makes it possible to control and monitor servers centrally.

port `623`

| Command | Description |
| --- | --- |
| msf6 auxiliary(scanner/ipmi/ipmi_version) | IPMI version detection. |
| msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) | Dump IPMI hashes. |

### **Linux Remote Management**

| Command | Description |
| --- | --- |
| ssh-audit.py <FQDN/IP> | Remote security audit against the target SSH service. |
| ssh <user>@<FQDN/IP> | Log in to the SSH server using the SSH client. |
| ssh -i private.key <user>@<FQDN/IP> | Log in to the SSH server using private key. |
| ssh <user>@<FQDN/IP> -o PreferredAuthentications=password | Enforce password-based authentication. |

### **Windows Remote Management**

| Command | Description |
| --- | --- |
| rdp-sec-check.pl <FQDN/IP> | Check the security settings of the RDP service. |
| xfreerdp /u:<user> /p:"<password>" /v:<FQDN/IP> | Log in to the RDP server from Linux. |
| evil-winrm -i <FQDN/IP> -u <user> -p <password> | Log in to the WinRM server. |
| wmiexec.py <user>:"<password>"@<FQDN/IP> "<system command>" | Execute command using the WMI service. |