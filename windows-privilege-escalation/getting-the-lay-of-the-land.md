# Getting the Lay of the Land

## **Situational Awareness**

* `ipconfig /all` → view interfaces, ip, dns info
* `arp -a` → view arp table
* `route print` → view routing table
* `PS C:\\htb> Get-MpComputerStatus` → checking windows defender status
* `PS C:\\htb> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections` → list applocker rules
* `PS C:\\htb> Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\\Windows\\System32\\cmd.exe -User Everyone` → testing applocker policy

## **Initial Enumeration**

* OS name
* Version
* Running Services
* `tasklist /svc` → look at running processes
* `set` → view environment variables
* `systeminfo`
*   `wmic product get name` → display installed software from cmd

    `Get-WmiObject -Class Win32_Product | select Name, Version` → display installed software from powershell
* `netstat -ano` → display active TCP and UDP connections
* `C:\\htb> query user` → view logged in users
* `C:\\htb> whoami /priv` → view current user privileges
* `C:\\htb> whoami /groups` → view current user group information
* `net localgroup "Backup Operators"` → list uses of backup operators group
* `C:\\htb> net user` → get all user
* `C:\\htb> net localgroup` → get all groups
* `C:\\htb> net accounts` → **Get Password Policy & Other Account Information**
* `C:\\htb> pipelist.exe /accepteula` → listing named pipes with pipelist

After obtaining a listing of named pipes, we can use [Accesschk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) to enumerate the permissions assigned to a specific named pipe by reviewing the Discretionary Access List (DACL), which shows us who has the permissions to modify, write, read, or execute a resource.

*   `C:\\htb> accesschk.exe /accepteula \\\\.\\Pipe\\lsass -v`

    or `accesschk.exe -accepteula -w` \pipe\SQLLocal\SQLEXPRESS01 `-v`
