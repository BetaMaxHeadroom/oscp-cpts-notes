# Hunting For A User

<details>

<summary>Enumerating &#x26; Retrieving Password Policies</summary>

### **Enumerating & Retrieving - from Linux - Credentialed ⭐**

With valid domain credentials, password policy can be obtained remotely using tools like `crackmapexec` or `rpcclient`

```
dollarboysushil@htb[/htb]$ crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-polSMB

         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\\avazquez:Password123
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] Dumping password info for domain: INLANEFREIGHT
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Minimum password length: 8
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Password history length: 24
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Maximum password age: Not Set
SMB         172.16.5.5      445    ACADEMY-EA-DC01
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Password Complexity Flags: 000001
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Refuse Password Change: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Password Store Cleartext: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Password Lockout Admins: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Password No Clear Change: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Password No Anon Change: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Password Complex: 1
```

### **Enumerating the Password Policy - from Linux - SMB NULL Sessions ⭐**

Without valid credentials, we can get password policy using SMB NULL sessions

SMB NULL sessions allow an unauthenticated attacker to retrieve information from the domain, such as a complete listing of users, groups, computers, user account attributes, and the domain password policy.

* `rpcclient -U "" -N 172.16.5.5`
* then run rpc command such as `querydominfo` to confirm NULL sessions access
* then rpc command`getdompwinfo` gives us the password policy.

#### Using [enum4linux](https://labs.portcullis.co.uk/tools/enum4linux) ⭐

* `enum4linux -P 172.16.5.5` -p flag specifies for password policy

#### Using [enum4linux](https://github.com/cddmp/enum4linux-ng)-ng

* `enum4linux-ng -P 172.16.5.5 -oA ilfreight` → enum4linux-ng is rewrite of enum4linux in python with additional features like export.

### **Enumerating Null Session - from Windows**

uncommon to do null session attack from windows.

* `C:\\htb> net use \\\\DC01\\ipc$ "" /u:""` → establishing null sessions

### **Enumerating the Password Policy - from Linux - LDAP Anonymous Bind**

#### **Using ldapsearch**

* `ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength`

### **Enumerating the Password Policy - from Windows ⭐**

If we are authenticated to the domain from a windows host, we can use `net.exe` to retrieve the password policy.

</details>

<details>

<summary>Password Spraying - Making a Target User List</summary>



&#x20;1️⃣ **SMB NULL Session to Pull User List**

#### **Using enum4linux**

* `enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"`

#### **Using rpcclient**

```
dollarboysushil@htb[/htb]$ rpcclient -U "" -N 172.16.5.5
rpcclient$> enumdomusers
```

#### **Using CrackMapExec --users Flag**

* `crackmapexec smb 172.16.5.5 --users`

&#x20;2️⃣ **Gathering Users with LDAP Anonymous**

#### **Using ldapsearch**

* `dollarboysushil@htb[/htb]$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "`

it is easier to use windapsearch

#### **Using windapsearch**

* `./windapsearch.py --dc-ip 172.16.5.5 -u "" -U`

&#x20;3️⃣ **Enumerating Users with Kerbrute ⭐**

if we have no access at all from our position in the internal network, we can use `Kerbrute` to enumerate valid AD accounts and for password spraying. this tool uses Kerberos Per-Authentication, which is much faster and stealthier

this method does not generate Windows event ID or logon failure.

The tool sends TGT requests to the domain controller without Kerberos Pre-Authentication to perform username enumeration. If the KDC responds with the error `PRINCIPAL UNKNOWN`, the username is invalid.

* `kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt`

\<aside> 4️⃣ **Credentialed Enumeration to Build our User List**

\</aside>

Once we get valid credential, we can use various tools to build get the user from AD

* `sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users` → this will give the list of users

</details>
