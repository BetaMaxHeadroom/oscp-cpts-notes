# Sniffing out a Foothold

### LLMNR/NBT-NS Poisoning From Linux

`LLMNR` is a protocol used to identify hosts when DNS fails to do so. Previously known as `NBT-NS`

<figure><img src="../.gitbook/assets/Untitled (5).png" alt=""><figcaption></figcaption></figure>

n last step when victim connects to us it sends us its `username` and `NTLM` hash. Which we will intercept using responder.

In short

1. A host attempts to connect to the print server at \\\print01.inlanefreight.local, but accidentally types in \\\printer01.inlanefreight.local.
2. The DNS server responds, stating that this host is unknown.
3. The host then broadcasts out to the entire local network asking if anyone knows the location of \\\printer01.inlanefreight.local.
4. The attacker (us with `Responder` running) responds to the host stating that it is the \\\printer01.inlanefreight.local that the host is looking for.
5. The host believes this reply and sends an authentication request to the attacker with a username and NTLMv2 password hash.
6. This hash can then be cracked offline or used in an SMB Relay attack if the right conditions exist.

RUN RESPONDER

* `sudo responder -I {interface}` → run responder

<figure><img src="../.gitbook/assets/Untitled (6).png" alt=""><figcaption></figcaption></figure>

Though not covered in this module, these hashes can also sometimes be used to perform an SMB Relay attack to authenticate to a host or multiple hosts in the domain with administrative privileges without having to crack the password hash offline.

## In windows we will use [Inveigh](https://github.com/Kevin-Robertson/Inveigh)

If we end up with a Windows host as our attack box, our client provides us with a Windows box to test from, or we land on a Windows host as a local admin via another attack method and would like to look to further our access, the tool [Inveigh](https://github.com/Kevin-Robertson/Inveigh) works similar to Responder, but is written in PowerShell and C#.

* `PS C:\\htb> Import-Module .\\Inveigh.ps1` → importing module.
*   `Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y` → starting inveigh with llmnr and NBNS spoofing and output to the console and write to a file.

    ### **`C# Inveigh (InveighZero)`**

    Powershell version is no longer updated, C# version is maintained update by the authors.
*   `PS C:\\htb> .\\Inveigh.exe` → run the c# version, which will start capturing the hash.

    We can hit the `esc` key to enter the console while Inveigh is running.

    After typing `HELP` and hitting enter, we are presented with several options:

    We can quickly view unique captured hashes by typing `GET NTLMV2UNIQUE`.

    We can type in `GET NTLMV2USERNAMES` and see which usernames we have collected.

