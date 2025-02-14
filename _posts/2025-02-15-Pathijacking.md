---
layaout: post
title: Path Hijacking
image: /assets/images/path.png
date: 15-02-2025
categories: [Pentesting & Techniques]
tag: [suid, sudoers, binarys, pathijacking]
excerpt: "Path Hijacking is a technique where an attacker manipulates the $PATH environment variable to run malicious code by placing a malicious binary in a directory that is searched before the legitimate one. This can lead to executing unauthorized commands."
---

![img-description](/assets/images/path.png)

Path Hijacking is a technique where an attacker manipulates the $PATH environment variable to run malicious code by placing a malicious binary in a directory that is searched before the legitimate one. This can lead to executing unauthorized commands.

## $PATH IN LINUX
---
In Linux, the `$PATH` is an environment variable that defines a list of directories where the system looks for executable files when a command is entered. When a user runs a command, the shell checks the directories listed in the `$PATH` variable, in order, to find the corresponding executable file. If the command isn't found in any of those directories, an error is returned. The `$PATH` allows the user to run programs by simply typing their name without needing to specify the full path to the executable file.
## ABSOLUTE AND RELATIVE PATH
---
Before exploiting this vulnerability, we need to understand the difference between absolute and relative paths

- **Absolute Path:** This is the full path to a file or command, starting from the root directory (/). An example would be `/usr/bin/fdisk`.

- **Relative Path:** This is a path relative to the current directory you’re in. For example, if you’re in the `/tmp` directory and you run `fdisk`, the system will look for the `fdisk` command in the current directory (`/tmp`), rather than searching the entire system.

## SUID AND SUDOERS HIJACKING
---

In Linux, both SUID and sudoers are mechanisms to elevate privileges, but they operate differently and can be exploited if not properly secured. Understanding these mechanisms is key before diving into path hijacking techniques.

**SUID**:
A program with the **SUID** bit set runs with the privileges of its owner, regardless of the user executing it. For example, if a root-owned program has the SUID bit set, any user running the program will execute it with root privileges.  
While SUID is useful for tasks requiring elevated privileges, it becomes a vulnerability when the program is poorly coded, as it might execute unintended commands or binaries.

**SUDOERS:**
The **sudoers** file defines which commands a user can execute with `sudo`. Unlike SUID, sudoers allows fine-grained control over privileges. For instance, you can specify that a user can only run a particular program with root privileges, reducing the risk of misuse.  
Sudoers is generally safer than SUID because it includes logging and granular control, but it can still be exploited if the allowed commands are insecurely implemented or if the user's environment (e.g., `$PATH`) is manipulated.

### Abusing a binary with suid or sudoers privileges:
----
Let's consider this program as an example. When we analyze it using a tool like `strings`, we can see that it calls `cat`, `fdisk`, and `lshw` without specifying their absolute paths. As attackers, we can take advantage of this by creating a malicious file with the same name as one of these binaries in a directory where we have write permissions. Once the malicious file is created, we can modify our `$PATH` variable to prioritize our directory over the default system directories. This way, when the program is executed, it will first look in our directory and execute our malicious script instead of the legitimate binary. Since the program is running with elevated privileges (e.g., as root), our script will execute with those privileges, allowing us to escalate our privileges and gain unauthorized access to the system.

````bash
❯ strings /usr/bin/sysinfo
====================Hardware Info====================
lshw -short
====================Disk Info====================
fdisk -l
====================CPU Info====================
cat /proc/cpuinfo
````

So, we can create a file with the same name as the command, using a relative path, in a directory where we have write permissions.

````
echo -e "#!/bin/bash\nchmod u+s /bin/bash" > cat
chmod +x cat
````

Modify your `$PATH` to include the current directory where the malicious script is located. You can do this by running one of the following commands:

````bash
export PATH=$(pwd):$PATH  # This one take your current path
export PATH=.:$PATH  # This one also take your current path
export PATH=$PATH:/home/user/scripts # With this one you can specify the directory

````

This will make the current directory (obtained from `pwd`) the first directory in the `$PATH`, so the system will check there for commands before anywhere else.

````bash
theseus@magic:/tmp$ /bin/sysinfo
theseus@magic:/tmp$ /bin/bash -p
bash-4.4# whoami
root
````

This works because `sysinfo` uses relative paths to invoke system commands (like `fdisk`, `lshw`, `free`, etc.). When the system searches for these commands, it uses the `$PATH` environment variable. If the `$PATH` is manipulated to include the current directory (where the attacker’s malicious file resides), the system will run the malicious file instead of the legitimate system command.

### Abusing sudoers with SETENV
---
The important part here is the SETENV directive, which allows the user to modify environment variables (like $PATH) when running commands with sudo.

What does this mean for Path Hijacking?
When the SETENV directive is present, it allows a user to modify the environment for the command they're running. In particular, they can manipulate the $PATH variable. 
````bash
wizard@photobomb:~$ sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh  
````
Here's how it works in this scenario:

Bypassing the system's security path: Normally, when you execute a command, the system looks for executables in a specific order, starting from the directories listed in the $PATH. The entry for secure_path in the sudoers file (/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin) ensures that certain trusted directories are prioritized.

Exploiting SETENV to modify $PATH: The SETENV directive allows the user to set or modify environment variables, including $PATH, when executing a command with sudo. This means that before running /opt/cleanup.sh as root, the user can prepend directories they control (e.g., their home directory or /tmp) to $PATH.

For example, the user can run:

````bash
sudo PATH=$PWD:$PATH /opt/cleanup.sh
````

This command temporarily changes the $PATH variable to include the current directory ($PWD) before the directories in the default $PATH. By doing this, the system will look for executables in the current directory first.

Executing malicious binaries: If the user has placed a malicious binary (for example, a binary named ls, cat, or any other command) in their current directory, it will be executed instead of the legitimate system binaries when the script /opt/cleanup.sh tries to call them.

This can lead to privilege escalation, as the attacker could have crafted a malicious version of a command that gets executed with root privileges, potentially giving them control over the system.

## PYTHON LIBRARY HIJACKING
---
Python Library Hijacking is a technique where an attacker places a malicious Python file with the same name as a legitimate library (e.g., os.py or shutil.py) in a location that Python searches first (e.g., the current working directory or a path specified in the PYTHONPATH environment variable).

When a Python script imports the legitimate library, the malicious file is loaded instead, allowing the attacker to execute arbitrary code. This relies on Python's module search order, making it a risk in poorly configured or untrusted environments.
### Python Library Hijacking with SETENV
---
In this case, the same principles observed in $PATH Hijacking apply here. Specifically, we have identified that a Python script can be executed as ROOT using the SETENV option. This allows us to manipulate the PYTHONPATH environment variable, which controls the directories Python searches for modules to import.

By injecting a malicious module into a directory prioritized in the search order (e.g., /tmp or another writable directory added to PYTHONPATH), we can force the script to import our code instead of legitimate libraries. This provides the opportunity to escalate privileges or execute arbitrary commands with root permissions, leveraging the inherent trust in the Python module search mechanism.

````bash
waldo@admirer:/var/tmp$ sudo -l
[sudo] password for waldo: 
Matching Defaults entries for waldo on admirer:
    env_reset, env_file=/etc/sudoenv, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    listpw=always

User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/backup.py
````
Upon examining the script, we notice that it imports the shutil library. We can exploit this by creating our own malicious version of the library. By placing our crafted library in a directory prioritized in the PYTHONPATH, we can hijack the import process.

When the script attempts to load the legitimate shutil, it will instead execute our malicious code, allowing us to perform arbitrary actions with the privileges granted to the script, potentially including root-level access. This is a classic example of Python Library Hijacking, leveraging the trust in Python's module resolution order.
````python
waldo@admirer:cat backup.py
#!/usr/bin/python3
from shutil import make_archive
src = '/var/www/html/'
# old ftp directory, not used anymore
#dst = '/srv/ftp/html'
dst = '/var/backups/html'
make_archive(dst, 'gztar', src)
````
Once the malicious library is created, we will execute the script with elevated privileges using sudo, but first, we will assign the PYTHONPATH environment variable. This ensures that the script prioritizes our malicious library during the import process, effectively redirecting the execution flow to our code.

By doing so, we can exploit the script's behavior to execute arbitrary commands or perform unauthorized actions under root privileges, leveraging the manipulated library.

````bash
sudo PYTHONPATH=/var/tmp /opt/scripts/backup.py
````
### Python Library Hijacking via Path Precedence
---
When Python imports a library, it searches through a list of directories defined in sys.path in a specific order. If you have write permissions in a higher-priority directory (e.g., the second path in sys.path), and the program is trying to load a library from a lower-priority directory (e.g., the third path), you can exploit this by placing a malicious library with the same name in the higher-priority directory.

**Steps for reproduce**

First, we need to determine the order in which the libraries are loaded by running the following command:

````bash
waldo@admirer:/var/tmp$ python3 -c 'import sys; print("\n".join(sys.path))'
/usr/lib/python35.zip  # 1º
/usr/lib/python3.5     # 2º 
/usr/lib/python3.5/plat-x86_64-linux-gnu # 3º
/usr/lib/python3.5/lib-dynload # 4º
/usr/local/lib/python3.5/dist-packages # 5º
/usr/lib/python3/dist-packages # 6º
````

Then or example, if we have write permissions in `/usr/lib/python3.5` (2nd in the sys.path order) and the library is normally loaded from `/usr/lib/python3.5/lib-dynload` (4th in the order), we can exploit this by creating a malicious library with the same name in the directory where we have write permissions. Since Python imports libraries in the order defined by sys.path, it will prioritize our malicious library over the legitimate one when the script attempts to import it. This allows us to execute our malicious code whenever the library is called.

### Exploiting Write Access on Python Modules
---

In this example, we exploit a Python script that runs periodically, such as through a crontab (a scheduled task). The script imports various Python modules to execute its functions. If any of these imported modules are in directories where we have write access, we can modify them to include malicious code.

When the script runs, it will import our modified module and execute the injected code. This could allow us to gain unauthorized access, execute arbitrary commands, or elevate privileges depending on the script's context.

The risk increases if the script runs with elevated privileges, such as through sudo, SUID, or other privileged contexts. In these cases, our injected code will inherit those privileges, making this a powerful attack vector.

The success of this technique depends on identifying writable directories in the module's search path and crafting payloads that align with the script’s execution.

````python
import logging
import subprocess
from colorama import Fore, Style, init

# Initialize colorama (for cross-platform support)
init(autoreset=True)

# Configure logging to write to a file (plain text)
logging.basicConfig(
    filename='/var/log/sshFailed.log',  # Log file path
    level=logging.INFO,  # Log level
    format='%(asctime)s - %(levelname)s - %(message)s'  # Plain text format for log file
)
continue ....
````
We can try to find the module logging,subprocess or colorama and if we have write permissions we can inyect our malicious code there

````bash
❯ locate logging.py
/usr/lib/python3/dist-packages/pip/_internal/utils/logging.py
❯ ls -la /usr/lib/python3/dist-packages/pip/_internal/utils/logging.py
.rwxrwxrwx root root 12 KB Sun Jan 26 17:41:40 2025  /usr/lib/python3/dist-packages/pip/_internal/utils/logging.py
````