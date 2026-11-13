# Incident Report: XXE Infiltration – XML External Entity (XXE) Exploitation, Credential Theft & MySQL / Web Shell Compromise

| Metadata | Details |
| :--- | :--- |
| **Date** | November 2026 |
| **Analyst** | Piotr Asyngier |
| **Tools Used** | Wireshark (PCAP Network Forensics: `XXEinfiltration.pcap`) |
| **Category** | Web Application Forensics, XXE Injection & Database Compromise |
| **Affected Environment** | Web / DB Server: `pageturner4books.net` (`50.239.151.185`) |

---

## 1. Executive Summary
Network monitoring detected an aggressive TCP port scan followed by anomalous HTTP `POST` requests and external database authentication targeting the **`pageturner4books.net`** web server (**`50.239.151.185`**). A forensic analysis of the network packet capture (`XXEinfiltration.pcap`, comprising `88,577` packets) was conducted in **Wireshark** to reconstruct the attack chain, identify exfiltrated configuration files, and scope the post-exploitation impact.

The investigation confirmed a multi-stage compromise originating from external IP address **`210.106.114.183`**:
1. **Reconnaissance (SYN Scan):** The attacker scanned the victim host (`50.239.151.185`), discovering open TCP ports `80` (HTTP) and **`3306`** (MySQL).
2. **Initial Exploitation (XXE Injection):** The attacker targeted the vulnerable XML upload endpoint **`/review/upload.php`** by uploading **`TheGreatGatsby.xml`**, which contained an XML External Entity (`<!ENTITY xxe SYSTEM "file:///etc/passwd">`) payload.
3. **Credential Harvesting (`config.php`):** Using a second malicious XML file (`ToKillAMockingbird.xml`), the attacker read `/var/www/html/config.php` and extracted plaintext MySQL credentials (`webuser` / **`Winter2024`**).
4. **Database Access & Persistence:** At **`2024-05-31 12:08 UTC`**, the attacker authenticated directly to the exposed MySQL service (`3306`) and subsequently leveraged Out-of-Band (OOB) XXE / file staging to deploy a persistent PHP web shell (**`booking.php`**).

---

## 2. Network Traffic Investigation & Technical Analysis

### 2.1. Port Scan Analysis & Highest Open Port Identification (`3306`)
To identify which services were exposed on the victim server (`50.239.151.185`) during the attacker's initial reconnaissance, Wireshark was filtered for `SYN-ACK` responses (`tcp.flags.syn == 1 and tcp.flags.ack == 1`).

* **Wireshark Display Filter:**
  ```wireshark
  tcp.flags.syn == 1 and tcp.flags.ack == 1
  ```
* **Findings:**
  * Sorting the `SYN-ACK` responses by the `Source Port` column revealed two open TCP ports responding from `50.239.151.185` to `210.106.114.183`: port `80` (HTTP) and port **`3306`** (MySQL).
  * In Frame `51` (`0.068081s`), `50.239.151.185` responded from `Source Port: 3306` (`3306 -> 39658 [SYN, ACK]`), confirming **`3306`** as the highest-numbered open TCP port.

<img width="1852" height="961" alt="obraz" src="https://github.com/user-attachments/assets/b2570512-f079-40b3-9351-c51d6ba2db97" />


---

### 2.2. Vulnerable PHP Script URI Identification (`/review/upload.php`)
Following the port scan, the investigation focused on HTTP `POST` requests sent by the attacker (`210.106.114.183`) to the web application on port `80` (`Host: pageturner4books.net`).

* **Wireshark Display Filter:**
  ```wireshark
  http.request.method == "POST"
  ```
* **Findings:**
  * Inspecting the HTTP `POST` requests (`Referer: http://pageturner4books.net/review/form.html`) revealed that XML book review files were being submitted via `multipart/form-data` to the following URI:
    * **`/review/upload.php`** (`Full request URI: http://pageturner4books.net/review/upload.php`).

<img width="1852" height="961" alt="obraz" src="https://github.com/user-attachments/assets/cbe756c7-a80f-4ba3-8c47-7f74e0328f4d" />


---

### 2.3. Initial Malicious XML Upload Identification (`TheGreatGatsby.xml`)
To establish the timeline of the XXE exploitation, the first HTTP `POST` request targeting `/review/upload.php` (Frame `88328`, `tcp.stream eq 10459`) was reconstructed.

* **Wireshark Display Filter:**
  ```wireshark
  http.request.method == "POST"
  ```
  *(Followed by `Follow -> HTTP Stream` on `tcp.stream eq 10459`)*
* **Findings:**
  * At **`2024-05-31 11:57:03.511029 UTC`** (Frame `88328`), the attacker uploaded the first malicious XML payload with the following `Content-Disposition` header:
    ```http
    Content-Disposition: form-data; name="file"; filename="TheGreatGatsby.xml"
    Content-Type: text/xml
    ```
  * **Payload Content:**
    ```xml
    <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>
    ```
  * The server (`Apache/2.4.58 (Ubuntu)`) parsed the external entity and returned the contents of `/etc/passwd` in the `HTTP/1.1 200 OK` response, confirming the vulnerability via **`TheGreatGatsby.xml`**.

<img width="1852" height="961" alt="obraz" src="https://github.com/user-attachments/assets/a7ad8655-817e-41bb-b325-e02dd26b77b1" />


<img width="1852" height="961" alt="obraz" src="https://github.com/user-attachments/assets/6d903584-1834-49ff-bab0-02f9ac33bb77" />


---

### 2.4. Web Application Configuration File Exfiltration (`config.php`)
After confirming arbitrary file read via `/etc/passwd`, the attacker submitted a second malicious XML payload in Frame `88336` (`2024-05-31 12:07:12.287535 UTC`, `tcp.stream eq 10462`) named `ToKillAMockingbird.xml`.

* **Wireshark Display Filter:**
  ```wireshark
  tcp.stream eq 10462
  ```
* **Findings:**
  * The uploaded XML payload targeted the web application's configuration file in the Apache web root:
    ```xml
    <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///var/www/html/config.php" >]>
    <foo>&xxe;</foo>
    ```
  * The targeted configuration file was **`config.php`**.

<img width="1852" height="961" alt="obraz" src="https://github.com/user-attachments/assets/7e40041d-369a-4f39-b263-7b213ccce8d4" />


<img width="1852" height="961" alt="obraz" src="https://github.com/user-attachments/assets/883147e3-0a27-4e0a-9274-c7cf80ade3f5" />


---

### 2.5. Compromised Database User Password Extraction (`Winter2024`)
Because the server response in `tcp.stream eq 10462` reflected the raw contents of `/var/www/html/config.php` inside the `<foo>` XML tags, the database connection parameters were exposed in cleartext.

* **Exfiltrated `config.php` Source Code (`tcp.stream eq 10462`):**
  ```php
  <?php
  $db_host = 'localhost';
  $db_name = 'pageturner';
  $db_user = 'webuser';
  $db_pass = 'Winter2024';

  $conn = new mysqli($db_host, $db_user, $db_pass, $db_name);
  if ($conn->connect_error) {
      die("Connection failed: " . $conn->connect_error);
  }
  ?>
  ```
* **Findings:**
  * **Database Name:** `pageturner`
  * **Database User:** `webuser`
  * **Compromised Password:** **`Winter2024`**

<img width="1852" height="961" alt="obraz" src="https://github.com/user-attachments/assets/96bd850b-4752-4f34-ab65-ddec496890dd" />


---

### 2.6. First Post-Exfiltration MySQL Login Timestamp (`2024-05-31 12:08`)
Armed with the `webuser:Winter2024` credentials stolen from `config.php` at `12:07:12 UTC`, the attacker connected directly to the exposed MySQL service on port `3306`.

* **Wireshark Display Filter:**
  ```wireshark
  mysql.login_request
  ```
* **Findings:**
  * While early unauthenticated/automated probes occurred at `11:47:24 UTC` during initial scanning, the first MySQL login attempt following the credential theft occurred in Frame `88389`.
  * **Timestamp (UTC):** **`2024-05-31 12:08:40.289336`** (**`2024-05-31 12:08`**).

<img width="1852" height="961" alt="obraz" src="https://github.com/user-attachments/assets/6ea75554-980c-43f0-9a26-4760bdf49f52" />


---

### 2.7. Uploaded Web Shell Identification (`booking.php`)
Following the database compromise, the attacker sent a final HTTP `POST` request to `/review/upload.php` in Frame `88410` (`2024-05-31 12:15:42.211258 UTC`, `tcp.stream eq 10464`) uploading `PrideandPrejudice.xml`.

* **Wireshark Display Filter:**
  ```wireshark
  tcp.stream eq 10464
  ```
* **Findings:**
  * Inspecting `tcp.stream eq 10464` revealed an Out-of-Band (OOB) / PHP filter XXE payload referencing a remote DTD (`http://203.0.113.55/evil.dtd`) and reading/staging a PHP script via `php://filter/read=convert.base64-encode/resource=booking.php`.
  * Correlating the HTTP traffic and web server artifacts confirmed that the web shell uploaded for remote code execution and persistence was **`booking.php`**.

<img width="1852" height="961" alt="obraz" src="https://github.com/user-attachments/assets/7562f9d1-414e-44c5-b461-7a1671f1c4c8" />

<img width="1852" height="961" alt="obraz" src="https://github.com/user-attachments/assets/9e411933-2c56-42c7-8096-31a94c153674" />


---

## 3. Attack Timeline (May 31, 2024)

| Timestamp (UTC) | Source IP | Destination IP | Protocol / Frame | Activity Description |
| :--- | :--- | :--- | :--- | :--- |
| `2024-05-31 11:46:46+` | `210.106.114.183` | `50.239.151.185` | `TCP` (`#51+`) | Attacker conducts TCP SYN scan; ports `80` and `3306` respond with `SYN-ACK`. |
| `2024-05-31 11:57:03.51` | `210.106.114.183` | `50.239.151.185` | `HTTP` (`#88328`) | Attacker uploads `TheGreatGatsby.xml` to `/review/upload.php`, exfiltrating `/etc/passwd` via XXE. |
| `2024-05-31 12:07:12.28` | `210.106.114.183` | `50.239.151.185` | `HTTP` (`#88336`) | Attacker uploads `ToKillAMockingbird.xml`, exfiltrating `/var/www/html/config.php` (`webuser:Winter2024`). |
| `2024-05-31 12:08:40.28` | `210.106.114.183` | `50.239.151.185:3306` | `MySQL` (`#88389`) | Attacker authenticates to MySQL (`3306`) using stolen credentials. |
| `2024-05-31 12:15:42.21` | `210.106.114.183` | `50.239.151.185` | `HTTP` (`#88410`) | Attacker uploads `PrideandPrejudice.xml` and stages web shell `booking.php`. |

---

## 4. Consolidated Indicators of Compromise (IoCs)

| Indicator Type | Value (Defanged) | Context |
| :--- | :--- | :--- |
| **Attacker IPv4** | `210.106.114[.]183` | External threat actor conducting port scans, XXE, and MySQL login |
| **External DTD Host** | `hxxp://203.0.113[.]55/evil.dtd` | External server referenced in OOB XXE payload (`tcp.stream eq 10464`) |
| **Vulnerable Endpoint** | `/review/upload.php` | PHP script on `pageturner4books.net` vulnerable to XXE injection |
| **Malicious XML Files** | `TheGreatGatsby.xml`, `ToKillAMockingbird.xml`, `PrideandPrejudice.xml` | XML files uploaded to exploit XXE and read local files |
| **Compromised DB Account** | `webuser` (`Password: Winter2024`) | MySQL credentials exfiltrated from `/var/www/html/config.php` |
| **Web Shell Artifact** | `booking.php` | Malicious PHP web shell deployed for RCE and persistence |

---

## 5. Summary of Lab Questions & Answers

| Question | Answer |
| :--- | :--- |
| **Q1:** What is the highest-numbered TCP port that responded as open on the victim host? | `3306` |
| **Q2:** What's the complete URI of the PHP script vulnerable to XXE Injection? | `/review/upload.php` |
| **Q3:** What's the name of the first malicious XML file uploaded by the attacker? | `TheGreatGatsby.xml` |
| **Q4:** What's the name of the web app configuration file the attacker read? | `config.php` |
| **Q5:** What is the password for the compromised database user? | `Winter2024` |
| **Q6:** What is the timestamp (UTC) of the attacker's first MySQL login attempt after stealing the credentials? | `2024-05-31 12:08` |
| **Q7:** Identify the name of the web shell that the attacker uploaded for remote code execution and persistence. | `booking.php` |

---

## 6. MITRE ATT&CK Mapping & Remediation

### MITRE ATT&CK Techniques
* **`T1046` – Network Service Discovery:** Conducting a TCP SYN scan against `50.239.151.185` to identify open ports (`80`, `3306`).
* **`T1190` – Exploit Public-Facing Application:** Exploiting an XML External Entity (XXE) vulnerability in `/review/upload.php` via crafted `DOCTYPE`/`ENTITY` declarations.
* **`T1552.001` – Unsecured Credentials: Credentials In Files:** Extracting plaintext MySQL credentials (`webuser:Winter2024`) from `/var/www/html/config.php`.
* **`T1078` – Valid Accounts:** Authenticating to the externally accessible MySQL database (`3306`) using stolen credentials.
* **`T1505.003` – Server Software Component: Web Shell:** Deploying `booking.php` to maintain persistent remote code execution.

### Recommended Remediation Actions
1. **Disable External Entities in PHP XML Parser:** Immediately patch `/review/upload.php` by disabling external entity loading (`libxml_disable_entity_loader(true);` in older PHP versions, or ensuring `LIBXML_NOENT` and `LIBXML_DTDLOAD` flags are **not** passed to `DOMDocument::loadXML()` / `simplexml_load_string()`).
2. **Database Hardening & Credential Rotation:** Rotate the `webuser` MySQL password immediately, revoke `FILE` privileges (`INTO OUTFILE` / `LOAD DATA`), and bind the MySQL service (`bind-address = 127.0.0.1`) or block TCP port `3306` at the perimeter firewall so it is not reachable from external networks.
3. **Web Shell Eradication:** Remove `booking.php` from the web root, audit `/var/www/html/` for unauthorized file modifications, and restrict the Apache (`www-data`) OS user from having write permissions to web root directories.
