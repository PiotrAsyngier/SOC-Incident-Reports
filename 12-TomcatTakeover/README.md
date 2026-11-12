# Incident Report: TomcatTakeover – Apache Tomcat Enumeration, Credential Brute-Force & Malicious WAR Deployment

| Metadata | Details |
| :--- | :--- |
| **Date** | November 2026 |
| **Analyst** | Piotr Asyngier |
| **Tools Used** | Wireshark (PCAP Network Forensics: `web server.pcap`), VirusTotal |
| **Category** | Network Forensics, Web Server Compromise & Reverse Shell Analysis |
| **Affected Environment** | Apache Tomcat Web Server (`10.0.0.112:8080`) |

---

## 1. Executive Summary
Network monitoring alerted on high-volume port scanning and anomalous HTTP requests targeting the internal **Apache Tomcat** web server at **`10.0.0.112`**. A packet-level forensic analysis of the network capture (`web server.pcap`, comprising `21,070` packets) was performed in **Wireshark** to reconstruct the attack chain, identify the threat actor's origin, and determine the method of remote code execution.

The investigation confirmed a complete takeover of the Apache Tomcat server originating from external IP address **`14.0.0.120`** (geolocated to **China**):
1. **Reconnaissance & Directory Enumeration:** The attacker scanned open ports on `10.0.0.112`, discovered the Apache Tomcat service on port **`8080`**, and executed automated directory brute-forcing using **`Gobuster`** (`gobuster/3.6`).
2. **Admin Interface Discovery & Brute-Force:** Enumeration uncovered the **`/manager`** administrative application, which the attacker subsequently accessed by brute-forcing HTTP Basic Authentication with credentials **`admin:tomcat`**.
3. **Malicious WAR Upload & Reverse Shell:** The attacker uploaded a weaponized Web Application Archive (**`JXQOZY.war`** containing `r2pmsx9N.jsp`) via `/manager/html/upload`, triggering a reverse shell callback to **`14.0.0.120:443`**.

---

## 2. Network Traffic Investigation & Technical Analysis

### 2.1. Attacker IP Identification (`14.0.0.120`)
To isolate HTTP reconnaissance and enumeration requests directed at the web server (`10.0.0.112`), packet capture traffic was filtered for HTTP `GET` requests.

* **Wireshark Display Filter:**
  ```wireshark
  http.request.method == "GET"
  ```
* **Findings:**
  * A total of `120` HTTP `GET` requests were identified originating from external IP address **`14.0.0.120`** (MAC: `00:0c:29:4b:ae:ba`) targeting **`10.0.0.112`** (MAC: `00:0c:29:40:6a:d0`).
  * Initial requests at `2023-09-10 20:19:19 UTC` (Frame `19951`) retrieved default Tomcat assets (`/`, `/tomcat.css`, `/tomcat.png`, `/asf-logo-wide.svg`) using `Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0`.

<img width="1854" height="1049" alt="obraz" src="https://github.com/user-attachments/assets/902dd181-4bea-4991-9743-e78af970c728" />


---

### 2.2. Threat Actor Geolocation (`China`)
To enrich the threat intelligence context around the source IP address (`14.0.0.120`), the indicator was queried in **VirusTotal**.

* **Threat Intelligence Lookup:** `14.0.0.120`
* **Findings:**
  * VirusTotal ASN/GeoIP metadata attributed `14.0.0.120` to **China (`CN`)**.

<img width="1854" height="966" alt="obraz" src="https://github.com/user-attachments/assets/bd045bb0-20e2-425a-b840-b9558d7791b2" />


---

### 2.3. Web Server Admin Panel Port Identification (`8080`)
Inspecting the Transmission Control Protocol (TCP) layer of the HTTP requests sent by `14.0.0.120` to `10.0.0.112` revealed the specific port hosting the Apache Tomcat service and administrative interface.

* **Wireshark Display Filter:**
  ```wireshark
  http.request.method == "GET"
  ```
* **Findings:**
  * Inspecting Frame `20126` (`2023-09-10 20:19:33.405263 UTC`, `GET /admin HTTP/1.1`) showed `Source Port: 37674` and **`Destination Port: 8080`** (`Host: 10.0.0.112:8080`).

<img width="1854" height="1047" alt="obraz" src="https://github.com/user-attachments/assets/a1bb5719-6f5d-4337-a5b8-06487fde3131" />


---

### 2.4. Directory Enumeration Tool Identification (`Gobuster`)
At `2023-09-10 20:19:33.396142 UTC` (starting at Frame `20089`), a rapid burst of automated HTTP `GET` requests began probing non-existent UUID paths (`/8a2cd816-3c71-4411-b1a1-0207948f02d3`) and common Tomcat URI paths (`/examples`, `/admin`, `/admin-console`, `/docs/`).

* **Wireshark Display Filter:**
  ```wireshark
  http.request.method == "GET"
  ```
* **Findings:**
  * Expanding the Hypertext Transfer Protocol header details in Frame `20126` (`GET /admin HTTP/1.1`) exposed the scanner's `User-Agent` string:
    * **`User-Agent: gobuster/3.6`** (**`Gobuster`**).

<img width="1854" height="1047" alt="obraz" src="https://github.com/user-attachments/assets/c4165db6-9821-48a4-992d-2a1c5a39414c" />


---

### 2.5. Uncovered Administrative Directory (`/manager`)
Following the TCP stream of the Gobuster scan (`tcp.stream eq 9451`) showed `404 Not Found` responses for `/host-manager/host-manager.xml` and `/jmx-console`, followed by a valid hit on the Tomcat Web Application Manager path.

* **Wireshark Display Filter:**
  ```wireshark
  tcp.stream eq 9451
  ```
* **Findings:**
  * In Frame `20273` (`2023-09-10 20:19:33.468667 UTC`), the attacker requested `GET /manager HTTP/1.1`.
  * In Frame `20281` (`20:19:33.471895 UTC`), the server responded with `HTTP/1.1 302 Found` (redirecting to `/manager/html`), confirming the presence of the **`/manager`** (`manager`) directory, followed by probes for `/manager/list`, `/manager/remove`, and `/manager/save`.

<img width="1854" height="1047" alt="obraz" src="https://github.com/user-attachments/assets/47ea55b1-c064-4142-87de-dae4a39babe5" />


---

### 2.6. Compromised Tomcat Manager Credentials (`admin:tomcat`)
After discovering `/manager` and brute-forcing the login, the attacker authenticated and issued an HTTP `POST` request to upload a payload. Filtering for `POST` requests from the attacker's IP revealed the successful Basic Authentication header.

* **Wireshark Display Filter:**
  ```wireshark
  http.request.method == "POST" and ip.src == 14.0.0.120
  ```
* **Findings:**
  * In Frame `20616` (`2023-09-10 20:22:14.310012 UTC`), the attacker sent `POST /manager/html/upload;jsessionid=0DE586F27B2F4800CA645F731E8E9E71?org.apache.catalina.filters.CSRF_NONCE=...`.
  * Expanding the **`Authorization: Basic YWRtaW46dG9tY2F0`** header in Wireshark decoded the credentials (`http.authbasic`) as:
    * **`admin:tomcat`**

<img width="1854" height="1047" alt="obraz" src="https://github.com/user-attachments/assets/7aa41968-c2c8-4b98-a57b-8d67ee73dace" />


---

### 2.7. Malicious WAR Payload Identification (`JXQOZY.war`)
To inspect the file uploaded via the `/manager/html/upload` endpoint in Frame `20616`, the HTTP stream (`tcp.stream eq 9460`) was reconstructed.

* **Wireshark Display Filter:**
  ```wireshark
  http.request.method == "POST" and ip.src == 14.0.0.120
  ```
  *(Followed by `Follow -> HTTP Stream` / `tcp.stream eq 9460`)*
* **Findings:**
  * The `multipart/form-data` payload (`Content-Length: 1324`) contained the following `Content-Disposition` header:
    ```http
    Content-Disposition: form-data; name="deployWar"; filename="JXQOZY.war"
    Content-Type: application/octet-stream
    ```
  * The archive (`PK` ZIP header) contained `META-INF/MANIFEST.MF`, `WEB-INF/web.xml`, and a JSP web shell/reverse shell script named **`r2pmsx9N.jsp`**.
  * The server responded with `HTTP/1.1 200 OK` (`Server: Apache-Coyote/1.1`), confirming successful deployment of **`JXQOZY.war`**.

<img width="1854" height="1047" alt="obraz" src="https://github.com/user-attachments/assets/935a58c5-fa07-416f-9c6c-09e6dc87dec5" />

<img width="1854" height="1047" alt="obraz" src="https://github.com/user-attachments/assets/241acc45-0399-47ee-bb93-aba13bd255c3" />


---

### 2.8. Reverse Shell Callback Destination (`14.0.0.120:443`)
Inspecting the contents of the uploaded `r2pmsx9N.jsp` payload and subsequent network connections after the WAR deployment (`20:22:14 UTC`) revealed the reverse shell callback parameters.

* **Findings:**
  * The deployed WAR payload (`JXQOZY.war` / `r2pmsx9N.jsp`) executed `/bin/sh` and initiated a reverse TCP connection back to the attacker's listener at **`14.0.0.120:443`**.

<img width="1854" height="1047" alt="obraz" src="https://github.com/user-attachments/assets/90e90195-2c12-47d6-b5a2-c197b83cb93b" />


---

## 3. Attack Timeline (September 10, 2023)

| Timestamp (UTC) | Source IP | Destination IP | Protocol / Frame | Activity Description |
| :--- | :--- | :--- | :--- | :--- |
| `2023-09-10 20:19:19.48` | `14.0.0.120` | `10.0.0.112:8080` | `HTTP` (`#19951`) | Attacker accesses Apache Tomcat landing page on port `8080` via Firefox. |
| `2023-09-10 20:19:33.39` | `14.0.0.120` | `10.0.0.112:8080` | `HTTP` (`#20089-20169`) | Automated directory enumeration launched using `gobuster/3.6`. |
| `2023-09-10 20:19:33.46` | `14.0.0.120` | `10.0.0.112:8080` | `HTTP` (`#20273-20281`) | Gobuster discovers `/manager` directory (`HTTP 302 Found`). |
| `2023-09-10 20:22:14.31` | `14.0.0.120` | `10.0.0.112:8080` | `HTTP` (`#20616`) | Attacker authenticates (`admin:tomcat`) and uploads `JXQOZY.war` via `POST /manager/html/upload`. |
| `2023-09-10 20:22:15+` | `10.0.0.112` | `14.0.0.120:443` | `TCP` | Deployed JSP payload (`r2pmsx9N.jsp`) establishes reverse shell to `14.0.0.120:443`. |

---

## 4. Consolidated Indicators of Compromise (IoCs)

| Indicator Type | Value | Context |
| :--- | :--- | :--- |
| **Attacker IPv4 / MAC** | `14.0.0.120` (`00:0c:29:4b:ae:ba`) | External threat actor IP (Geolocated to China / `CN`) |
| **Target Server IPv4** | `10.0.0.112:8080` (`00:0c:29:40:6a:d0`) | Compromised Apache Tomcat web server |
| **Scanner User-Agent** | `gobuster/3.6` | Directory enumeration tool used against port `8080` |
| **Compromised Credentials** | `admin:tomcat` (`YWRtaW46dG9tY2F0`) | Default/weak Tomcat Manager Basic Auth credentials |
| **Malicious Archive** | `JXQOZY.war` | Malicious WAR package deployed via `/manager/html/upload` |
| **Embedded Web Shell** | `r2pmsx9N.jsp` | JSP reverse shell script packaged inside `JXQOZY.war` |
| **C2 Callback Socket** | `14.0.0.120:443` | Attacker listener receiving the reverse shell connection |

---

## 5. Summary of Lab Questions & Answers

| Question | Answer |
| :--- | :--- |
| **Q1:** Identify the source IP address responsible for initiating these requests on our server. | `14.0.0.120` |
| **Q2:** Identify the country from which the attacker's activities originated. | `China` |
| **Q3:** Which of these ports provides access to the web server admin panel? | `8080` |
| **Q4:** Which tools can you identify from the analysis that assisted the attacker in this enumeration process? | `Gobuster` |
| **Q5:** Which directory related to the admin panel did the attacker uncover? | `/manager` (`manager`) |
| **Q6:** What credentials did the attacker successfully use? | `admin:tomcat` |
| **Q7:** Identify the name of this malicious file from the captured data. | `JXQOZY.war` |
| **Q8:** What is the callback destination in `IP:port` format? | `14.0.0.120:443` |

---

## 6. MITRE ATT&CK Mapping & Remediation

### MITRE ATT&CK Techniques
* **`T1595.003` – Active Scanning: Wordlist Scanning:** Enumerating web directories on port `8080` using `gobuster/3.6`.
* **`T1110.001` – Brute Force: Password Guessing:** Brute-forcing HTTP Basic Authentication on `/manager/html` and authenticating with default credentials (`admin:tomcat`).
* **`T1505.003` – Server Software Component: Web Shell:** Uploading a malicious WAR archive (`JXQOZY.war` containing `r2pmsx9N.jsp`) to achieve remote code execution on Apache Tomcat.
* **`T1059.004` – Command and Scripting Interpreter: Unix Shell:** Executing `/bin/sh` via the JSP payload to establish an interactive reverse shell over TCP port `443`.

### Recommended Remediation Actions
1. **Immediate Containment & Eradication:** Isolate `10.0.0.112` from the network, terminate active outbound connections to `14.0.0.120:443`, undeploy and delete `JXQOZY.war` (and the expanded `/webapps/JXQOZY/` directory), and audit `tomcat-users.xml`.
2. **Restrict `/manager` Access:** Restrict access to `/manager` and `/host-manager` by IP address using Tomcat's `RemoteAddrValve` (in `META-INF/context.xml`) so only internal administrative jump hosts can reach the interface.
3. **Credential Hardening & Lockout:** Remove default credentials (`admin:tomcat`) from `conf/tomcat-users.xml`, enforce strong passwords, and verify that Tomcat's `LockOutRealm` is active to prevent brute-force attacks.
