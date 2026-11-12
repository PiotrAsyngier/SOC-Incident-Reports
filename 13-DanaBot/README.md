# Incident Report: DanaBot – Malicious JScript Dropper, WSH Execution & Second-Stage DLL Payload Analysis

| Metadata | Details |
| :--- | :--- |
| **Date** | November 2026 |
| **Analyst** | Piotr Asyngier |
| **Tools Used** | Wireshark (`205-DanaBot.pcap`), Linux CLI (`sha256sum`, `md5sum`), VirusTotal |
| **Category** | Network Forensics, Malware Dropper Analysis & Threat Intelligence |
| **Affected Environment** | Victim Host: `10.2.14.101` (Gateway/DNS: `10.2.14.1`) |

---

## 1. Executive Summary
Network intrusion detection alerted on suspicious DNS queries and outbound HTTP file transfers originating from internal workstation **`10.2.14.101`**. A forensic analysis of the captured network traffic (`205-DanaBot.pcap`, comprising `13,900` packets) was conducted in **Wireshark**, supplemented by cryptographic hashing and **VirusTotal** threat intelligence lookups, to reconstruct the **DanaBot** infection chain.

The investigation uncovered a two-stage malware delivery sequence:
1. **Initial Access & First-Stage Dropper:** The victim host (`10.2.14.101`) resolved `portfolio.serveirc[.]com` to **`62.173.142.148`** and issued an HTTP `GET /login.php` request, which delivered a heavily obfuscated JScript dropper attachment named **`allegato_708.js`** (`SHA-256: 847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268`).
2. **Host Execution via WSH:** The obfuscated JScript file leveraged Windows Script Host (**`Wscript.exe`**) and `ActiveXObject` calls to execute locally and reach out to a second-stage staging server.
3. **Second-Stage Payload Delivery:** The script queried `soundata[.]top` (`188.114.97.3`) and downloaded an 11.9 MB malicious Dynamic Link Library (`resources.dll`, extension **`.dll`**, `MD5: e758e07113016aca55d9eda2b0ffeebe`) representing the main **DanaBot** banking trojan/stealer payload.

---

## 2. Network Traffic Investigation & Technical Analysis

### 2.1. Initial Access IP Identification (`62.173.142.148`)
To determine how the infection began, DNS traffic (`dns`) at the start of the packet capture was inspected to identify external domains queried by the victim workstation (`10.2.14.101`).

* **Wireshark Display Filter:**
  ```
  dns
  ```
* **Findings:**
  * In Frame `1` (`2024-02-14 17:25:53.856487 UTC`), host `10.2.14.101` queried DNS server `10.2.14.1` for the `A` record of **`portfolio.serveirc.com`**.
  * In Frame `2` (`17:25:54.004505 UTC`), the DNS response resolved `portfolio.serveirc.com` to IPv4 address **`62.173.142.148`** (`NS: nf1.no-ip.com`).
  * Querying **`62.173.142.148`** in **VirusTotal** confirmed that the IP belongs to `AS34300` (*Internet-Cosmos LLC*, Russia / `RU`) and was flagged by security vendors for hosting malicious content.

<img width="1854" height="1047" alt="obraz" src="https://github.com/user-attachments/assets/180722b5-00a3-4be3-8cc9-dbcc0c801ff7" />


<img width="1854" height="968" alt="obraz" src="https://github.com/user-attachments/assets/bad96068-3578-43d3-8f1e-4ebb8e70dbd6" />


---

### 2.2. First-Stage Malicious File Identification (`allegato_708.js`)
Immediately following the DNS resolution of `portfolio.serveirc.com`, the victim host initiated a TCP handshake and HTTP `GET` request to `62.173.142.148:80`.

* **Analysis Method:**
  * Inspected `File -> Export Objects -> HTTP` (Packet `11`, Host: `portfolio.serveirc.com`, URI: `login.php`, Size: `5,558 bytes`).
  * Followed the first HTTP stream (`tcp.stream eq 0`) to inspect the server's HTTP response headers.
* **Findings:**
  * In Frame `6` (`2024-02-14 17:25:54.190701 UTC`), `10.2.14.101` requested `GET /login.php HTTP/1.1` from `Host: portfolio.serveirc.com`.
  * In Frame `11` (`17:25:54.375218 UTC`), the server (`nginx/1.14.0 (Ubuntu)`) responded with `HTTP/1.1 200 OK` (`Content-Type: application/octet-stream`) and forced a file download via the `Content-Disposition` header:
    ```http
    Content-Disposition: attachment; filename="allegato_708.js"
    ```
  * Therefore, the actual filename saved to the victim's disk for initial access was **`allegato_708.js`**.

<img width="748" height="558" alt="obraz" src="https://github.com/user-attachments/assets/3f95477f-a3ce-402c-a831-1cda3dcdeb30" />


<img width="1854" height="1047" alt="obraz" src="https://github.com/user-attachments/assets/1d34cde1-ca24-4c64-892b-4ff84038ea5a" />


<img width="1854" height="1047" alt="obraz" src="https://github.com/user-attachments/assets/b4d04f0e-78a2-448f-b1d0-1ab8540ea98c" />


---

### 2.3. First-Stage Dropper Cryptographic Hash (`SHA-256`)
To uniquely identify the initial access artifact (`login.php` / `allegato_708.js`) and correlate it with threat intelligence platforms, the HTTP object (`5,558 bytes`) was exported from Wireshark to the analysis workstation.

* **Command Executed:**
  ```bash
  sha256sum login.php
  ```
* **Findings:**
  * **SHA-256 Hash:** **`847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268`**
  * Searching the hash on **VirusTotal** yielded **32/61** malicious detections, classifying the obfuscated script as a `js` `obfuscated` `downloader` (`Trojan.JScript.Downloader` / `DanaBot`).

<img width="808" height="150" alt="obraz" src="https://github.com/user-attachments/assets/cc194fa2-5d67-4390-8dc7-581fb59f5fda" />

<img width="1854" height="967" alt="obraz" src="https://github.com/user-attachments/assets/8e4eee6b-6fbd-49fa-a62f-cb78d6d11f06" />


---

### 2.4. Host Execution Process Identification (`Wscript.exe`)
Inspecting the de-chunked body of `allegato_708.js` in the HTTP stream (`tcp.stream eq 0`) revealed how the script executes on a Windows host.

* **Code & Behavioral Analysis:**
  * Searching the HTTP stream for `WScript` revealed multiple invocations of the Windows Script Host object model (`WScript[...]`, `new ActiveXObject(...)`).
  * On Windows systems, `.js` (JScript) files executed outside a browser are handled by **Windows Script Host (WSH)**, which invokes **`Wscript.exe`** by default for GUI/double-click execution.

<img width="672" height="243" alt="obraz" src="https://github.com/user-attachments/assets/5b920537-385b-4025-be72-6a38c4cd1d1c" />


<img width="1850" height="1050" alt="obraz" src="https://github.com/user-attachments/assets/0b701ae0-527d-403b-8897-1ccc48bc1064" />


<img width="1850" height="1050" alt="obraz" src="https://github.com/user-attachments/assets/0982b2aa-b014-42fd-8b2a-9b8ecf844e42" />


---

### 2.5. Second-Stage Payload Extension Identification (`.dll`)
Once `allegato_708.js` was executed via `Wscript.exe`, it initiated a second stage download from an external domain (`soundata.top`, resolved in Frame `245`–`246` to Cloudflare IP `188.114.97.3`).

* **Analysis Method:**
  * Reviewed the second payload in `File -> Export Objects -> HTTP` (Packet `9952`, Host: `soundata.top`, Filename: `resources.dll`, Size: `11 MB` / `11,922,432 bytes`).
  * Inspected the HTTP stream (`tcp.stream eq 6`) to verify the file header and PE structure.
* **Findings:**
  * The HTTP stream begins with the `MZ` magic bytes (`This program cannot be run in DOS mode`) and contains Portable Executable (PE) strings and exports indicative of a compiled C++ MFC library (`resources.dll`).
  * The file extension of the second malicious file is **`.dll`**.

<img width="1850" height="1050" alt="obraz" src="https://github.com/user-attachments/assets/e6607f3b-3cd0-45cf-be28-433d0e23bf98" />


<img width="1850" height="1050" alt="obraz" src="https://github.com/user-attachments/assets/417ff211-7e70-40d1-95c5-2b4586b148e8" />


---

### 2.6. Second-Stage Payload Cryptographic Hash (`MD5`)
To obtain the MD5 signature of the second-stage DanaBot payload (`resources.dll`), the `11,922,432`-byte binary was exported from Wireshark and hashed via the terminal.

* **Command Executed:**
  ```bash
  md5sum resources.dll
  ```
* **Findings:**
  * **MD5 Hash:** **`e758e07113016aca55d9eda2b0ffeebe`**
  * Submitting the hash to **VirusTotal** flagged the file with **57/72** detections as a 32-bit Win32 **DanaBot** trojan DLL (`11.37 MB`).

<img width="1850" height="1050" alt="obraz" src="https://github.com/user-attachments/assets/9093432a-083d-4d7e-839a-15a5f1493bbb" />


<img width="1850" height="965" alt="obraz" src="https://github.com/user-attachments/assets/717abae4-4203-482d-8158-f82508c7a583" />


---

## 3. Attack Timeline (February 14, 2024)

| Timestamp (UTC) | Source IP | Destination IP | Protocol / Frame | Activity Description |
| :--- | :--- | :--- | :--- | :--- |
| `2024-02-14 17:25:53.85` | `10.2.14.101` | `10.2.14.1` | `DNS` (`#1-2`) | Victim queries `portfolio.serveirc.com`, resolving to `62.173.142.148`. |
| `2024-02-14 17:25:54.19` | `10.2.14.101` | `62.173.142.148` | `HTTP` (`#6-11`) | `GET /login.php` downloads obfuscated JScript dropper `allegato_708.js` (`5,558 B`). |
| `2024-02-14 17:26:55.34` | `10.2.14.101` | `10.2.14.1` | `DNS` (`#245-246`) | `Wscript.exe` executes `allegato_708.js`, querying second-stage domain `soundata.top` (`188.114.97.3`). |
| `2024-02-14 17:26:58.54` | `188.114.97.3` | `10.2.14.101` | `HTTP` (`#9952`) | Second-stage DanaBot payload `resources.dll` (`11.9 MB`) transferred to victim. |

---

## 4. Consolidated Indicators of Compromise (IoCs)

| Indicator Type | Value (Defanged) | Context |
| :--- | :--- | :--- |
| **IPv4 Address (Stage 1)** | `62.173.142[.]148` | Initial access server hosting the JScript dropper (`AS34300`, RU) |
| **Domain (Stage 1)** | `portfolio.serveirc[.]com` | Dynamic DNS domain serving `/login.php` (`allegato_708.js`) |
| **File Artifact (Stage 1)** | `allegato_708.js` (`login.php`) | Obfuscated JScript dropper (`5,558 bytes`) |
| **SHA-256 (Stage 1)** | `847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268` | SHA-256 hash of `allegato_708.js` |
| **Domain / IP (Stage 2)** | `soundata[.]top` (`188.114.97[.]3`) | Second-stage distribution server hosting the DanaBot DLL |
| **File Artifact (Stage 2)** | `resources.dll` | Second-stage DanaBot PE32 DLL payload (`11,922,432 bytes`) |
| **MD5 (Stage 2)** | `e758e07113016aca55d9eda2b0ffeebe` | MD5 hash of `resources.dll` |

---

## 5. Summary of Lab Questions & Answers

| Question | Answer |
| :--- | :--- |
| **Q1:** Which IP address was used by the attacker during the initial access? | `62.173.142.148` |
| **Q2:** What is the name of the malicious file used for initial access? | `allegato_708.js` |
| **Q3:** What is the SHA-256 hash of the malicious file used for initial access? | `847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268` |
| **Q4:** Which process was used to execute the malicious file? | `Wscript.exe` |
| **Q5:** What is the file extension of the second malicious file utilized by the attacker? | `.dll` |
| **Q6:** What is the MD5 hash of the second malicious file? | `e758e07113016aca55d9eda2b0ffeebe` |

---

## 6. MITRE ATT&CK Mapping & Remediation

### MITRE ATT&CK Techniques
* **`T1059.007` – Command and Scripting Interpreter: JavaScript:** Execution of the obfuscated JScript dropper (`allegato_708.js`) via Windows Script Host (`Wscript.exe`).
* **`T1027` – Obfuscated Files or Information:** Heavy array-rotation and string-encoding obfuscation applied to `allegato_708.js` and `11.9 MB` binary padding applied to `resources.dll` to evade AV scanners.
* **`T1105` – Ingress Tool Transfer:** Downloading the second-stage `resources.dll` payload over HTTP from `soundata.top`.
* **`T1218.011` – System Binary Proxy Execution: Rundll32:** Standard DanaBot execution of the downloaded `.dll` payload (`resources.dll`) following dropper staging.

### Recommended Remediation Actions
1. **Endpoint Isolation & Credential Rotation:** Immediately isolate host `10.2.14.101`. Because DanaBot functions as an information stealer and banking trojan, revoke active browser sessions and rotate all credentials stored on or entered from this workstation.
2. **Hardening Windows Script Host (WSH):** Change the default file association for `.js` and `.jse` files to `notepad.exe` via Group Policy, or disable Windows Script Host (`HKLM\Software\Microsoft\Windows Script Host\Settings\Enabled = 0`) for standard users.
3. **Network & DNS Blocking:** Block `portfolio.serveirc.com`, `soundata.top`, and `62.173.142.148` at the DNS sinkhole and perimeter firewall, and implement Attack Surface Reduction (ASR) rules to block JavaScript/VBScript from launching downloaded executable content.
