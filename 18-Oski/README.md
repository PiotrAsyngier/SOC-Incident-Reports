# Incident Report: Oski Lab – Phishing PPT Dropper, Stealc/Oski Infostealer Triage & Sandbox Behavioral Analysis

| Metadata | Details | 
| ----- | ----- | 
| **Date** | November 2026 | 
| **Analyst** | Piotr Asyngier | 
| **Tools Used** | VirusTotal, Recorded Future Triage (`[tria.ge](https://tria.ge/260730-engzhayhja)`), ANY.RUN Sandbox | 
| **Category** | Threat Intelligence, Malware Sandbox Triage & Infostealer Analysis | 
| **Target Sample (MD5 / SHA-256)** | `12c1842c3ccafe7408c23ebf292ee3d9` / `a040a0af8697e30506218103074c7d6ea77a84ba3ac1ee5efae20f15530a19bb` | 

## 1. Executive Summary

An accountant at the organization received a spear-phishing email with the subject **"Urgent New Order"** containing a malicious PowerPoint (`PPT`) invoice attachment displaying fabricated order details. Shortly after the user opened the attachment, the SIEM generated an alert for a suspicious binary download (`VPN.exe`, `MD5: 12c1842c3ccafe7408c23ebf292ee3d9`). A multi-platform threat intelligence and dynamic sandbox investigation was conducted across **VirusTotal**, **Recorded Future Triage**, and **ANY.RUN** to profile the malware's capabilities, extract its cryptographic configuration, and document its post-exfiltration anti-forensic behavior.

The investigation confirmed that the downloaded payload is a 32-bit C/C++ information stealer tracked as **Stealc / Oski Stealer**:

1. **Origin & C2 Infrastructure:** The executable (`311.50 KB`, compiled on **`2022-09-28 17:40:46 UTC`**) communicates with an external Command-and-Control (C2) gate at **`http://171.22.28.221/5c06c05b7b34e8e6.php`** and encrypts its internal Base64 strings using the plaintext RC4 key **`5329514621441247975720749009`**.

2. **Post-Infection Staging & Credential Theft:** Immediately upon execution, the stealer requests and drops **`sqlite3.dll`** (`C:\ProgramData\sqlite3.dll`) to parse SQLite browser databases and harvest saved credentials (**MITRE `T1555`** / `T1555.003`).

3. **Defense Evasion & Self-Deletion:** Following data exfiltration over HTTP `POST`, the malware spawns a `cmd.exe` child process that waits **`5` seconds** (`timeout /t 5`) before deleting its own executable (`VPN.exe`) and wiping all `.dll` files inside **`C:\ProgramData`** (`del "C:\ProgramData\*.dll"`).

## 2. Threat Intelligence & Sandbox Technical Analysis

### 2.1. Malware Creation Timestamp Identification (`2022-09-28 17:40`)

Starting from the MD5 hash extracted during initial triage (`12c1842c3ccafe7408c23ebf292ee3d9`), the sample was queried in **VirusTotal** (resolving to `SHA-256: a040a0af8697e30506218103074c7d6ea77a84ba3ac1ee5efae20f15530a19bb`) to inspect its Portable Executable (PE) header metadata under the **Details** tab.

* **PE Metadata & History Findings:**

  * **File Type:** `Win32 EXE` (`PE32 executable (GUI) Intel 80386, for MS Windows`, compiled with Microsoft Visual C/C++ 2010).

  * **File Size:** `311.50 KB (318,976 bytes)`

  * **Creation Time (PE Compile Timestamp):** **`2022-09-28 17:40:46 UTC`** (**`2022-09-28 17:40`**).

  * **First Submission to VirusTotal:** `2023-09-23 22:02:55 UTC`.

<img width="1852" height="1000" alt="obraz" src="https://github.com/user-attachments/assets/66f32883-f637-466f-b38d-8687a3348afa" />

<img width="1852" height="962" alt="obraz" src="https://github.com/user-attachments/assets/d1459cc4-8a36-419a-ba2c-e9df5d354997" />


### 2.2. Command-and-Control (C2) Server Identification (`http://171.22.28.221/5c06c05b7b34e8e6.php`)

Pivoting to the **Behavior** tab (`Activity Summary`) in VirusTotal—and cross-checking with the **Recorded Future Triage** and **ANY.RUN** network logs—revealed the exact HTTP endpoint contacted by `VPN.exe`.

* **Findings:**

  * **Memory Pattern IPs / Domains:** `171.22.28.221`

  * **Memory Pattern URLs / C2 Gate:** **`http://171.22.28.221/5c06c05b7b34e8e6.php`**

  * During dynamic execution, `VPN.exe` (`PID 3484`) sends multiple `HTTP POST` requests directly to `http://171.22.28.221/5c06c05b7b34e8e6.php` to fetch dynamic configuration and exfiltrate harvested host data.

<img width="1852" height="962" alt="obraz" src="https://github.com/user-attachments/assets/a622e908-04c4-442e-9e24-68b74029c4b1" />


### 2.3. Post-Infection Auxiliary Library Identification (`sqlite3.dll`)

Because Chromium- and Gecko-based web browsers store saved logins, cookies, and autofill data inside SQLite3 databases (`Login Data`, `cookies.sqlite`, `Web Data`), Stealc/Oski dynamically requests a legitimate copy of the SQLite3 library from its C2 server immediately after infection.

* **Findings (VirusTotal `Files Dropped` & ANY.RUN):**

  * Under `Files Dropped` in VirusTotal's **Behavior** tab, the first library requested and written to disk (`C:\ProgramData\sqlite3.dll`) is:

    * **`sqlite3.dll`** (requested via `GET http://171.22.28.221/9e226a84ec50246d/sqlite3.dll`).

<img width="1852" height="962" alt="obraz" src="https://github.com/user-attachments/assets/b9a3a311-d713-43d4-8da0-89cfe624728e" />


### 2.4. Static Configuration & RC4 Decryption Key Extraction (`5329514621441247975720749009`)

Examining the automated malware configuration extractor in the **Recorded Future Triage** sandbox report (`Sample ID: 260730-engzhayhja`, Score: `10/10`) exposed the hardcoded obfuscation parameters used by the binary to decrypt its internal Base64-encoded strings.

* **Extracted Malware Configuration (`Malware Config`):**

  * **Family:** `stealc`

  * **Botnet ID:** `default`

  * **C2 URL:** `http://171.22.28.221` (`url_path: /5c06c05b7b34e8e6.php`)

  * **RC4 Plaintext Key (`rc4.plain`):** **`5329514621441247975720749009`**

<img width="1852" height="962" alt="obraz" src="https://github.com/user-attachments/assets/803ff8a8-4b60-471f-93e3-ee72ceedbc98" />


### 2.5. MITRE ATT&CK Password Theft Technique Identification (`T1555`)

Reviewing the **ANY.RUN** interactive sandbox report (`VPN.exe`, `PID 3484`, tagged `stealc`, `stealer`, `loader`, `oski`) highlighted the specific MITRE ATT&CK techniques triggered during credential harvesting.

* **Findings:**

  * Under the **Danger** panel for `VPN.exe` (`ID 3484`), ANY.RUN flagged:

    * `T1555.003` – *Credentials from Web Browsers (Steals credentials from Web Browsers)*.

  * Therefore, the parent/main MITRE ATT&CK technique (excluding the `.003` sub-technique) is **`T1555`** (*Credentials from Password Stores*).

<img width="1852" height="962" alt="Zrzut ekranu z 2026-11-15 19-09-53" src="https://github.com/user-attachments/assets/04c4c34c-3920-480f-a4fc-6c21579bf9c9" />


### 2.6. Anti-Forensic DLL Cleanup Directory (`C:\ProgramData`) & Self-Deletion Delay (`5` Seconds)

Once `VPN.exe` (`PID 3484`) finishes exfiltrating the stolen browser data via `POST /5c06c05b7b34e8e6.php`, it spawns `cmd.exe` (`PID 2780`) and `timeout.exe` (`PID 3320`) to erase its forensic footprint from the endpoint.

* **Child Process Command Line (`PID 2780` in ANY.RUN):**

  ```cmd
  "C:\Windows\system32\cmd.exe" /c timeout /t 5 & del /f /q "C:\Users\admin\AppData\Local\Temp\VPN.exe" & del "C:\ProgramData\*.dll" & exit
  ```

* **Findings:**

  * **Target Directory for DLL Deletion (Q6):** **`C:\ProgramData`** (`del "C:\ProgramData\*.dll"` removes `sqlite3.dll` and any other auxiliary third-party DLLs such as `nss3.dll` or `freebl3.dll` staged during browser credential extraction).

  * **Self-Deletion Delay in Seconds (Q7):** **`5`** (`timeout /t 5` pauses execution for 5 seconds so `VPN.exe` can terminate and release its file handle before `del /f /q` deletes the binary from `%TEMP%`).

<img width="1852" height="962" alt="Zrzut ekranu z 2026-11-15 19-11-20" src="https://github.com/user-attachments/assets/cfa9c9e2-fa2e-40bb-80e3-8b1446e11cd6" />

<img width="1852" height="962" alt="Zrzut ekranu z 2026-11-15 19-12-08" src="https://github.com/user-attachments/assets/0db8e584-0403-4295-944a-95703b457e41" />


## 3. Malware Execution & Sandbox Timeline

| Stage / Offset | Process (`PID`) | Activity Description | 
| ----- | ----- | ----- | 
| **Pre-Incident** (`2022-09-28 17:40 UTC`) | Compiler | Threat actor compiles the 32-bit Visual C++ Stealc/Oski binary (`VPN.exe`). | 
| **Initial Execution** (`+0.0s`) | `VPN.exe` (`3484`) | Launched in `C:\Users\admin\AppData\Local\Temp\VPN.exe`; decrypts strings using RC4 key `5329514621441247975720749009`. | 
| **C2 Handshake & DLL Staging** (`+2.3s`) | `VPN.exe` (`3484`) | Contacts `http://171.22.28.221/5c06c05b7b34e8e6.php` and downloads `sqlite3.dll` into `C:\ProgramData\`. | 
| **Credential Harvesting & Exfiltration** (`+2.4s – +28s`) | `VPN.exe` (`3484`) | Reads browser login stores (`T1555.003`) and exfiltrates data via `HTTP POST` to `171.22.28.221`. | 
| **Anti-Forensic Cleanup** (`+29.0s`) | `cmd.exe` (`2780`) -> `timeout.exe` (`3320`) | Executes `timeout /t 5`, deletes `VPN.exe` from `%TEMP%`, and deletes `C:\ProgramData\*.dll`. | 

## 4. Consolidated Indicators of Compromise (IoCs)

| Indicator Type | Value (Defanged) | Context | 
| ----- | ----- | ----- | 
| **MD5 Hash** | `12c1842c3ccafe7408c23ebf292ee3d9` | Primary Stealc / Oski Stealer executable (`VPN.exe`, `318,976 B`) | 
| **SHA-1 Hash** | `4b1af84cc11a8b1e290a18a4222849526eeadd10` | SHA-1 hash of `VPN.exe` | 
| **SHA-256 Hash** | `a040a0af8697e30506218103074c7d6ea77a84ba3ac1ee5efae20f15530a19bb` | SHA-256 hash of `VPN.exe` | 
| **C2 Gate URL** | `hxxp://171.22.28[.]221/5c06c05b7b34e8e6.php` | Primary C2 endpoint receiving stolen data via HTTP `POST` | 
| **DLL Staging URL** | `hxxp://171.22.28[.]221/9e226a84ec50246d/sqlite3.dll` | URL used to fetch `sqlite3.dll` post-infection | 
| **RC4 Key** | `5329514621441247975720749009` | Hardcoded RC4 decryption key extracted from malware config | 
| **Host Artifacts** | `C:\ProgramData\sqlite3.dll`, `%TEMP%\VPN.exe` | Staged files deleted post-exfiltration via `cmd.exe /c timeout /t 5` | 

## 5. Summary of Lab Questions & Answers

| Question | Answer | 
| ----- | ----- | 
| **Q1:** What was the time of malware creation? | `2022-09-28 17:40` | 
| **Q2:** Which C2 server does the malware in the PPT file communicate with? | `http://171.22.28.221/5c06c05b7b34e8e6.php` | 
| **Q3:** What is the first library that the malware requests post-infection? | `sqlite3.dll` | 
| **Q4:** What RC4 key is used by the malware to decrypt its base64-encoded string? | `5329514621441247975720749009` | 
| **Q5:** Identify the main MITRE technique (not sub-techniques) the malware uses to steal the user's password. | `T1555` | 
| **Q6:** Which directory does the malware target for the deletion of all DLL files? | `C:\ProgramData` | 
| **Q7:** After successfully exfiltrating the user's data, how many seconds does it take for the malware to self-delete? | `5` | 

## 6. MITRE ATT&CK Mapping & Remediation

### MITRE ATT&CK Techniques

* **`T1566.001` – Phishing: Spearphishing Attachment:** Initial delivery via a malicious PowerPoint (`PPT`) attachment in the "Urgent New Order" email.

* **`T1140` – Deobfuscate/Decode Files or Information:** Decrypting internal Base64-encoded strings using RC4 (`5329514621441247975720749009`).

* **`T1105` – Ingress Tool Transfer:** Downloading `sqlite3.dll` from `171.22.28.221` into `C:\ProgramData\` to parse victim browser databases.

* **`T1555` (`T1555.003`) – Credentials from Password Stores: Credentials from Web Browsers:** Extracting saved passwords and cookies from installed web browsers.

* **`T1070.004` – Indicator Removal: File Deletion:** Executing `cmd.exe /c timeout /t 5 & del /f /q ... & del "C:\ProgramData\*.dll"` to self-delete the payload and auxiliary DLLs.

### Recommended Remediation Actions

1. **Immediate Credential Reset & Session Revocation:** Because Stealc/Oski exfiltrates browser-stored credentials and session cookies prior to self-deleting, immediately revoke active web/SSO sessions and force password resets for all accounts used by the accountant on the affected workstation.

2. **Network & C2 Blocking:** Block outbound traffic to `171.22.28.221` at the perimeter firewall and web proxy, and hunt across proxy/firewall logs for any other internal hosts communicating with `/5c06c05b7b34e8e6.php`.

3. **EDR Behavioral Detection:** Implement EDR detection rules for processes spawning `cmd.exe /c timeout /t * & del` self-deletion patterns and unsigned executables in `%TEMP%` dropping `.dll` files (`sqlite3.dll`, `nss3.dll`) into `C:\ProgramData\`.
