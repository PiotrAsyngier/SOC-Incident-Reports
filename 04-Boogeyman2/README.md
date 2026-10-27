# Incident Report: The Boogeyman 2 – Malicious VBA Macro & Endpoint Memory Forensics (Volatility 3)

| Metadata | Details |
| :--- | :--- |
| **Date** | October 2026 |
| **Analyst** | Piotr Asyngier |
| **Tools Used** | Thunderbird, `md5sum`, VirusTotal, `olevba`, Volatility 3, `strings`, `grep` |
| **Category** | Maldoc Analysis & Endpoint Memory Forensics (DFIR) |
| **Threat Actor / Group** | Boogeyman |
| **Affected Victim** | Maxine Beck (`maxine.beck`), HR Specialist – Quick Logistics LLC (Host: `WKSTN-2961` / `10.10.49.181`) |

---

## 1. Executive Summary
Maxine Beck, a Human Resource Specialist at **Quick Logistics LLC**, received a spearphishing email disguised as a job application for a Junior IT Analyst position. Opening the attached Microsoft Word document (`Resume_WesleyTaylor.doc`) triggered an embedded `AutoOpen` VBA macro attributed to the **Boogeyman** threat group.

Static analysis of the document (`olevba`) and forensic examination of the workstation's memory image (`WKSTN-2961.raw`) using **Volatility 3** revealed a multi-stage infection chain:
1. The malicious Word macro fetched a Stage-2 JScript dropper masquerading as an image (`update.png`) from `files.boogeymanisback[.]lol` and saved it locally as `C:\ProgramData\update.js`.
2. `wscript.exe` (`PID: 4260`) executed `update.js`, which subsequently downloaded and launched a Stage-3 C2 binary (`C:\Windows\Tasks\updater.exe`, `PID: 6216`) communicating with `128.199.95[.]189:8080`.
3. To maintain persistence, the attacker registered a daily scheduled task (`Updater`) executing an obfuscated PowerShell one-liner that loads a Base64-encoded payload directly from the Windows Registry (`HKCU:\Software\Microsoft\Windows\CurrentVersion\debug`).

---

## 2. Spearphishing & Malicious Document Analysis

### 2.1. Email Triage & Attachment Identification
Inspection of the raw email artifact (`/home/ubuntu/Desktop/Artefacts/Resume - Application for Junior IT Analyst Role.eml`) revealed a socially engineered job application targeting the HR department:
* **Sender (`From`):** `Wesley Taylor <westaylor23@outlook.com>`
* **Recipient (`To`):** `Maxine Beck <maxine.beck@quicklogisticsorg.onmicrosoft.com>`
* **Subject:** `Resume - Application for Junior IT Analyst Role`
* **Timestamp:** `Sun, 20 Aug 2023 18:19:20 +0000`
* **Attached File:** `Resume_WesleyTaylor.doc`

<img width="680" height="405" alt="obraz" src="https://github.com/user-attachments/assets/d6252e60-b014-4394-b0a1-33d5448bb61a" />


---

### 2.2. Cryptographic Hash & Threat Intelligence Lookup
The attachment was extracted to the analysis environment to compute its cryptographic signature and query threat intelligence databases:
* **Command Used:** `md5sum Resume_WesleyTaylor.doc`
* **MD5 Hash:** `52c4384a0b9e248b95804352ebec6c5b`
* **SHA-256 Hash:** `42b25e63c48be36aa219fe2192711affb5d05d7a25a38b9b990beb19f06abc`
* **VirusTotal Assessment:** Flagged as malicious by **39 security vendors** with the threat label `download.ole2` (VBA macro downloader).

<img width="585" height="218" alt="obraz" src="https://github.com/user-attachments/assets/b0bd05ee-48fd-46cd-8223-021cffe5ef3e" />


<img width="1858" height="964" alt="obraz" src="https://github.com/user-attachments/assets/c07f7c09-eb29-4d96-bc4d-2850c38b959f" />


---

### 2.3. Static VBA Macro Analysis (`olevba`)
To inspect the embedded macro code without executing the document, **`olevba`** was run against `Resume_WesleyTaylor.doc`:
* **Command Used:** `olevba Resume_WesleyTaylor.doc`
* **Macro Stream:** `Macros/VBA/NewMacros` (`NewMacros.bas`)
* **Behavioral Analysis:**
  1. The `AutoOpen()` subroutine automatically triggers upon opening the document.
  2. It initializes an `MSXML2.XMLHTTP` object to send an HTTP `GET` request to the Stage-2 staging URL:
     ```text
     hxxps://files.boogeymanisback[.]lol/aa2a9c53cbb80416d3b47d85538d9971/update.png
     ```
  3. Using `Adodb.Stream`, the response body is written to disk as a JScript file at **`C:\ProgramData\update.js`**.
  4. Finally, `WScript.Shell` executes the dropped script via:
     ```cmd
     wscript.exe C:\ProgramData\update.js
     ```

<img width="944" height="877" alt="obraz" src="https://github.com/user-attachments/assets/2e702161-6477-4371-a4b2-c3e25b538814" />


---

## 3. Endpoint Memory Forensics (`WKSTN-2961.raw` – Volatility 3)

Following the initial execution alert on Maxine's workstation (`WKSTN-2961`), a full RAM dump (`WKSTN-2961.raw`) was acquired using `DumpIt.exe` and analyzed with **Volatility 3**.

### 3.1. Process Tree Reconstruction & Stage-2 Execution (`wscript.exe`)
Enumerating active processes and their parent-child relationships exposed the exact execution chain originating from Microsoft Outlook:
* **Commands Used:**
  ```bash
  vol -f WKSTN-2961.raw windows.pstree.PsTree
  vol -f WKSTN-2961.raw windows.cmdline | grep wscript
  ```
* **Process Lineage:**
  * `OUTLOOK.EXE` (`PID: 1440`, `PPID: 596`)
    * `└── WINWORD.EXE` (`PID: 1124`, `PPID: 1440`) – Opened malicious attachment at `14:12:31 UTC`
      * `└── wscript.exe` (**`PID: 4260`**, **`PPID: 1124`**) – Spawned at `14:12:47 UTC`
* **Stage-2 Payload Path (`cmdline`):**
  ```text
  wscript.exe C:\ProgramData\update.js
  ```
* **Cached Outlook Attachment Path (`windows.filescan`):**
  Querying the memory dump for file objects (`vol -f WKSTN-2961.raw windows.filescan | grep Resume_WesleyTaylor`) confirmed the exact path where Outlook cached the opened attachment:
  ```text
  C:\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc
  ```

<img width="946" height="825" alt="obraz" src="https://github.com/user-attachments/assets/bb5e5e60-7a99-4e63-a3af-b8e268a961cf" />


<img width="946" height="52" alt="obraz" src="https://github.com/user-attachments/assets/bb2bf5b6-be38-4304-8148-b3802e36b9b0" />


<img width="744" height="109" alt="obraz" src="https://github.com/user-attachments/assets/61e8911a-1f9e-4820-a6b9-5256a384c8e6" />



---

### 3.2. Stage-3 C2 Binary & Network Connection Analysis (`updater.exe`)
Inspecting memory strings associated with the attacker's domain (`files.boogeymanisback.lol`) and correlating child processes of `wscript.exe` (`PID: 4260`) revealed the Stage-3 payload:

1. **Stage-3 Download URL:**
   * **Command Used:** `strings WKSTN-2961.raw | grep -i "files.boogeymanisback.lol"`
   * **Discovered URL:** `hxxps://files.boogeymanisback[.]lol/aa2a9c53cbb80416d3b47d85538d9971/update.exe`
2. **Malicious C2 Process Identification:**
   * **Process Name:** `updater.exe` (**`PID: 6216`**, `PPID: 4260`), spawned by `wscript.exe` at `14:12:48 UTC`.
   * **Full File Path (`vol -f WKSTN-2961.raw windows.cmdline | grep updater.exe`):**
     ```text
     C:\Windows\Tasks\updater.exe
     ```
3. **Active C2 Network Communication (`windows.netscan`):**
   * **Command Used:** `vol -f WKSTN-2961.raw windows.netscan | grep 6216`
   * **Finding:** Process `updater.exe` (`PID: 6216`) on local host `10.10.49.181` initiated multiple outbound `TCPv4` connections to the Command and Control (C2) server at **`128.199.95[.]189:8080`**.

<img width="745" height="273" alt="obraz" src="https://github.com/user-attachments/assets/8440d54c-d177-4d99-9878-7cdfc758240d" />


<img width="742" height="54" alt="obraz" src="https://github.com/user-attachments/assets/9372d4ac-aa05-4a7b-a966-001a6e981e5e" />


<img width="744" height="438" alt="obraz" src="https://github.com/user-attachments/assets/8d9f6833-86ce-44e6-8991-37acbe0c1cb7" />


---

### 3.3. Fileless Registry Persistence via Scheduled Task (`schtasks`)
Searching the memory image for scheduled task artifacts exposed how the attacker established long-term persistence on `WKSTN-2961`:
* **Command Used:** `strings WKSTN-2961.raw | grep schtasks`
* **Identified Persistence Command:**
  ```powershell
  schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))\"'
  ```
* **Technical Analysis:** The attacker created a daily scheduled task named **`Updater`** (triggering at `09:00` daily) that launches a hidden, non-interactive PowerShell session. Rather than referencing a file on disk, the command queries (`gp` / `Get-ItemProperty`) the Windows Registry key **`HKCU:\Software\Microsoft\Windows\CurrentVersion`** (value **`debug`**), decodes its Base64 contents, and executes it directly in memory via `IEX` (`Invoke-Expression`).

<img width="744" height="516" alt="obraz" src="https://github.com/user-attachments/assets/d95b277a-58b6-4b76-9a9e-a6ada07f1cd2" />


---

## 4. Consolidated Indicators of Compromise (IoCs)

| Indicator Type | Value (Defanged) | Context |
| :--- | :--- | :--- |
| **Email Address** | `westaylor23@outlook[.]com` | Attacker email used to deliver malicious resume |
| **MD5 Hash** | `52c4384a0b9e248b95804352ebec6c5b` | Malicious Word document `Resume_WesleyTaylor.doc` |
| **SHA-256 Hash** | `42b25e63c48be36aa219fe2192711affb5d05d7a25a38b9b990beb19f06abc` | SHA-256 signature of `Resume_WesleyTaylor.doc` |
| **Domain** | `files.boogeymanisback[.]lol` | Attacker payload staging domain |
| **URL (Stage 2)** | `hxxps://files.boogeymanisback[.]lol/aa2a9c53cbb80416d3b47d85538d9971/update.png` | JScript dropper disguised as PNG |
| **URL (Stage 3)** | `hxxps://files.boogeymanisback[.]lol/aa2a9c53cbb80416d3b47d85538d9971/update.exe` | Stage-3 C2 executable URL |
| **IPv4 / Port** | `128.199.95[.]189:8080` | External C2 server contacted by `updater.exe` (`PID: 6216`) |
| **File Path** | `C:\ProgramData\update.js` | Dropped Stage-2 JScript executed via `wscript.exe` |
| **File Path** | `C:\Windows\Tasks\updater.exe` | Dropped Stage-3 C2 binary |
| **Registry Key** | `HKCU:\Software\Microsoft\Windows\CurrentVersion\debug` | Registry value storing Base64-encoded persistence payload |
| **Scheduled Task** | `Updater` | Daily scheduled task (09:00) executing registry payload |

---

## 5. MITRE ATT&CK Mapping & Remediation

### MITRE ATT&CK Techniques
* **`T1566.001` – Phishing: Spearphishing Attachment:** Delivery of `Resume_WesleyTaylor.doc` containing a malicious VBA macro (`T1204.002`).
* **`T1059.005` & `T1059.007` – Command and Scripting Interpreter (VBA & JScript):** `AutoOpen` VBA macro dropping and executing `C:\ProgramData\update.js` via `wscript.exe`.
* **`T1053.005` – Scheduled Task/Job: Scheduled Task:** Creation of the `Updater` daily task via `schtasks.exe`.
* **`T1112` & `T1027` – Modify Registry / Obfuscated Files or Information:** Storing a Base64-encoded PowerShell payload inside `HKCU:\Software\Microsoft\Windows\CurrentVersion\debug` for fileless execution (`T1059.001`).
* **`T1071.001` – Application Layer Protocol: Web Protocols:** C2 communication over port `8080` to `128.199.95.189`.

### Recommended Remediation Actions
1. **Endpoint Isolation & Process Termination:** Immediately isolate host `WKSTN-2961` (`10.10.49.181`). Terminate malicious processes `wscript.exe` (`PID: 4260`) and `updater.exe` (`PID: 6216`).
2. **Persistence & Artifact Eradication:** Delete the `Updater` scheduled task (`schtasks /Delete /TN Updater /F`), remove the registry value `HKCU:\Software\Microsoft\Windows\CurrentVersion\debug`, and purge `C:\ProgramData\update.js`, `C:\Windows\Tasks\updater.exe`, and the cached `.doc` file in `INetCache\Content.Outlook`.
3. **Network & Policy Hardening:** Block `128.199.95.189` and `*.boogeymanisback.lol` at the perimeter firewall/DNS sinkhole. Enforce Group Policy (GPO) Attack Surface Reduction (ASR) rules to block Office macros from spawning child processes (`WINWORD.EXE` -> `wscript.exe`) and associate `.js` files with `notepad.exe` by default.
