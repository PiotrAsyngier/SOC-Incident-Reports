# Incident Report: Ramnit – Windows Memory Forensics (Volatility 3), Process Extraction & C2 Infrastructure Analysis

| Metadata | Details | 
| ----- | ----- | 
| **Date** | November 2026 | 
| **Analyst** | Piotr Asyngier | 
| **Tools Used** | Volatility 3 Framework (`windows.pstree`, `windows.netscan`, `windows.dumpfiles`), `sha1sum`, IP Geolocation, VirusTotal | 
| **Category** | Memory Forensics, Malware Extraction & Threat Intelligence | 
| **Affected Environment** | Windows Workstation (`192.168.19.133`, User: `alex`, Image: `memory.dmp`) | 

## 1. Executive Summary

Following an endpoint security alert on user **`alex`**'s Windows workstation (**`192.168.19.133`**), a full volatile memory image (`memory.dmp`) was acquired for forensic examination. Using the **Volatility 3 Framework**, the investigation reconstructed active processes, active/closed network sockets, and in-memory executable sections, followed by **VirusTotal** threat intelligence correlation.

The memory analysis confirmed a trojanized installer infection (**Ramnit** family):

1. **Suspicious Process Execution:** User `alex` executed a masqueraded Google Chrome installer named **`ChromeSetup.exe`** (`PID 4628`, Parent `PID 4568`: `explorer.exe`) directly from **`C:\Users\alex\Downloads\ChromeSetup.exe`** at `2024-02-01 19:48:50 UTC`.

2. **Outbound C2 Communication:** One second after execution (`19:48:51 UTC`), `ChromeSetup.exe` (`PID 4628`) initiated outbound TCP connections from `192.168.19.133:49682` to external IPv4 address **`58.64.204.181`** on port **`5202`** (geolocated to **`Hong Kong`**).

3. **Memory Dumping & Malware Attribution:** Extracting the process binary from memory via `windows.dumpfiles` yielded the `ImageSectionObject` (`SHA-1: 280c9d36039f9432433893dee6126d72b9112ad2`) and `DataSectionObject` (`SHA-1: b9921cc2bfe3b43e457cdbc7d82b849c66f119cb` / `SHA-256: 56133c0d017af35f49253926e3583cf72c36146ab7faa65b6058971685166652`). Threat intelligence confirmed a PE compilation timestamp of **`2019-12-01 08:36:04 UTC`** and linked the payload to the malicious domain **`dnsnb8.net`** (`ddos.dnsnb8.net:799`).

## 2. Memory Forensics & Technical Analysis

### 2.1. Malicious Process & Executable Path Identification (`ChromeSetup.exe`)

To enumerate running processes and their parent-child hierarchy at the time of memory acquisition, the `windows.pstree` plugin was executed against `memory.dmp`.

* **Volatility 3 Command:**

  ```bash
  vol -f memory.dmp windows.pstree
  ```

* **Findings:**

  * Under `explorer.exe` (`PID 4568`), a suspicious child process was identified running from the user's `Downloads` directory:
    * **Process Name (Q1):** **`ChromeSetup.exe`**
    * **Process ID (`PID`):** `4628` (`PPID: 4568`, Offset: `0xca82b830a300`, Threads: `4`, Creation Time: `2024-02-01 19:48:50.000000 UTC`)
    * **Exact Executable Path (Q2):** **`C:\Users\alex\Downloads\ChromeSetup.exe`** (`\Device\HarddiskVolume3\Users\alex\Downloads\ChromeSetup.exe`)

<img width="1853" height="1048" alt="obraz" src="https://github.com/user-attachments/assets/b626b4fb-61a6-426c-a10c-ea485c0975ef" />


### 2.2. Network Connection Analysis (`58.64.204.181`)

To identify outbound network communications initiated by `ChromeSetup.exe` (`PID 4628`), the `windows.netscan` plugin was used to carve TCP and UDP endpoints from the memory dump.

* **Volatility 3 Command:**

  ```bash
  vol -f memory.dmp windows.netscan
  ```

* **Findings:**

  * Filtering the `netscan` output for `PID 4628` (`ChromeSetup.ex`) revealed outbound `TCPv4` socket entries at `2024-02-01 19:48:51.000000 UTC` (in `SYN_SENT` and `CLOSED` states):
    * **Local Socket:** `192.168.19.133:49682`
    * **Remote C2 IP Address (Q3):** **`58.64.204.181`** (Destination Port: `5202`)

<img width="1853" height="1048" alt="obraz" src="https://github.com/user-attachments/assets/91fdc76d-c622-4adb-8266-b2722a565418" />


### 2.3. Threat Actor C2 Geolocation (`Hong Kong`)

Querying the destination IPv4 address (`58.64.204.181`) in an IP Geolocation tool provided geographic and ISP attribution for the C2 server.

* **Geolocation Details:**

  * **City / Region (Q4):** **`Hong Kong`** (Coordinates: `22.285521, 114.157692`)
  * **ISP / Organization:** `NWT IDC Data Service` (`newworldtel.com`)
  * **Usage Type:** `Data Center / Web Hosting / Transit`

<img width="1853" height="964" alt="obraz" src="https://github.com/user-attachments/assets/06aef382-d9af-45fe-8982-92ae89bb038c" />


### 2.4. Process Memory Dumping & SHA-1 Hash Calculation (`280c9d36039f9432433893dee6126d72b9112ad2`)

To extract the `ChromeSetup.exe` binary and its loaded modules directly from the memory image for cryptographic hashing, the `windows.dumpfiles` plugin was executed targeting `--pid 4628`.

* **Commands Executed:**

  ```bash
  mkdir -p dump_files
  vol -f memory.dmp -o dump_files windows.dumpfiles --pid 4628
  sha1sum dump_files/*ChromeSetup*
  ```

* **Findings:**

  * Volatility carved two file objects for `ChromeSetup.exe` (`FileObject 0xca82b85325a0`):
    1. **`ImageSectionObject` (`file.0xca82b85325a0.0xca82b7e06c80.ImageSectionObject.ChromeSetup.exe.img`):**
       * **SHA-1 Hash (Q5):** **`280c9d36039f9432433893dee6126d72b9112ad2`**
    2. **`DataSectionObject` (`file.0xca82b85325a0.0xca82b83c7770.DataSectionObject.ChromeSetup.exe.dat`):**
       * **SHA-1 Hash:** `b9921cc2bfe3b43e457cdbc7d82b849c66f119cb` (`SHA-256: 56133c0d017af35f49253926e3583cf72c36146ab7faa65b6058971685166652`)

<img width="1162" height="867" alt="obraz" src="https://github.com/user-attachments/assets/b07d67b9-c92e-49f5-894a-15c9fb368b40" />

<img width="1033" height="90" alt="obraz" src="https://github.com/user-attachments/assets/493a4781-20c0-4d6c-93eb-7902dec398a2" />


### 2.5. Malware Compilation Timestamp Identification (`2019-12-01 08:36`)

Querying the extracted `ChromeSetup.exe` hash (`b9921cc2bfe3b43e457cdbc7d82b849c66f119cb` / `56133c0d017af35f49253926e3583cf72c36146ab7faa65b6058971685166652`) on **VirusTotal** under the **Details** tab revealed the Portable Executable (PE32) metadata and compilation history.

* **PE Metadata & History Findings:**

  * **File Type:** `Win32 EXE` (`PE32 executable (GUI) Intel 80386, for MS Windows`, Microsoft Visual C/C++ 12.00.9782, `980.00 KB` / `1,003,520 bytes`).
  * **Creation Time / Compilation Timestamp (Q6):** **`2019-12-01 08:36:04 UTC`** (**`2019-12-01 08:36`**).
  * **First Submission to VirusTotal:** `2020-01-15 02:41:31 UTC`.

<img width="1854" height="883" alt="obraz" src="https://github.com/user-attachments/assets/abf90e22-8481-4e98-be66-d90eb3beec3a" />


### 2.6. Associated Malware Domain Identification (`dnsnb8.net`)

Pivoting to the **Relations** tab (`Contacted URLs` and `Contacted Domains`) in VirusTotal for the dumped executable exposed the external domain infrastructure contacted by the malware to fetch secondary `.rar` payloads.

* **Findings:**

  * **Contacted URLs (`5`):**
    * `hxxp://ddos.dnsnb8[.]net:799/cj/k1.rar` through `k5.rar`
  * **Contacted Domains:**
    * **`dnsnb8.net`** (`14/92` detections, Registrar: `Dynadot Inc`, Created: `2020-08-13`) and subdomain `ddos.dnsnb8.net` (`13/92` detections).

<img width="1852" height="882" alt="obraz" src="https://github.com/user-attachments/assets/98a238f4-b0bf-4e2c-aa10-186ef3278937" />


## 3. Incident Timeline (February 1, 2024)

| Timestamp (UTC) | Source / Process | Destination / Target | Event Description | 
| ----- | ----- | ----- | ----- | 
| `2019-12-01 08:36:04` | Threat Actor Compiler | `ChromeSetup.exe` | Malware PE32 executable compiled (`Microsoft Visual C/C++`). | 
| `2024-02-01 19:48:26.00` | `userinit.exe` (`4508`) | `explorer.exe` (`4568`) | User `alex` logs into workstation `192.168.19.133`. | 
| `2024-02-01 19:48:50.00` | `explorer.exe` (`4568`) | `ChromeSetup.exe` (`4628`) | Malicious binary executed from `C:\Users\alex\Downloads\ChromeSetup.exe`. | 
| `2024-02-01 19:48:51.00` | `192.168.19.133:49682` (`PID 4628`) | `58.64.204.181:5202` | `ChromeSetup.exe` initiates outbound TCP connection to C2 server in Hong Kong. | 

## 4. Consolidated Indicators of Compromise (IoCs)

| Indicator Type | Value (Defanged) | Context | 
| ----- | ----- | ----- | 
| **Malicious File Path** | `C:\Users\alex\Downloads\ChromeSetup.exe` | Trojanized Chrome installer executed under `PID 4628` | 
| **SHA-1 (`ImageSectionObject`)** | `280c9d36039f9432433893dee6126d72b9112ad2` | Memory-mapped image section of `ChromeSetup.exe` | 
| **SHA-1 (`DataSectionObject`)** | `b9921cc2bfe3b43e457cdbc7d82b849c66f119cb` | Raw on-disk data section of `ChromeSetup.exe` (`1,003,520 B`) | 
| **SHA-256 (`DataSectionObject`)** | `56133c0d017af35f49253926e3583cf72c36146ab7faa65b6058971685166652` | SHA-256 hash of `ChromeSetup.exe` | 
| **MD5 (`DataSectionObject`)** | `14f6b75515df5eee396d961e161148c5` | MD5 hash of `ChromeSetup.exe` | 
| **C2 IPv4 / Port** | `58.64.204[.]181:5202` | Outbound TCP C2 endpoint (`NWT IDC Data Service`, Hong Kong) | 
| **Malicious Domain / URLs** | `dnsnb8[.]net` / `hxxp://ddos.dnsnb8[.]net:799/cj/k[1-5].rar` | Secondary payload staging domain registered via `Dynadot Inc` | 

## 5. Summary of Lab Questions & Answers

| Question | Answer | 
| ----- | ----- | 
| **Q1:** What is the name of the process responsible for the suspicious activity? | `ChromeSetup.exe` | 
| **Q2:** What is the exact path of the executable for the malicious process? | `C:\Users\alex\Downloads\ChromeSetup.exe` | 
| **Q3:** What IP address did the malware attempt to connect to? | `58.64.204.181` | 
| **Q4:** Which city is associated with the IP address the malware communicated with? | `Hong Kong` | 
| **Q5:** What is the SHA1 hash of the malware executable? | `280c9d36039f9432433893dee6126d72b9112ad2` | 
| **Q6:** What is the compilation timestamp for the malware? | `2019-12-01 08:36` | 
| **Q7:** Can you provide the domain connected to the malware? | `dnsnb8.net` | 

## 6. MITRE ATT&CK Mapping & Remediation

### MITRE ATT&CK Techniques

* **`T1036.005` – Masquerading: Match Legitimate Name or Location:** Disguising the Ramnit dropper as a legitimate Google Chrome installer (`ChromeSetup.exe`) in the user's `Downloads` folder.
* **`T1204.002` – User Execution: Malicious File:** Relying on user `alex` to manually launch `ChromeSetup.exe` via Windows Explorer (`explorer.exe`).
* **`T1071.001` / `T1571` – Application Layer Protocol & Non-Standard Port:** Communicating with external C2 infrastructure over non-standard TCP ports (`58.64.204.181:5202` and `ddos.dnsnb8.net:799`).

### Recommended Remediation Actions

1. **Host Isolation & Re-imaging:** Because the **Ramnit** malware family is known for infecting legitimate PE executables, `.dll` files, and `.html` files across local and removable drives, isolate `192.168.19.133` immediately and perform a full OS wipe/re-image rather than relying solely on file deletion.
2. **Perimeter & DNS Blocking:** Block outbound traffic to `58.64.204.181` (port `5202`) and sinkhole `dnsnb8.net` (`*.dnsnb8.net`) at the corporate DNS resolver and firewall.
3. **Application Control & Code Signing Enforcement:** Implement AppLocker or Windows Defender Application Control (WDAC) policies to prevent unverified or unsigned executables (`Signature Verification: File is not signed`) from launching out of user-writable directories such as `C:\Users\*\Downloads\`.
