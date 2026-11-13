# Incident Report: Yellow Rat – Yellow Cockatoo (Jupyter / SolarMarker) Threat Intelligence & Artifact Triage

| Metadata | Details | 
| ----- | ----- | 
| **Date** | November 2026 | 
| **Analyst** | Piotr Asyngier | 
| **Tools Used** | VirusTotal, OSINT / Threat Intelligence Reports (Red Canary, Zscaler) | 
| **Category** | Threat Intelligence, Malware Attribution & Host Artifact Analysis | 
| **Target Sample (SHA-256)** | `30e527e45f50d2ba92865c5679b4fe989ee0a1755361ab01673950810d071c85` | 

## 1. Executive Summary

During an incident response engagement, a suspicious `.NET` Dynamic Link Library (`SHA-256: 30e527e45f50d2ba92865c5679b4fe989ee0a1755361ab01673950810d071c85`) was recovered from an affected workstation. A threat intelligence investigation leveraging **VirusTotal** telemetry and vendor research (**Red Canary** and **Zscaler**) was conducted to attribute the threat cluster, establish the malware's development and sighting timeline, identify host-level persistence artifacts, and extract Command-and-Control (C2) indicators.

The investigation confirmed that the binary belongs to the **Yellow Cockatoo** threat cluster (also tracked across the industry as **Jupyter Infostealer**, **SolarMarker**, or **Polazert**):

1. **Threat Attribution & File Profile:** The sample is a 68.00 KB (`69,632 bytes`) 32-bit `.NET` assembly (`Win32 DLL`) internally named **`111bc461-1ca8-43c6-97ed-911e0e69fdf8.dll`**, attributed by Red Canary to the **`yellow cockatoo`** RAT/infostealer cluster.
2. **Development & Sighting Timeline:** Portable Executable (PE) metadata indicates the payload was compiled on **`2020-09-24 18:26:47 UTC`** and was first submitted to VirusTotal roughly three weeks later on **`2020-10-15 02:47:37 UTC`**.
3. **Host Persistence & C2 Infrastructure:** The malware establishes persistence by writing startup `.lnk` shortcuts and dropping an encrypted configuration/tracking file named **`solarmarker.dat`** into the user's `AppData` directory, while communicating with its Command-and-Control server at **`hxxps://gogohid.com`**.

## 2. Threat Intelligence & Technical Analysis

### 2.1. Threat Cluster Attribution (`yellow cockatoo`)

To identify the threat group/cluster associated with the SHA-256 hash provided in `hash.txt` (`30e527e45f50d2ba92865c5679b4fe989ee0a1755361ab01673950810d071c85`), the hash was queried in **VirusTotal** and cross-referenced with community intelligence tags and vendor publications.

* **VirusTotal Community & OSINT Findings:**
  * Community threat feeds (`NeikiAnalytics`) tagged the `68.00 KB` Win32 DLL with `#malware #pedll #polazert #msil #jupyter #delphi`.
  * Cross-referencing the `#jupyter` / `#polazert` / `#solarmarker` family tags with **Red Canary** technical analysis confirmed that Red Canary tracks this specific `.NET` RAT/infostealer cluster under the name yellow cockatoo.

<img width="1852" height="967" alt="obraz" src="https://github.com/user-attachments/assets/4910ccd4-a61e-4498-92a1-5ec98e219c87" />


### 2.2. Malware Common & Internal Filename Identification (`111bc461-1ca8-43c6-97ed-911e0e69fdf8.dll`)

To assist incident responders in scanning other endpoints for the presence of this DLL, the **Details** tab in VirusTotal was inspected for PE Version Info and commonly observed filenames.

* **Findings:**
  * **Internal Name (File Version Information):** `111bc461-1ca8-43c6-97ed-911e0e69fdf8.dll`
  * **Common Filename (Names List):** **`111bc461-1ca8-43c6-97ed-911e0e69fdf8.dll`**
  * **Module VersionId:** `11bc5a57-32dd-45b4-9d54-9549c25ec26a`
  * **File Type:** `PE32 executable (DLL) (console) Intel 80386 Mono/.Net assembly, for MS Windows` (`69,632 bytes`).

<img width="1852" height="967" alt="obraz" src="https://github.com/user-attachments/assets/a73f382f-b210-4c18-bed3-1a95cabfb336" />


### 2.3. PE Compilation Timestamp Analysis (`2020-09-24 18:26`)

Inspecting the **History** and **Portable Executable Info** sections under the VirusTotal **Details** tab revealed when the `.NET` assembly was compiled by the threat actor.

* **Findings:**
  * **Creation Time / Compilation Timestamp:** **`2020-09-24 18:26:47 UTC`** (**`2020-09-24 18:26`**).
  * **Target Machine:** `Intel 386 or later processors and compatible processors`
  * **Entry Point:** `0x00012FDE`

<img width="1852" height="967" alt="obraz" src="https://github.com/user-attachments/assets/93fd3a5f-150f-4d9d-9ab4-9b13773ca37f" />


### 2.4. First Community Sighting on VirusTotal (`2020-10-15 02:47`)

To determine the dwell-time window between the malware's compilation and its initial discovery by the security community, the **History** section in VirusTotal was reviewed.

* **Findings:**
  * **First Submission:** **`2020-10-15 02:47:37 UTC`** (**`2020-10-15 02:47`**).
  * **First Seen In The Wild:** `2021-01-12 20:40:12 UTC`

<img width="1852" height="967" alt="obraz" src="https://github.com/user-attachments/assets/a1a67c60-5789-4b7a-9b7d-06ac035a8531" />


### 2.5. Dropped AppData Artifact Identification (`solarmarker.dat`)

Reviewing technical analysis reports from Red Canary and Zscaler regarding **Yellow Cockatoo / SolarMarker** execution and persistence mechanisms revealed how the PowerShell loader stages artifacts on the victim's filesystem.

* **Behavioral & Persistence Analysis:**
  * The initial PowerShell loader uses logical `-bxor` operations to deobfuscate commands and writes malicious `.lnk` (shortcut) files into the Windows Startup directory alongside `.dat` files in `AppData` (`%APPDATA%\Roaming\`).
  * Specifically, the malware creates a file named **`solarmarker.dat`** inside the `AppData` folder to store victim tracking/identification data and stage the command-line script that loads the malicious `.NET` DLL into memory.

<img width="1852" height="963" alt="obraz" src="https://github.com/user-attachments/assets/811e1feb-ec1f-4a2d-8056-bc5ac988aca8" />


### 2.6. Command-and-Control (C2) Server Identification (`hxxps://gogohid.com`)

Pivoting to the **Behavior** tab (`Activity Summary`) in VirusTotal for the sample (`30e527e45f50d2ba92865c5679b4fe989ee0a1755361ab01673950810d071c85`) exposed the network indicators and memory pattern URLs extracted during sandbox detonation.

* **Findings:**
  * **Memory Pattern Domains:** `gogohid.com`
  * **Memory Pattern URLs (C2 Server):** **`hxxps://gogohid.com`** (`https://gogohid.com`).

<img width="1852" height="967" alt="obraz" src="https://github.com/user-attachments/assets/f24a0d9d-952b-4a96-a233-29844af3a90f" />


## 3. Malware Lifecycle & Artifact Timeline

| Timestamp (UTC) | Event Type | Details | 
| ----- | ----- | ----- | 
| `2020-09-24 18:26:47` | **PE Compilation** | Malware sample (`111bc461-1ca8-43c6-97ed-911e0e69fdf8.dll`) compiled by the threat actor. | 
| `2020-10-15 02:47:37` | **First VT Submission** | Sample first uploaded to VirusTotal for analysis (~21 days after compilation). | 
| `2021-01-12 20:40:12` | **First Seen ITW** | Recorded "First Seen In The Wild" timestamp in VirusTotal telemetry. | 

## 4. Consolidated Indicators of Compromise (IoCs)

| Indicator Type | Value (Defanged) | Context | 
| ----- | ----- | ----- | 
| **SHA-256** | `30e527e45f50d2ba92865c5679b4fe989ee0a1755361ab01673950810d071c85` | Yellow Cockatoo / Jupyter / SolarMarker `.NET` DLL (`69,632 B`) | 
| **MD5** | `f196ef0b4300d0b22368b07b071c852d` *(from VT)* | MD5 hash of the Yellow Cockatoo DLL | 
| **Internal / Common Filename** | `111bc461-1ca8-43c6-97ed-911e0e69fdf8.dll` | Original PE internal name and common filename on disk | 
| **Host Artifact (`.dat`)** | `solarmarker.dat` | File dropped in `%APPDATA%` by Yellow Cockatoo / SolarMarker | 
| **C2 URL / Domain** | `hxxps://gogohid[.]com` (`gogohid[.]com`) | Command-and-Control server extracted from memory patterns | 

## 5. Summary of Lab Questions & Answers

| Question | Answer | 
| ----- | ----- | 
| **Q1:** What name does Red Canary use for the threat cluster associated with the SHA256 in `hash.txt`? | `yellow cockatoo` | 
| **Q2:** What is the common filename associated with this malware? | `111bc461-1ca8-43c6-97ed-911e0e69fdf8.dll` | 
| **Q3:** What compilation timestamp does VirusTotal show for this malware sample? | `2020-09-24 18:26` | 
| **Q4:** When was the malware first submitted to VirusTotal? | `2020-10-15 02:47` | 
| **Q5:** What is the name of the `.dat` file that the malware dropped in the `AppData` folder? | `solarmarker.dat` | 
| **Q6:** What is the C2 server that the malware is communicating with? | `hxxps://gogohid.com` | 

## 6. MITRE ATT&CK Mapping & Remediation

### MITRE ATT&CK Techniques

* **`T1059.001` – Command and Scripting Interpreter: PowerShell:** Executing PowerShell commands containing `-bxor` bitwise XOR decoders and `[Reflection.Assembly]::Load` to load the `.NET` DLL into memory.
* **`T1547.001` – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder:** Creating malicious `.lnk` shortcut files inside the Windows Startup directory that invoke PowerShell/cmd to launch the payload stored in `AppData`.
* **`T1027` – Obfuscated Files or Information:** Storing encrypted/encoded payload data inside `.dat` files (`solarmarker.dat`) and using XOR obfuscation in scripts.
* **`T1071.001` – Application Layer Protocol: Web Protocols:** Communicating with the C2 server (`hxxps://gogohid.com`) over HTTPS.

### Recommended Remediation Actions

1. **Host Eradication:** Search all endpoints across the environment for `solarmarker.dat` in `%APPDATA%`, `111bc461-1ca8-43c6-97ed-911e0e69fdf8.dll`, and suspicious `.lnk` files in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` invoking `powershell.exe`, `cmd.exe`, or `mshta.exe`.
2. **Network Blocking:** Block outbound DNS and HTTPS traffic to `gogohid.com` at the corporate firewall, DNS sinkhole, and web proxy.
3. **Detection Engineering:** Configure EDR/SIEM alerts for PowerShell processes executing command lines containing `-bxor` or `FromBase64String` in conjunction with file creation events (`.lnk` or `.dat`) inside `AppData` or Startup directories.
