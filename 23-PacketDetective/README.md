# Incident Report: PacketDetective – SMB/DCE-RPC Forensics, Event Log Clearing, Named Pipe Lateral Movement & PsExec Execution

| Metadata | Details |
| :--- | :--- |
| **Date** | November 2026 |
| **Analyst** | Piotr Asyngier |
| **Tools Used** | Wireshark (`Traffic-1.pcapng`, `Traffic-2.pcapng`, `Traffic-3.pcapng`) |
| **Category** | Network Forensics, Defense Evasion, Lateral Movement & Remote Execution |
| **Affected Environment** | Internal Subnet `172.16.66.0/24` (Target Server: `01566S-WIN16-IR` / `172.16.66.36`; Source Hosts: `172.16.66.1` [`02694W-WIN10`], `172.16.66.37`) |

---

## 1. Executive Summary

In September 2020, SOC analysts detected anomalous Server Message Block (SMB) and Remote Procedure Call (DCE/RPC) activity targeting internal Windows Server **`172.16.66.36`** (`01566S-WIN16-IR`). A forensic review of three network packet captures (`Traffic-1.pcapng`, `Traffic-2.pcapng`, and `Traffic-3.pcapng`) was conducted in **Wireshark** to reconstruct the threat actor's lateral movement, persistence mechanisms, and defense evasion tactics.

The investigation uncovered three distinct stages of malicious post-exploitation activity directed at `172.16.66.36`:

1. **Covert Persistence & PsExec Remote Execution (`Traffic-3.pcapng`):** On July 19, 2020, an attacker operating from `172.16.66.1` (`02694W-WIN10`) authenticated over SMB2 using a rogue account named **`backdoor`** (`3B\backdoor`), mounted `\\172.16.66.36\ADMIN$`, and staged **`psexesvc.exe`** (`PSEXESVC.exe`) for remote command execution.
2. **DCOM / RPC Lateral Movement via Named Pipes (`Traffic-2.pcapng`):** On July 24, 2020, across an **`11.7247`-second** communication window between `172.16.66.1` and `172.16.66.36`, DCOM `ISystemActivator` (`RemoteCreateInstance`) activity exposed named-pipe RPC bindings targeting the Task Scheduler service (**`atsvc`**) under `NT AUTHORITY\SYSTEM`.
3. **Anti-Forensic Event Log Clearing (`Traffic-1.pcapng`):** On September 23, 2020, an attacker host at `172.16.66.37` established an SMB session (`4,406` SMB bytes) to `172.16.66.36` using the privileged **`Administrator`** account, opened the **`\eventlog`** named pipe over `IPC$`, and invoked the `ClearEventLogW` RPC operation (`opnum 0`) at **`2020-09-23 16:50` UTC** to erase audit trails.

---

## 2. Network Traffic Investigation & Technical Analysis

### Part I: `Traffic-1.pcapng` – Privileged SMB Access & Event Log Clearing

#### 2.1. SMB Protocol Byte Volume (`4406` Bytes)
To quantify SMB protocol usage across the first capture (`32` total packets, `6,262` total frame bytes), Wireshark's **Protocol Hierarchy Statistics** (`Statistics -> Protocol Hierarchy`) were reviewed.

* **Findings:**
  * **SMB (Server Message Block Protocol):** `100.0%` of packets (`32` packets), representing `70.4%` of captured bytes.
  * **Total SMB Protocol Bytes (Q1):** **`4406`** bytes (`End Bytes: 3765`, encapsulating `332` bytes of DCE/RPC and `116` bytes of Event Logger traffic).

<img width="1851" height="960" alt="obraz" src="https://github.com/user-attachments/assets/32613fa6-46f5-4964-805e-22dd2d5c45c4" />


---

#### 2.2. Compromised Privileged Account Identification (`Administrator`)
Filtering the capture for SMB traffic (`smb` / `tcp.stream eq 0`) isolated the NTLMSSP authentication handshake between `172.16.66.37:50106` and `172.16.66.36:445`.

* **Wireshark Display Filter:**
  ```text
  smb
  ```
* **Findings (`Frame 5`, `2020-09-23 16:50:16.691265 UTC`):**
  * Navigating through `SMB -> Session Setup AndX Request -> Security Blob -> GSS-API -> Simple Protected Negotiation -> negTokenTarg -> NTLM Secure Service Provider -> User name` (`ntlmssp.auth.username`) revealed:
    * **Authenticated Username (Q2):** **`Administrator`** (`User: \Administrator`, `Domain name: NULL`).
  * Frame `6` (`16:50:16.693160 UTC`) confirmed successful authentication (`Session Setup AndX Response`).

<img width="1851" height="960" alt="obraz" src="https://github.com/user-attachments/assets/b1f0ad6c-2ff4-4dde-bdd2-4beecaad0353" />

<img width="1851" height="960" alt="obraz" src="https://github.com/user-attachments/assets/382d0fbc-0949-4191-9c3a-1b402b357c05" />


---

#### 2.3. Accessed Pipe / File Identification (`eventlog`)
Immediately following authentication, the attacker mounted `\\172.16.66.36\IPC$` (`Frame 7`) and issued an `NT Create AndX Request` to open a specific system named pipe.

* **Findings (`Frame 9`, `2020-09-23 16:50:16.698044 UTC`):**
  * **Packet Summary:** `NT Create AndX Request, FID: 0x4000, Path: \eventlog` (`Access Mask: 0x00000003`, `Disposition: Open`).
  * **Opened File / Pipe Name (Q3):** **`eventlog`** (`\eventlog`).

<img width="1851" height="960" alt="obraz" src="https://github.com/user-attachments/assets/d7fc38c9-4910-49cf-b758-1b693e6b1bcb" />


---

#### 2.4. Event Log Clearing Timestamp (`2020-09-23 16:50`)
After binding to the `EVENTLOG` DCE/RPC interface (`Frame 11`) and invoking `OpenEventLogW` (`Frame 15`), the attacker triggered an RPC call to wipe the event log. In Windows DCE/RPC Event Logger (`MS-EVEN`), `ClearEventLogW` corresponds to operation number (`opnum`) `0`.

* **Wireshark Display Filter:**
  ```text
  dcerpc.opnum == 0
  ```
* **Findings (`Frame 19`):**
  * **Packet Summary:** `EVENTLOG ClearEventLogW request` (`169 bytes`, `172.16.66.37:50106 -> 172.16.66.36:445`, `Call: 2, Ctx: 0`).
  * **Exact Timestamp (UTC):** `2020-09-23 16:50:16.731550` (**`2020-09-23 16:50`**) (Q4).

<img width="1851" height="960" alt="obraz" src="https://github.com/user-attachments/assets/8a8aa736-33c1-4caa-a319-0d197f3ad6e2" />


---

### Part II: `Traffic-2.pcapng` – Named Pipe RPC Service & Session Duration

#### 2.5. Named Pipe RPC Service Identification (`atsvc`)
To locate Windows named pipe references (`\PIPE`) encoded in UTF-16LE (`5c:00:50:00:49:00:50:00:45`) inside `Traffic-2.pcapng` (`139` packets), a raw hex byte filter was applied.

* **Wireshark Display Filter:**
  ```text
  frame contains 5c:00:50:00:49:00:50:00:45
  ```
* **Findings (`Frame 25`, `2020-07-24 10:13:45.504223 UTC`):**
  * The filter isolated a `1,190`-byte `ISystemActivator RemoteCreateInstance response` sent from `172.16.66.36` to `172.16.66.1`.
  * Inspecting `RemoteRequestPtr -> RemoteReply -> OxidBindingsPtr -> OxidBindings -> StringBinding[1]` revealed:
    * `NetworkAddr: "\\\\01566S-WIN16-IR[\\PIPE\\atsvc]"`
    * `SecurityBinding[1]: PrincName="NT AUTHORITY\SYSTEM"`
  * **Communicating Service Name (Q5):** **`atsvc`** (Windows Task Scheduler AT-Service RPC interface).

<img width="1851" height="960" alt="obraz" src="https://github.com/user-attachments/assets/ada9ed4b-d0d3-4876-b0d3-0e38c3567658" />


---

#### 2.6. Communication Duration Measurement (`11.7247` Seconds)
To determine how long `172.16.66.1` and `172.16.66.36` exchanged traffic in `Traffic-2.pcapng`, Wireshark's **Conversations** statistics (`Statistics -> Conversations -> IPv4`) were examined.

* **Findings:**
  * **Conversation:** `172.16.66.1` <-> `172.16.66.36` (`133` packets, `104 kB` total: `50` packets / `15 kB` from A->B and `83` packets / `88 kB` from B->A).
  * **Communication Duration (Q6):** **`11.7247`** seconds.

<img width="1851" height="960" alt="obraz" src="https://github.com/user-attachments/assets/44bdb2f6-10ef-41a7-8312-6932fb2b1843" />


---

### Part III: `Traffic-3.pcapng` – Rogue Account Authentication & PsExec Staging

#### 2.7. Rogue Persistence Account Identification (`backdoor`)
Examining the SMB2 session setup packets at the beginning of `Traffic-3.pcapng` (`264` total packets) revealed an authentication request from `172.16.66.1:52445` to `172.16.66.36:445`.

* **Findings (`Frame 5`, `2020-07-19 13:14:41.182561 UTC`):**
  * **Packet Summary:** `SMB2 Session Setup Request, NTLMSSP_AUTH, User: 3B\backdoor` (`721 bytes`).
  * Inspecting the NTLM Secure Service Provider fields (`ntlmssp.auth.username`) confirmed:
    * **Domain Name:** `3B`
    * **Source Host Name:** `02694W-WIN10` (`Version 10.0 Build 10586`)
    * **Username Used (Q7):** **`backdoor`**
<img width="1851" height="960" alt="obraz" src="https://github.com/user-attachments/assets/cdbbb5df-833e-42e7-8775-5077387e6899" />


---

#### 2.8. Remote Execution Service Binary Identification (`psexesvc.exe`)
Following successful SMB2 authentication as `3B\backdoor` (`Frame 6`), the attacker connected to the hidden administrative share `\\172.16.66.36\ADMIN$` (`Frame 7`) and created a remote service executable on the target server.

* **Findings (`Frame 11`, `2020-07-19 13:14:41.184987 UTC`):**
  * **Packet Summary:** `SMB2 Create Request File: PSEXESVC.exe` (`382 bytes`, `Disposition: Overwrite If`, `Access Mask: 0x00120196` – Read/Write).
  * Subsequent TCP/SMB2 packets (`Frames 13+`) transferred the `PSEXESVC.exe` binary across the network to establish remote process execution via Sysinternals PsExec.
  * **Remote Execution Executable Name (Q8):** **`psexesvc.exe`** (`PSEXESVC.exe`).

<img width="1851" height="960" alt="obraz" src="https://github.com/user-attachments/assets/972d71a9-bde0-47d1-9f71-dc797b507134" />


---

## 3. Consolidated Chronological Attack Timeline

Ordering the three packet captures chronologically illustrates the progression from initial covert remote execution to DCOM/RPC lateral movement and eventual anti-forensic log wiping:

| Timestamp (UTC) | Source Capture | Source IP | Destination IP | Protocol / Frame | Activity Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `2020-07-19 13:14:41.182` | `Traffic-3.pcapng` | `172.16.66.1` (`02694W-WIN10`) | `172.16.66.36:445` | `SMB2` (`#5`) | Attacker authenticates using rogue account `3B\backdoor`. |
| `2020-07-19 13:14:41.184` | `Traffic-3.pcapng` | `172.16.66.1` | `172.16.66.36:445` | `SMB2` (`#7`, `#11`) | Mounts `\\172.16.66.36\ADMIN$` and uploads `PSEXESVC.exe` for remote execution. |
| `2020-07-24 10:13:45.504` | `Traffic-2.pcapng` | `172.16.66.36` (`01566S-WIN16-IR`) | `172.16.66.1` | `ISystemActivator` (`#25`) | DCOM `RemoteCreateInstance` exposes `\PIPE\atsvc` RPC binding (`11.7247s` total session). |
| `2020-09-23 16:50:16.691` | `Traffic-1.pcapng` | `172.16.66.37` | `172.16.66.36:445` | `SMB` (`#5`) | Attacker authenticates to `172.16.66.36` over SMBv1 as `\Administrator`. |
| `2020-09-23 16:50:16.698` | `Traffic-1.pcapng` | `172.16.66.37` | `172.16.66.36:445` | `SMB` (`#7`, `#9`) | Connects to `\\172.16.66.36\IPC$` and opens the `\eventlog` named pipe (`FID: 0x4000`). |
| `2020-09-23 16:50:16.731` | `Traffic-1.pcapng` | `172.16.66.37` | `172.16.66.36:445` | `EVENTLOG` (`#19`) | Invokes `ClearEventLogW` (`dcerpc.opnum == 0`) to wipe Windows Event Logs. |

---

## 4. Consolidated Indicators of Compromise (IoCs)

| Indicator Type | Value | Context |
| :--- | :--- | :--- |
| **Target Server IPv4 / Hostname** | `172.16.66.36` (`01566S-WIN16-IR` / `00:50:56:23:45:59`) | Compromised Windows Server targeted across all three captures |
| **Source Host 1 IPv4 / Hostname** | `172.16.66.1` (`02694W-WIN10` / `00:50:56:0c:d5:49`) | Source of `3B\backdoor` PsExec execution and DCOM/`atsvc` session |
| **Source Host 2 IPv4 / MAC** | `172.16.66.37` (`00:50:56:34:fb:f7`) | Source of `\Administrator` SMB session and remote `ClearEventLogW` |
| **Compromised / Rogue Accounts** | `Administrator`, `3B\backdoor` | Privileged and non-standard accounts used for SMB authentication |
| **Remote Service Binary** | `PSEXESVC.exe` (`psexesvc.exe`) | PsExec binary written to `\\172.16.66.36\ADMIN$` |
| **Abused Named Pipes / Services** | `\eventlog`, `\PIPE\atsvc` (`IPC$`, `ADMIN$`) | RPC pipes used for event log clearing and scheduled task execution |

---

## 5. Summary of Lab Questions & Answers

| Question | File | Answer |
| :--- | :--- | :--- |
| **Q1:** What is the total number of bytes of the SMB protocol? | `Traffic-1.pcapng` | `4406` |
| **Q2:** Which username was utilized for authentication via SMB? | `Traffic-1.pcapng` | `Administrator` |
| **Q3:** What is the name of the file that was opened by the attacker? | `Traffic-1.pcapng` | `eventlog` |
| **Q4:** What is the timestamp of the attempt to clear the event log? (24-hour UTC) | `Traffic-1.pcapng` | `2020-09-23 16:50` |
| **Q5:** What is the name of the service that communicated using this named pipe? | `Traffic-2.pcapng` | `atsvc` |
| **Q6:** What was the duration of communication between `172.16.66.1` and `172.16.66.36`? | `Traffic-2.pcapng` | `11.7247` |
| **Q7:** Which username was used to set up these potentially suspicious requests? | `Traffic-3.pcapng` | `backdoor` |
| **Q8:** What is the name of the executable file utilized to execute processes remotely? | `Traffic-3.pcapng` | `psexesvc.exe` |

---

## 6. MITRE ATT&CK Mapping & Remediation

### MITRE ATT&CK Techniques
* **`T1021.002` – Remote Services: SMB/Windows Admin Shares:** Authenticating to `\\172.16.66.36\IPC$` and `\\172.16.66.36\ADMIN$` over TCP port `445`.
* **`T1569.002` – System Services: Service Execution:** Deploying `PSEXESVC.exe` over `ADMIN$` to achieve remote command execution (`Traffic-3.pcapng`).
* **`T1053.002` / `T1021.003` – Scheduled Task/Job (`At`) & DCOM:** Interacting with `ISystemActivator` (`RemoteCreateInstance`) and the `\PIPE\atsvc` named pipe (`Traffic-2.pcapng`).
* **`T1070.001` – Indicator Removal: Clear Windows Event Logs:** Invoking `ClearEventLogW` (`dcerpc.opnum == 0`) over `\eventlog` to erase forensic evidence (`Traffic-1.pcapng`).
* **`T1078` – Valid Accounts:** Abusing both the built-in `Administrator` account and a rogue `3B\backdoor` account.

### Recommended Remediation Actions
1. **Account Eradication & Credential Rotation:** Immediately disable and delete the rogue `3B\backdoor` account, rotate the local and domain `Administrator` credentials across the `172.16.66.0/24` segment, and audit Active Directory / SAM databases for additional unauthorized accounts.
2. **Centralized Log Forwarding & Anti-Tampering:** Because the attacker remotely wiped local logs via `ClearEventLogW`, configure **Windows Event Forwarding (WEF)** or a SIEM agent to stream Security (`Event ID 1102` – *Audit log was cleared*), System (`Event ID 7045`), and SMB (`Event ID 5140`/`5145`) logs off-host in real time.
3. **SMB & RPC Hardening:** Disable legacy **SMBv1** (observed in `Traffic-1.pcapng`), enforce **SMB Signing**, restrict remote access to `ADMIN$` and `IPC$` via host firewalls, and limit administrative RPC/DCOM connections strictly to hardened Privileged Access Workstations (PAWs).
