# Incident Report: PsExec Hunt – Network Traffic Forensics & SMB Lateral Movement via PsExec

| Metadata | Details | 
| ----- | ----- | 
| **Date** | November 2026 | 
| **Analyst** | Piotr Asyngier | 
| **Tools Used** | Wireshark (PCAP Network Forensics: `psexec-hunt.pcapng`) | 
| **Category** | Network Forensics, Lateral Movement & Remote Service Execution | 
| **Affected Environment** | Internal Subnet: `10.0.0.0/24` (Hosts: `10.0.0.130`, `SALES-PC`, `MARKETING-PC`) | 

## 1. Executive Summary

Security operations identified anomalous Server Message Block (SMB2) traffic across the internal corporate subnet (`10.0.0.0/24`), indicative of unauthorized lateral movement. A packet-level forensic investigation of the network capture (`psexec-hunt.pcapng`, comprising `40,294` packets) was performed in **Wireshark** to identify the breached host, compromised credentials, abused administrative shares, and all pivoted endpoints.

The investigation confirmed that the threat actor abused **Sysinternals PsExec** from an initial foothold at **`10.0.0.130`** to move laterally across the environment:

1. **Initial Foothold:** The attacker operated from host **`10.0.0.130`** (`HR-PC`), generating `99.37%` of all packets in the capture.

2. **First Lateral Movement (`SALES-PC`):** Using compromised credentials for user **`ssales`**, the attacker authenticated over SMB2 to **`10.0.0.133`** (**`SALES-PC`**).

3. **Service Installation & IPC:** The attacker mapped the **`IPC$`** share for named-pipe communication and the **`ADMIN$`** administrative share to upload and execute the PsExec service binary (**`PSEXESVC.exe`**).

4. **Second Lateral Movement (`MARKETING-PC`):** The attacker also pivoted from **`10.0.0.130`** to a second workstation at **`10.0.0.131`** (**`MARKETING-PC`**), staging `PSEXESVC.exe` and encryption key artifacts (`PSEXEC-HR-PC-8FF87B23.key`).

## 2. Network Traffic Investigation & Technical Analysis

### 2.1. Identification of the Attacker's Initial Foothold (`10.0.0.130`)

To establish a baseline of active hosts and identify the primary source of anomalous traffic, Wireshark's IPv4 Statistics (`Statistics -> IPv4 Statistics -> All Addresses`) were analyzed.

* **Telemetry Distribution:**

  * **`10.0.0.130`:** `40,039` packets (`99.37%` of total traffic)

  * **`10.0.0.133`:** `38,284` packets (`95.01%`)

  * **`10.0.0.131`:** `1,768` packets (`4.39%`)

* **Findings:**

  * Correlating the statistical distribution with the SMB2 session initiations confirmed that **`10.0.0.130`** (MAC: `00:0c:29:06:cc:75`, identified in key artifacts as `HR-PC`) served as the attacker's initial entry point and staging machine.

<img width="1854" height="1050" alt="obraz" src="https://github.com/user-attachments/assets/e1833c1f-ccd8-41a9-8bee-91d363e1f908" />


### 2.2. First Pivot Target Identification (`SALES-PC`)

Filtering for SMB2 traffic originating from the attacker's host (`10.0.0.130`) exposed an active SMB2 negotiation and session setup sequence with destination IP **`10.0.0.133`**.

* **Wireshark Display Filter:**

  ```
  ip.addr == 10.0.0.130 and smb2
  ```

* **Findings:**

  * In Frame `131` (`2023-10-11 09:42:08.078667 UTC`), host `10.0.0.133` (MAC: `00:0c:29:59:23:50`) responded with an SMB2 `Session Setup Response` (`STATUS_MORE_PROCESSING_REQUIRED`, `NTLMSSP_CHALLENGE`).

  * Inspecting the `NTLMSSP_CHALLENGE` attributes (`ntlmssp.challenge.target_name`) revealed the target machine's hostname: **`SALES-PC`** (OS Build `10.0.19041`).

<img width="1854" height="1050" alt="obraz" src="https://github.com/user-attachments/assets/11e029a0-d720-4645-b305-2ae72abd8457" />


### 2.3. Compromised Account Identification (`ssales`)

Immediately following the `NTLMSSP_CHALLENGE` in Frame `131`, the attacker completed the NTLM challenge-response authentication in Frame `132`.

* **Wireshark Display Filter:**

  ```
  ip.addr == 10.0.0.130 and smb2
  ```

* **Findings:**

  * At **`2023-10-11 09:42:08.079115 UTC`** (Frame `132`), `10.0.0.130` sent an SMB2 `Session Setup Request, NTLMSSP_AUTH` to `10.0.0.133` (`SALES-PC`).

  * **Authenticated Username:** `\ssales` (**`ssales`**).

  * Frame `133` confirmed a successful login (`Session Setup Response`).

<img width="1854" height="1050" alt="obraz" src="https://github.com/user-attachments/assets/3b075423-ab39-438e-95d2-f7d46d6251c3" />


### 2.4. Remote Service Executable Staging (`psexesvc.exe`)

Once authenticated as `ssales` on `SALES-PC`, the attacker proceeded to drop an executable binary onto the target system to establish remote command execution.

* **Wireshark Display Filter:**

  ```
  ip.addr == 10.0.0.130 and smb2
  ```

* **Findings:**

  * In Frame `144` (`2023-10-11 09:42:08.085179 UTC`), `10.0.0.130` issued an SMB2 `Create Request` (`Disposition: Overwrite If`, `Access Mask: 0x00120196` – Read/Write) to `10.0.0.133`.

  * **Created File Name:** **`PSEXESVC.exe`** (`psexesvc.exe`).

  * Subsequent frames (`192`, `236`, `287`, etc.) show 64 KB (`Len: 65536`) SMB2 `Write Request` chunks transferring the `PSEXESVC.exe` binary over the network.

<img width="1854" height="1050" alt="obraz" src="https://github.com/user-attachments/assets/e002a4db-f03c-4f03-8bc6-821055571f78" />


### 2.5. Administrative Share Abused for Service Installation (`admin$`)

To install and execute `PSEXESVC.exe` as a Windows system service, PsExec must write the binary directly into the target's `%SystemRoot%\System32` directory via a hidden administrative share.

* **Wireshark Display Filter:**

  ```
  ip.addr == 10.0.0.130 and smb2
  ```

* **Findings:**

  * Prior to creating `PSEXESVC.exe`, Frame `138` (`2023-10-11 09:42:08.082995 UTC`) shows a `Tree Connect Request` from `10.0.0.130` to `\\10.0.0.133\ADMIN$`.

  * Frame `139` confirms `Tree Connect Response` (`Share Type: Physical disk (0x01)`), verifying that **`ADMIN$`** (`admin$`) was used to stage the service binary.

<img width="1854" height="1050" alt="obraz" src="https://github.com/user-attachments/assets/c63d920d-04f7-4841-98ee-be4321526b27" />


### 2.6. Inter-Process Communication Share Identification (`ipc$`)

In addition to transferring the binary via `ADMIN$`, PsExec relies on Windows Named Pipes over SMB to control the remote Service Control Manager (`svcctl`) and redirect standard input/output (`stdin`/`stdout`/`stderr`).

* **Wireshark Display Filter:**

  ```
  ip.addr == 10.0.0.130 and smb2
  ```

* **Findings:**

  * In Frame `134` (`2023-10-11 09:42:08.081275 UTC`), immediately after authentication, `10.0.0.130` sent a `Tree Connect Request` for **`\\10.0.0.133\IPC$`** (`ipc$`).

  * Frame `135` confirmed the connection to `IPC$`, enabling remote RPC and named pipe communication between the two machines.

<img width="1854" height="1050" alt="obraz" src="https://github.com/user-attachments/assets/512d5385-21af-445f-8e16-c9c0b3b008f1" />


### 2.7. Second Lateral Movement Target Identification (`marketing-pc`)

To determine whether the attacker pivoted to any other hosts from `10.0.0.130`, SMB2 traffic between `10.0.0.130` and `10.0.0.133` (`SALES-PC`) was excluded from the view.

* **Wireshark Display Filter:**

  ```
  ip.addr == 10.0.0.130 and smb2 and ip.addr != 10.0.0.133
  ```

* **Findings:**

  * The filter isolated `214` SMB2 packets exchanged between `10.0.0.130` and **`10.0.0.131`** around `2023-10-11 09:40:19` – `09:40:22 UTC`.

  * Inspecting the `NTLMSSP_CHALLENGE` packet in Frame `38514` (`09:40:19.913313 UTC`) and Frame `38534` (`09:40:21.975614 UTC`) revealed the `Target Name`: **`MARKETING-PC`** (`marketing-pc`).

  * Following authentication, the attacker connected to `\\10.0.0.131\ADMIN$` and `\\10.0.0.131\IPC$`, uploaded `PSEXESVC.exe`, and generated `PSEXEC-HR-PC-8FF87B23.key`.

<img width="1854" height="1050" alt="obraz" src="https://github.com/user-attachments/assets/95748043-ddb1-4dd2-8045-0d643c835342" />


## 3. Attack Timeline (October 11, 2023)

| Timestamp (UTC) | Source IP | Destination IP | Protocol / Frame | Activity Description | 
| ----- | ----- | ----- | ----- | ----- | 
| `2023-10-11 09:40:19.91` | `10.0.0.130` | `10.0.0.131` | `SMB2` (`#38514-38536`) | Attacker initiates SMB2 authentication toward `MARKETING-PC` (`10.0.0.131`). | 
| `2023-10-11 09:40:21.97` | `10.0.0.130` | `10.0.0.131` | `SMB2` (`#38538-38774`) | Attacker mounts `ADMIN$` and `IPC$` on `MARKETING-PC`, drops `PSEXESVC.exe` and `PSEXEC-HR-PC-8FF87B23.key`. | 
| `2023-10-11 09:42:08.07` | `10.0.0.130` | `10.0.0.133` | `SMB2` (`#130-133`) | Attacker authenticates to `SALES-PC` (`10.0.0.133`) using compromised account `ssales`. | 
| `2023-10-11 09:42:08.081` | `10.0.0.130` | `10.0.0.133` | `SMB2` (`#134-135`) | Attacker connects to `\\10.0.0.133\IPC$` for inter-process communication. | 
| `2023-10-11 09:42:08.082` | `10.0.0.130` | `10.0.0.133` | `SMB2` (`#138-139`) | Attacker connects to `\\10.0.0.133\ADMIN$` to stage the service binary. | 
| `2023-10-11 09:42:08.085` | `10.0.0.130` | `10.0.0.133` | `SMB2` (`#144-287+`) | Attacker creates and writes `PSEXESVC.exe` onto `SALES-PC`. | 

## 4. Consolidated Indicators of Compromise (IoCs)

| Indicator Type | Value | Context | 
| ----- | ----- | ----- | 
| **breached IPv4 / Host** | `10.0.0.130` (`HR-PC` / `00:0c:29:06:cc:75`) | Compromised workstation used by the attacker to launch PsExec | 
| **Pivot Target 1** | `10.0.0.133` (`SALES-PC` / `00:0c:29:59:23:50`) | Workstation accessed via PsExec using `ssales` credentials | 
| **Pivot Target 2** | `10.0.0.131` (`MARKETING-PC` / `00:0c:29:64:0f:9e`) | Second workstation targeted by the attacker via PsExec | 
| **Compromised Account** | `ssales` | User account abused for SMB2 NTLMSSP authentication | 
| **Service Binary** | `PSEXESVC.exe` (`psexesvc.exe`) | PsExec remote service executable written to `ADMIN$` | 
| **Key Artifact** | `PSEXEC-HR-PC-8FF87B23.key` | PsExec session key file created on `MARKETING-PC` | 
| **Abused Shares** | `ADMIN$`, `IPC$` | Administrative shares used for binary staging and named-pipe RPC | 

## 5. Summary of Lab Questions & Answers

| Question | Answer | 
| ----- | ----- | 
| **Q1:** Identify the IP address of the machine from which the attacker initially gained access. | `10.0.0.130` | 
| **Q2:** Determine the machine's hostname to which the attacker first pivoted. | `SALES-PC` | 
| **Q3:** What is the username utilized by the attacker for authentication? | `ssales` | 
| **Q4:** What's the name of the service executable the attacker set up on the target? | `psexesvc.exe` | 
| **Q5:** Which network share was used by PsExec to install the service on the target machine? | `admin$` | 
| **Q6:** Which network share did PsExec use for communication? | `ipc$` | 
| **Q7:** What is the hostname of the second machine the attacker targeted to pivot within our network? | `marketing-pc` | 

## 6. MITRE ATT&CK Mapping & Remediation

### MITRE ATT&CK Techniques

* **`T1021.002` – Remote Services: SMB/Windows Admin Shares:** Abusing `ADMIN$` and `IPC$` over SMB2 (TCP/445) to stage binaries and communicate with remote endpoints.

* **`T1569.002` – System Services: Service Execution:** Executing commands remotely via `PSEXESVC.exe` registered with the Windows Service Control Manager.

* **`T1078` – Valid Accounts:** Authenticating across the network using compromised credentials (`ssales`).

### Recommended Remediation Actions

1. **Host Isolation & Credential Reset:** Immediately isolate `10.0.0.130` (`HR-PC`), `10.0.0.133` (`SALES-PC`), and `10.0.0.131` (`MARKETING-PC`). Force a password reset for user `ssales` and revoke active sessions.

2. **Restrict Workstation-to-Workstation SMB:** Implement Windows Defender Firewall rules via Group Policy to block inbound TCP port `445` (SMB) and TCP port `135` (RPC) between peer workstations (`10.0.0.0/24`), permitting administrative SMB connections only from hardened Jump Hosts / PAWs.

3. **Artifact Eradication & Detection:** Remove residual `PSEXESVC.exe` binaries and `.key` files from `C:\Windows\`, and configure SIEM alerts for Windows Security Event ID `5140` / `5145` (access to `ADMIN$` / `PSEXESVC`) and System Event ID `7045` (new service installation of `PSEXESVC`).
