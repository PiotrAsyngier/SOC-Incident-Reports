# Incident Report: PoisonedCredentials – LLMNR/NBNS/mDNS Poisoning & SMB Relay / Lateral Movement

| Metadata | Details | 
| :--- | :--- | 
| **Date** | November 2026 | 
| **Analyst** | Piotr Asyngier | 
| **Tools Used** | Wireshark (PCAP Network Forensics: `PoisonedCredentials.pcap`) | 
| **Category** | Network Forensics, Name Resolution Poisoning & Credential Harvesting | 
| **Affected Environment** | Domain: `cybercactus.local` (Subnet: `192.168.232.0/24`) | 

---

## 1. Executive Summary

Network monitoring flagged anomalous multicast/broadcast name resolution traffic and suspicious Server Message Block (SMB) authentication sessions within the `cybercactus.local` corporate LAN (`192.168.232.0/24`). A forensic analysis of the captured packet trace (`PoisonedCredentials.pcap`) was conducted in **Wireshark** to reconstruct the attack chain, identify the rogue host, and determine the scope of compromised user credentials and systems.

The investigation confirmed an active **Adversary-in-the-Middle (AitM) / Name Resolution Poisoning** attack (commonly executed via tools such as *Responder*):

1. **Initial Trigger (Mistyped Share):** A legitimate workstation (`192.168.232.162`) issued broadcast/multicast queries for a misspelled hostname: **`fileshaare`**.
2. **Name Resolution Poisoning:** A rogue machine at **`192.168.232.215`** poisoned **LLMNR**, **NBNS**, and **mDNS** responses, impersonating the requested resources (`fileshaare` and `prinetr`).
3. **Multi-Host Targeting:** In addition to `192.168.232.162`, a second workstation at **`192.168.232.176`** received spoofed name resolution responses from the attacker.
4. **Credential Compromise & Lateral Movement:** The attacker captured/relayed credentials belonging to domain user **`janesmith`** (`cybercactus.local\janesmith`) and authenticated via **SMB2** to the target workstation **`AccountingPC`** (`192.168.232.176`).

---

## 2. Network Traffic Investigation & Technical Analysis

### 2.1. Identification of Mistyped Name Resolution Query (`fileshaare`)

When a Windows host fails to resolve a hostname via standard DNS, it falls back to link-local multicast and broadcast protocols: **LLMNR** (UDP/5355), **mDNS** (UDP/5353), and **NBNS** (UDP/137). Filtering traffic originating from `192.168.232.162` revealed repeated fallback queries caused by a user typo when attempting to access a file share.

* **Wireshark Display Filter:**
  ```text
  ip.addr == 192.168.232.162
  ```
* **Findings:**
  * Starting at Frame `47` (`2023-10-31 20:27:45.444390 UTC`), host **`192.168.232.162`** sent NBNS (`255.255.255.255` / `192.168.232.255`), mDNS (`224.0.0.251`), and LLMNR (`224.0.0.252`) queries.
  * **Queried Hostname:** **`fileshaare`** (a typo of `fileshare`).

<img width="1854" height="967" alt="obraz" src="https://github.com/user-attachments/assets/8c111609-d978-40c4-bacb-11a120c36bda" />



---

### 2.2. Identification of the Rogue Poisoning Host (`192.168.232.215`)

Because LLMNR, NBNS, and mDNS lack cryptographic authentication, any host on the local broadcast domain can respond to multicast/broadcast queries and claim ownership of the requested hostname.

* **Wireshark Display Filter:**
  ```text
  ip.addr == 192.168.232.162
  ```
* **Findings:**
  * Immediately following the queries from `192.168.232.162` (`2023-10-31 20:27:45.449598 UTC`, Frames `50`–`56`), unicast responses (`Standard query response`) were sent back to the victim.
  * **Rogue Source IP:** **`192.168.232.215`** (MAC: `00:0c:29:44:ca:ef`).
  * The rogue host claimed that `fileshaare` resolved to **`192.168.232.215`**, forcing the victim machine to initiate TCP connections (ports `80` and `445`) directly to the attacker.

<img width="1854" height="967" alt="obraz" src="https://github.com/user-attachments/assets/f580bbd1-db8e-47d2-a2d5-00967da7bfcf" />



---

### 2.3. Scoping Additional Poisoned Victims (`192.168.232.176`)

To identify all endpoints impacted by the rogue Responder instance, traffic was filtered for all packets originating from or destined to the attacker's IP (`192.168.232.215`), focusing on NBNS, LLMNR, and mDNS responses.

* **Wireshark Display Filter:**
  ```text
  ip.addr == 192.168.232.215
  ```
* **Findings:**
  * At **`2023-10-31 20:30:40.289919 UTC`** (Frame `145`) and **`20:30:45.222126 UTC`** (Frames `166`–`172`), `192.168.232.215` sent poisoned NBNS, mDNS, and LLMNR responses (`prinetr` -> `192.168.232.215`) to a second host on the subnet.
  * **Second Victim IP:** **`192.168.232.176`** (MAC: `00:0c:29:9c:01:34`).
  * Notably, frames `148`–`158` also show NBNS `Registration response, Name is in conflict` involving `192.168.232.176` and legitimate server `192.168.232.140`.

<img width="1854" height="967" alt="obraz" src="https://github.com/user-attachments/assets/56001c46-8b81-4751-acec-0e43695154c0" />



---

### 2.4. Compromised User Account Identification (`janesmith`)

When victims connect to a rogue SMB/HTTP server spoofing a trusted hostname, Windows automatically attempts NTLMSSP authentication (`NTLMv2` challenge/response). If the attacker cracks the captured Net-NTLMv2 hash offline or relays it, they can authenticate as that user.

* **Wireshark Display Filter:**
  ```text
  ntlmssp.auth.username
  ```
* **Findings:**
  * In Frame `242` (`2023-10-31 20:33:09.120022 UTC`), the attacker machine (`192.168.232.215`) initiated an **SMB2 `Session Setup Request`** (`NTLMSSP_AUTH`) over TCP port `445` toward `192.168.232.176`.
  * **Authenticated User:** `cybercactus.local\janesmith` (Username: **`janesmith`**).

<img width="1854" height="967" alt="obraz" src="https://github.com/user-attachments/assets/8cff50e4-2d78-480d-a3c6-af454f574162" />



---

### 2.5. Target Hostname Identification via SMB NTLMSSP Challenge (`AccountingPC`)

To determine the exact hostname of the machine accessed by the attacker (`192.168.232.176`) via SMB, the `NTLMSSP_CHALLENGE` packet returned by the target server during the SMB2 negotiation was inspected.

* **Wireshark Display Filter:**
  ```text
  ntlmssp.challenge.target_info
  ```
* **Findings:**
  * Inspecting the `SMB2 Session Setup Response` (`NTLMSSP_CHALLENGE`, message type `0x00000002`) from `192.168.232.176` to `192.168.232.215` revealed the `Target Info` attributes:
    * **NetBIOS Domain Name:** `CYBERCACTUS`
    * **NetBIOS Computer Name:** **`ACCOUNTINGPC`** (`AccountingPC`)
    * **DNS Domain Name:** `cybercactus.local`
    * **DNS Computer Name:** `AccountingPC.cybercactus.local`

<img width="1854" height="967" alt="obraz" src="https://github.com/user-attachments/assets/9d653b45-21be-4f97-a390-a8340a5e91f9" />



---

## 3. Attack Timeline (October 31, 2023)

| Timestamp (UTC) | Source IP | Destination IP | Protocol / Frame | Activity Description | 
| :--- | :--- | :--- | :--- | :--- | 
| `2023-10-31 20:27:45.44` | `192.168.232.162` | `224.0.0.252` / `.251` | `NBNS` / `mDNS` / `LLMNR` (`#47-53`) | Victim `192.168.232.162` queries mistyped hostname `fileshaare`. | 
| `2023-10-31 20:27:45.45` | `192.168.232.215` | `192.168.232.162` | `NBNS` / `mDNS` / `LLMNR` (`#50-56`) | Rogue host `.215` poisons responses, resolving `fileshaare` to `192.168.232.215`. | 
| `2023-10-31 20:30:40.28` | `192.168.232.215` | `192.168.232.176` | `NBNS` (`#145`) | Rogue host `.215` sends poisoned NBNS response to second victim `192.168.232.176`. | 
| `2023-10-31 20:30:45.27` | `192.168.232.215` | `192.168.232.176` | `LLMNR` (`#171-172`) | Rogue host `.215` poisons LLMNR query for mistyped hostname `prinetr`. | 
| `2023-10-31 20:33:09.12` | `192.168.232.215` | `192.168.232.176` | `SMB2` (`#241-242`) | Attacker authenticates to `AccountingPC` (`.176`) via SMB2 using compromised account `janesmith`. | 

---

## 4. Consolidated Indicators of Compromise (IoCs)

| Indicator Type | Value | Context | 
| :--- | :--- | :--- | 
| **Rogue IPv4 / MAC** | `192.168.232.215` (`00:0c:29:44:ca:ef`) | Attacker machine performing LLMNR/NBNS/mDNS poisoning | 
| **Victim 1 IPv4 / MAC** | `192.168.232.162` (`00:0c:29:fa:cb:e9`) | Workstation querying mistyped share `fileshaare` | 
| **Victim 2 IPv4 / Host** | `192.168.232.176` (`AccountingPC.cybercactus.local`) | Workstation poisoned (`prinetr`) and accessed via SMB2 | 
| **Spoofed Hostnames** | `fileshaare`, `prinetr` | Mistyped hostnames poisoned by the rogue entity | 
| **Compromised Account** | `janesmith` (`cybercactus.local\janesmith`) | Domain user whose credentials were used for SMB lateral movement | 

---

## 5. Summary of Lab Questions & Answers

| Question | Answer | 
| :--- | :--- | 
| **Q1:** Can you identify the specific mistyped query made by the machine with the IP address `192.168.232.162`? | `fileshaare` | 
| **Q2:** What is the IP address of the machine acting as the rogue entity? | `192.168.232.215` | 
| **Q3:** What is the IP address of the second machine that received poisoned responses from the rogue machine? | `192.168.232.176` | 
| **Q4:** What is the username of the account that the attacker compromised? | `janesmith` | 
| **Q5:** What is the hostname of the machine that the attacker accessed via SMB? | `AccountingPC` | 

---

## 6. MITRE ATT&CK Mapping & Remediation

### MITRE ATT&CK Techniques

* **`T1557.001` – Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay:** Spoofing authoritative responses to LLMNR (`UDP/5355`), NBNS (`UDP/137`), and mDNS (`UDP/5353`) queries (`fileshaare`, `prinetr`) to intercept NTLMSSP authentication traffic.
* **`T1078.002` – Valid Accounts: Domain Accounts:** Using compromised domain credentials (`cybercactus.local\janesmith`) to authenticate to internal resources.
* **`T1021.002` – Remote Services: SMB/Windows Admin Shares:** Lateral movement from `192.168.232.215` to `AccountingPC` (`192.168.232.176`) over TCP port `445` (SMB2).

### Recommended Remediation Actions

1. **Disable Legacy Name Resolution Protocols:**
   * Disable **LLMNR** via Group Policy (`Computer Configuration -> Administrative Templates -> Network -> DNS Client -> Turn off multicast name resolution = Enabled`).
   * Disable **NetBIOS over TCP/IP (NBT-NS)** across all network adapters via DHCP options or Group Policy startup scripts.
2. **Enforce SMB Signing:** Require SMB packet signing on both workstations and servers via Group Policy (`Microsoft network server: Digitally sign communications (always) = Enabled`) to prevent NTLM relay attacks.
3. **Credential Reset & Host Isolation:** Isolate rogue host `192.168.232.215`, audit `AccountingPC` (`192.168.232.176`) for post-exploitation artifacts, and force an immediate password reset for `janesmith` (enforcing strong password complexity to resist offline NTLMv2 cracking).
