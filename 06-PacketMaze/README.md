# 🕵️‍♂️ CyberDefenders: PacketMaze — Network Forensics Write-up (Wireshark)

[![Platform](https://img.shields.io/badge/Platform-CyberDefenders-blue)](https://cyberdefenders.org/blueteam-ctf-challenges/packetmaze/)
[![Category](https://img.shields.io/badge/Category-Network%20Forensics-informational)](#)
[![Tool](https://img.shields.io/badge/Tool-Wireshark-1679A7)](#)

## 📌 Lab Overview & Setup
This write-up documents the network forensics investigation of the **PacketMaze** challenge from [CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/packetmaze/).

To begin the analysis, we download the challenge archive, extract it using the standard password (`cyberdefenders.org`), and load the capture file (`UNODC-GPC-001-003-JohnDoe-NetworkCapture-2021-04-29.pcapng`) into **Wireshark**.

---

### Q1: What is the FTP password?
Because standard **FTP (File Transfer Protocol)** transmits authentication credentials in cleartext, we can quickly isolate all FTP control traffic by applying the `ftp` display filter in Wireshark:

    ftp

Inspecting the authentication sequence (`USER` and `PASS` requests) reveals the cleartext password in packet `500`:

<img width="1855" height="1045" alt="obraz" src="https://github.com/user-attachments/assets/e266a585-baef-452c-8731-67639e840787" />


* **Answer:** `AfricaCTF2021`

---

### Q2: What is the IPv6 address of the DNS server used by `192.168.1.26`?
1. First, we filter for DNS queries originating from `192.168.1.26` to identify the DNS server's IPv4 address and its Layer 2 hardware (MAC) address:

    ip.src == 192.168.1.26 && dns

This narrows the view down to 6 packets sent to the DNS server at `192.168.1.10`, whose destination MAC address in the Ethernet II header is `ca:0b:ad:ad:20:ba`:

<img width="1855" height="1045" alt="obraz" src="https://github.com/user-attachments/assets/bd9c3a2a-6a1f-4be2-afb2-d3c47d611a70" />


2. Next, we pivot using the DNS server's MAC address alongside the `ipv6` protocol filter to correlate the host across Layer 2 and find its IPv6 address:

    eth.addr == ca:0b:ad:ad:20:ba && ipv6

<img width="1855" height="1045" alt="obraz" src="https://github.com/user-attachments/assets/7187f0dc-75b9-4fba-a73d-a0457cb09ef6" />


* **Answer:** `fe80::c80b:adff:feaa:1db7`

---

### Q3: What domain is the user looking up in packet `15174`?
We jump directly to packet `15174` using `Ctrl+G` (or by applying the filter `frame.number == 15174`) and inspect the **Info** column / DNS query details:

<img width="1855" height="1045" alt="obraz" src="https://github.com/user-attachments/assets/51ecb9f2-4dbb-4f8c-b06c-632b2320a132" />


* **Answer:** `www.7-zip.org`

---

### Q4: How many UDP packets were sent from `192.168.1.26` to `24.39.217.246`?
We construct a display filter specifying the source IP, destination IP, and transport layer protocol (`udp`):

    ip.src == 192.168.1.26 && ip.dst == 24.39.217.246 && udp

Looking at the bottom status bar in Wireshark (*Displayed*), we can read the exact number of matching packets:

<img width="1855" height="1045" alt="obraz" src="https://github.com/user-attachments/assets/59ed4bc6-7130-47ec-9ab8-26b63d55273a" />


* **Answer:** `10`

---

### Q5: What is the MAC address of the system under investigation in the PCAP file?
Since the host under investigation uses the IPv4 address `192.168.1.26`, we filter for packets originating from this IP:

    ip.src == 192.168.1.26

Selecting any matching frame and expanding the **Ethernet II** layer reveals the source hardware (MAC) address:

<img width="1855" height="1045" alt="obraz" src="https://github.com/user-attachments/assets/b036fd73-4bda-479e-9477-a145afb78e05" />


* **Answer:** `c8:09:a8:57:47:93`

---

### Q6: What was the camera model name used to take picture `20210429_152157.jpg`?
1. To extract files transferred over FTP, we navigate to **File -> Export Objects -> FTP-DATA** and save `20210429_152157.jpg` to disk:

<img width="1855" height="1045" alt="obraz" src="https://github.com/user-attachments/assets/b54ff9ae-7b5a-4924-907e-de8e4696b29f" />


2. Once saved, we inspect the image's **EXIF metadata** (via **Properties -> Image Properties** or `exiftool`), which lists both the camera manufacturer (`LG Electronics`) and the exact model name:

<img width="478" height="594" alt="obraz" src="https://github.com/user-attachments/assets/def3a20e-623f-4ea7-a32a-0f02b2c23158" />


* **Answer:** `LM-Q725K`

---

### Q7: What is the ephemeral public key provided by the server during the TLS handshake in the session with the session ID: `da4a0000342e4b73459d7360b4bea971cc303ac18d29b99067e46d16cc07f4ff`?
We isolate the specific TLS session using the `tls.handshake.session_id` filter:

    tls.handshake.session_id == da4a0000342e4b73459d7360b4bea971cc303ac18d29b99067e46d16cc07f4ff

Next, we inspect packet `28913` (`Server Hello, Certificate, Server Key Exchange, Server Hello Done`) and expand:
**Transport Layer Security -> TLSv1.2 Record Layer -> Handshake Protocol: Server Key Exchange -> EC Diffie-Hellman Server Params -> Pubkey**:

<img width="1857" height="1050" alt="obraz" src="https://github.com/user-attachments/assets/d325ec96-1aa6-407c-a4d6-969c533d2009" />


* **Answer:** `04edcc123af7b13e90ce101a31c2f996f471a7c8f48a1b81d765085f548059a550f3f4f62ca1f0e8f74d727053074a37bceb2cbdc7ce2a8994dcd76dd6834eefc5438c3b6da929321f3a1366bd14c877cc83e5d0731b7f80a6b80916efd4a23a4d`

---

### Q8: What is the first `TLS 1.3` client random that was used to establish a connection with `protonmail.com`?
We search for packets containing the string `protonmail.com` (or filter by SNI: `tls.handshake.extensions_server_name contains "protonmail.com"`).

The first two matches use TLS 1.2, whereas the third match (packet `17992`) negotiates **TLS 1.3**. Expanding **Transport Layer Security -> Handshake Protocol: Client Hello -> Random** reveals the 32-byte client random value:

<img width="1857" height="1050" alt="obraz" src="https://github.com/user-attachments/assets/65509636-fe58-4754-86ce-1458a646b67c" />


* **Answer:** `24e92513b97a0348f733d16996929a79be21b0b1400cd7e2862a732ce7775b70`

---

### Q9: Which country is the manufacturer of the `FTP server’s MAC` address registered in?
1. Filtering for `ftp` traffic allows us to identify the FTP server (`192.168.1.20`) by looking at the source of the FTP response packets.
2. Expanding the **Ethernet II** header of a server response packet shows the source MAC address: `08:00:27:a6:1f:86`.
3. The first three bytes (`08:00:27`) represent the **OUI (Organizationally Unique Identifier)** assigned to the Network Interface Card (NIC) vendor. Looking up `08:00:27` in an OUI database resolves to **PCS Systemtechnik GmbH / Oracle Corporation** (VirtualBox virtual NIC), with Oracle headquartered in the **United States**:

<img width="1857" height="1050" alt="obraz" src="https://github.com/user-attachments/assets/2f542e6f-9c1f-4881-863e-68e8011f798f" />


* **Answer:** `United States`

---

### Q10: What time was a `non-standard folder` created on the FTP server on the 20th of April?
File transfers and directory listings in FTP are carried over a separate data channel (`ftp-data`). Because filtering for `ftp-data` alone returns thousands of packets, we refine the display filter to search for the string `"Apr 20"` inside the payload:

    ftp-data contains "Apr 20"

This isolates a single packet. Right-clicking it and selecting **Follow -> TCP Stream** displays the full directory listing (`ls -la` output), where we can see a non-standard directory named `ftp` (owned by `65534:65534`) created on `Apr 20` at `17:53`:

<img width="1857" height="1050" alt="obraz" src="https://github.com/user-attachments/assets/b797344e-7877-44ba-80c3-d3b96339f395" />


* **Answer:** `17:53`

---

### Q11: What URL was visited by the user and connected to the IP address `104.21.89.171`?
To identify the domain requested during the TLS handshake with `104.21.89.171`, we filter for **TLS Client Hello** packets (`tls.handshake.type == 1`) sent to that destination IP:

    ip.dst == 104.21.89.171 && tls.handshake.type == 1

In packet `28268`, we expand **Transport Layer Security -> Handshake Protocol: Client Hello -> Extension: server_name (SNI)**, which reveals the target hostname `dfir.science` (alongside the HTTP protocol indicators in the payload/ALPN extension):

<img width="1857" height="1050" alt="obraz" src="https://github.com/user-attachments/assets/d083648d-0e1b-491b-bcb9-866606309e98" />


* **Answer:** `[http://dfir.science/](http://dfir.science/)`
