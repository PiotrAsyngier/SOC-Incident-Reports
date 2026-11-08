# 🕵️‍♂️ CyberDefenders: JetBrains — Network & Web Attack Forensics Write-up (Wireshark)

[![Platform](https://img.shields.io/badge/Platform-CyberDefenders-blue)](https://cyberdefenders.org/)
[![Category](https://img.shields.io/badge/Category-Network%20Forensics-informational)](#)
[![CVE](https://img.shields.io/badge/CVE-2024--27198-critical)](https://www.rapid7.com/blog/post/ra-cve-2024-27198-analysis/)
[![Tool](https://img.shields.io/badge/Tool-Wireshark-1679A7)](#)

## 📌 Lab Overview
This write-up documents the network forensics investigation of the **JetBrains** challenge on CyberDefenders. By analyzing the captured network traffic (`Capture.pcap`) in **Wireshark**, we reconstruct a complete intrusion chain against a vulnerable **JetBrains TeamCity** CI/CD server—from initial authentication bypass (**CVE-2024-27198**) and rogue administrator creation to JSP web shell deployment, credential file tampering (**MITRE T1565.001**), and privileged Docker container escape.

---

### Q1: Identifying the attacker's IP address helps trace the source and stop further attacks. What is the attacker's IP address?
We start by hunting for anomalous HTTP state-changing requests, such as unauthorized configuration changes, file/plugin uploads, or web shell command executions. Applying the following display filter isolates all HTTP `POST` requests:

    http.request.method == "POST"

Scrolling through the filtered results quickly reveals a series of suspicious `POST` requests targeting `/admin/...` and `/plugins/NSt8bHTg/NSt8bHTg.jsp` on the internal server (`172.31.25.119`), all originating from a single external IPv4 address:

<img width="1855" height="964" alt="obraz" src="https://github.com/user-attachments/assets/9abbc8ef-3dcf-458b-a71a-5a3e543db056" />


* **Answer:** `23.158.56.196`

---

### Q2: To identify potential vulnerability exploitation, what version of our web server service is running?
To determine how the attacker gained initial access and which server version was running, we filter for all HTTP traffic involving the attacker's IP address:

    http and ip.addr == 23.158.56.196

In packet `24701`, we spot a suspicious `GET` request targeting `/hax?jsp=/app/rest/server;.jsp`. Right-clicking this packet and selecting **Follow -> HTTP Stream** (`tcp.stream eq 364`) reveals the XML response returned by the **JetBrains TeamCity** server, which explicitly discloses the running software version inside the `<server version="2023.11.3 (build 147512)" ...>` tag:

<img width="1855" height="964" alt="obraz" src="https://github.com/user-attachments/assets/55f402fe-d594-4cd6-9946-4b5726ce799f" />

<img width="1855" height="964" alt="obraz" src="https://github.com/user-attachments/assets/58db1798-1e14-40ee-9f30-26390d540fa8" />


* **Answer:** `2023.11.3`

---

### Q3: After identifying the version of our web server service, what CVE number corresponds to the vulnerability the attacker exploited?
In the previous step, we observed the attacker requesting URI paths formatted as `/hax?jsp=/app/rest/server;.jsp` against **JetBrains TeamCity 2023.11.3**. Researching this specific URI pattern and version leads directly to **CVE-2024-27198** (CVSS 9.8 Critical)—an authentication bypass vulnerability in the web component of TeamCity (`jetbrains.buildServer.controllers.BaseController`) that allows an unauthenticated remote attacker to bypass authentication checks on REST API endpoints by appending `;.jsp` to the URL:

* **Reference:** https://www.rapid7.com/blog/post/ra-cve-2024-27198-analysis/

<img width="1855" height="964" alt="obraz" src="https://github.com/user-attachments/assets/fddc53c2-ba2b-4b72-a118-41ba7385a8be" />


* **Answer:** `CVE-2024-27198`

---

### Q4: What credentials did the attacker successfully use for Basic Auth against the TeamCity server?
Continuing our analysis of HTTP stream `364` (`tcp.stream eq 364`, packet `24711`), right after enumerating the server version, the attacker sends an unauthenticated `POST /hax?jsp=/app/rest/users;.jsp` request with an `application/json` payload to create a new user assigned the `SYSTEM_ADMIN` role:

    {"username": "c91oyemw", "password": "CL5vzdwLuK", "email": "c91oyemw@example.com", "roles": {"role": [{"roleId": "SYSTEM_ADMIN", "scope": "g"}]}}

The server responds with `HTTP/1.1 200`, confirming the creation of the administrative account, which the attacker subsequently uses for authentication:

<img width="1855" height="964" alt="obraz" src="https://github.com/user-attachments/assets/a18daa3f-8d6d-491e-bcc2-2e571c17c052" />


* **Answer:** `c91oyemw:CL5vzdwLuK`

---

### Q5: The attacker uploaded a webshell to ensure his access to the system. What is the name of the file that the attacker uploaded?
Scrolling further down in HTTP stream `364` (`tcp.stream eq 364`), we see the attacker leveraging their newly acquired administrative privileges (and bearer token) to send a `POST /admin/pluginUpload.html HTTP/1.1` request (`Content-Type: multipart/form-data`).

Inspecting the MIME form-data headers (`Content-Disposition: form-data; name="fileName"` and `filename="..."`) reveals the exact archive name uploaded as a malicious TeamCity plugin, which unpacks a JSP web shell (`buildServerResources/NSt8bHTg.jsp` utilizing Java's `ProcessBuilder` to execute OS commands passed via the `cmd` parameter):

<img width="1855" height="964" alt="obraz" src="https://github.com/user-attachments/assets/c491a49b-a335-41de-b963-b2e6c75d675a" />


* **Answer:** `NSt8bHTg.zip`

---

### Q6: When did the attacker execute their first command via the web shell?
To pinpoint the exact timestamp of the first command execution through the newly uploaded JSP web shell, we filter for `POST` requests sent by the attacker:

    http.request.method == "POST" and ip.src == 23.158.56.196

With Wireshark's time display format set to **UTC Date and Time of Day** (*View -> Time Display Format -> UTC Date and Time of Day*), we locate the very first `POST` request targeting `/plugins/NSt8bHTg/NSt8bHTg.jsp` in packet `25572`, which occurred on **2024-06-30** at **08:03** UTC (`08:03:54`):

<img width="1855" height="964" alt="obraz" src="https://github.com/user-attachments/assets/488c6a8f-d714-4467-b76c-6418e8076d84" />


* **Answer:** `2024-06-30 08:03`

---

### Q7: The attacker tampered with a text file that contained the credentials of the admin user of the webserver. What new username and password did the attacker write in the file?
While reviewing the attacker's web shell `POST` requests to `/plugins/NSt8bHTg/NSt8bHTg.jsp`, we spot packet `31123` overwriting `/root/Creds.txt` via `echo`, followed immediately by packet `31134` in TCP stream `546`:

    tcp.stream eq 546

Following the HTTP stream for `tcp.stream eq 546` shows the attacker executing `cmd=cat+/root/Creds.txt`, and the HTTP `200` response body outputs the newly written contents of the file (`username:a1l4m` and `password:youarecompromised`):

<img width="1855" height="964" alt="obraz" src="https://github.com/user-attachments/assets/0544f74e-00ff-48c8-a5c6-3c8c3c94e55a" />


* **Answer:** `a1l4m:youarecompromised`

---

### Q8: Q7 showed the attacker writing false credentials into `Creds.txt`. Which MITRE ATT&CK sub-technique (Data Manipulation family) describes that specific file-write action?
Mapping this activity to the **MITRE ATT&CK** framework under the **Impact** tactic (`TA0040`) and **Data Manipulation** parent technique (`T1565`): modifying or overwriting existing files on disk (`Creds.txt`) to alter data at rest corresponds to sub-technique **T1565.001 (Stored Data Manipulation)**:

<img width="727" height="805" alt="obraz" src="https://github.com/user-attachments/assets/df9d5538-fbc5-46f3-a990-d2fc8e2e0b06" />


* **Answer:** `T1565.001`

---

### Q9: Immediately after gaining a shell, the attacker executed a docker command that mounted the host filesystem and chrooted into it — providing full host access. What was that exact command? (Do NOT include the `cmd=` prefix seen in the HTTP body.)
To locate the container escape command executed via the web shell, we filter for HTTP requests from the attacker containing both `cmd` and `chroot`:

    ip.src == 23.158.56.196 and http contains "cmd" and http contains "chroot"

This isolates packet `32113`. Opening **Follow -> HTTP Stream** (`tcp.stream eq 601`) reveals the URL-encoded payload sent in the HTTP request body:

    cmd=docker+run+--rm+-it+-v+/:/host+ubuntu+chroot+/host

Removing the `cmd=` prefix and replacing the URL-encoded `+` spaces gives us the exact command used to mount the host root filesystem (`/`) to `/host` inside an Ubuntu container and `chroot` into it:

<img width="1854" height="963" alt="obraz" src="https://github.com/user-attachments/assets/495f94af-bf10-429b-8041-3c3e9b246d90" />
<img width="1854" height="963" alt="obraz" src="https://github.com/user-attachments/assets/d7d323cc-8a70-4bfe-b493-9a6c31949e63" />


* **Answer:** `docker run --rm -it -v /:/host ubuntu chroot /host`
