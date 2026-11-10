# Incident Report: AWSRaid – AWS CloudTrail Triage, S3 Exfiltration & IAM Privilege Escalation

| Metadata | Details |
| :--- | :--- |
| **Date** | November 2026 |
| **Analyst** | Piotr Asyngier |
| **SIEM / Tools Used** | Splunk Enterprise (AWS CloudTrail Telemetry) |
| **Category** | Cloud Incident Response, S3 Data Exposure & IAM Persistence |
| **Affected Environment** | AWS Account ID: `141573560337` (Region: `us-east-1`) |

---

## 1. Executive Summary
Security monitoring alerted on anomalous API calls and unauthorized configuration changes within the organization's Amazon Web Services (AWS) infrastructure (`Account ID: 141573560337`). A retrospective investigation of **AWS CloudTrail** logs (`index=cloudtrail`) ingested into **Splunk** from November 2, 2023, was conducted to determine the initial entry point, scope the data exposure, and identify any persistence mechanisms established by the threat actor.

The investigation uncovered a multi-stage cloud compromise originating from external IP address **`185.199.110.153`**:
1. **Initial Access:** Compromise of the IAM user account **`helpdesk.luke`** via an AWS Management Console login from a Linux host.
2. **Collection & Exfiltration:** Reconnaissance and unauthorized access (`GetObject`) to sensitive S3 buckets, including intellectual property (`CAD Design.dwg`) stored in **`product-designs-repository31183937`**.
3. **Defense Evasion / Exposure:** Modification of S3 Block Public Access settings (`DeleteBucketPublicAccessBlock`) and Access Control Lists (`PutBucketAcl`) on the **`backup-and-restore98825501`** bucket, exposing backups publicly.
4. **Persistence & Privilege Escalation:** Creation of a rogue IAM user account (**`marketing.mark`**) and immediate assignment to the **`admins`** IAM group (`AddUserToGroup`).

---

## 2. SIEM Investigation & Technical Analysis

### 2.1. Initial Compromise & Entry Point Identification (`helpdesk.luke`)
To identify the compromised account used as the initial entry point, CloudTrail authentication events (`AwsConsoleSignIn`) were queried in Splunk.

* **SPL Query:**
  ```spl
  index=cloudtrail eventType=AwsConsoleSignIn
  ```
* **Findings:**
  * At **`2023-11-02T09:44:48Z`**, a successful console sign-in (`ConsoleLogin`) was recorded for IAM user **`helpdesk.luke`** (`arn:aws:iam::141573560337:user/helpdesk.luke`).
  * **Source IP:** `185.199.110.153`
  * **User Agent:** `Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0`

<img width="1854" height="963" alt="obraz" src="https://github.com/user-attachments/assets/92b6b05b-dab5-4b31-8f5e-19884f164d3c" />


<img width="1854" height="963" alt="obraz" src="https://github.com/user-attachments/assets/41a87ccc-eb64-42ea-9230-4f06e7dfe2e5" />


---

### 2.2. S3 Reconnaissance & First Object Access (`2023-11-02 09:55`)
Following the initial console login, the investigation pivoted to S3 data events (`eventSource=s3.amazonaws.com`) associated with the compromised account `helpdesk.luke` to determine the attacker's motives and timeline.

* **SPL Query:**
  ```spl
  index=cloudtrail "userIdentity.userName"=helpdesk.luke eventSource="s3.amazonaws.com" eventName=GetObject
  ```
* **Findings:**
  * The attacker began enumerating and accessing S3 objects shortly after authentication.
  * The **first `GetObject` request** occurred at **`2023-11-02T09:55:02Z`** (`2023-11-02 09:55`).
  * **Target Bucket:** `company-templates68582623`
  * **Accessed Object:** `Company Presentation Template.pptx`

<img width="1856" height="965" alt="obraz" src="https://github.com/user-attachments/assets/29b4dafc-8d56-4a48-af00-a8d335b85266" />


---

### 2.3. Intellectual Property Theft – CAD Design Exposure (`product-designs-repository31183937`)
Further analysis of S3 data events focused on identifying high-value engineering files—specifically AutoCAD drawing files (`.dwg`)—accessed by the threat actor.

* **SPL Query:**
  ```spl
  index=cloudtrail "userIdentity.userName"=helpdesk.luke eventSource="s3.amazonaws.com" "*.dwg"
  ```
  *(Alternatively inspecting `requestParameters.key` across `GetObject` events)*
* **Findings:**
  * At **`2023-11-02T09:56:07Z`**, user `helpdesk.luke` executed a `GetObject` API call to download a proprietary CAD file.
  * **Bucket Name:** **`product-designs-repository31183937`**
  * **Object Key:** `CAD Design.dwg`
  * **Bucket ARN:** `arn:aws:s3:::product-designs-repository31183937`

<img width="1856" height="965" alt="obraz" src="https://github.com/user-attachments/assets/80116829-4f33-4455-a195-877d27624038" />


<img width="1856" height="922" alt="obraz" src="https://github.com/user-attachments/assets/ac63d60f-c2a7-47d6-a16c-56e9c8b1be11" />


---

### 2.4. Unauthorized S3 Configuration Modification (`backup-and-restore98825501`)
To assess whether the attacker weakened security controls or exposed data externally, S3 management events modifying bucket ACLs and public access blocks were analyzed.

* **SPL Query:**
  ```spl
  index=cloudtrail "userIdentity.userName"=helpdesk.luke eventSource="s3.amazonaws.com" (eventName=DeleteBucketPublicAccessBlock OR eventName=PutBucketAcl OR eventName=PutBucketPublicAccessBlock)
  ```
* **Findings:**
  * Between **`2023-11-02T09:57:42Z`** and **`2023-11-02T09:58:01Z`**, the attacker altered the security posture of the backup repository bucket: **`backup-and-restore98825501`**.
  * Specifically, at `09:57:42Z`, `PutBucketPublicAccessBlock` was modified to set `BlockPublicAcls: false`, `IgnorePublicAcls: false`, `BlockPublicPolicy: false`, and `RestrictPublicBuckets: false`.
  * At `09:58:01Z`, `PutBucketAcl` was invoked to grant `READ` permissions (`uri: http://acs.amazonaws.com/groups/global/AllUsers`), effectively making the **`backup-and-restore98825501`** bucket publicly accessible.

<img width="1856" height="965" alt="obraz" src="https://github.com/user-attachments/assets/53650940-d0af-439c-9e64-7e6d9773b471" />


<img width="1856" height="965" alt="obraz" src="https://github.com/user-attachments/assets/3847055b-7d31-4964-9e57-e35d6096a1c6" />


---

### 2.5. Persistence via Rogue IAM Account Creation (`marketing.mark`)
Attackers frequently provision new IAM identities to maintain access in the event the initially compromised credentials (`helpdesk.luke`) are rotated. CloudTrail IAM management events (`iam.amazonaws.com`) were queried for account creation activity.

* **SPL Query:**
  ```spl
  index=cloudtrail "userIdentity.userName"=helpdesk.luke eventSource="iam.amazonaws.com" eventName=CreateUser
  ```
* **Findings:**
  * At **`2023-11-02T09:59:33Z`**, `helpdesk.luke` executed the `CreateUser` API call via the AWS Management Console.
  * **Created Username:** **`marketing.mark`**
  * **Created User ARN:** `arn:aws:iam::141573560337:user/marketing.mark` (`userId: AIDASBSTE3VA6JAF2MOWY`)

<img width="1856" height="965" alt="obraz" src="https://github.com/user-attachments/assets/db9f614b-5a15-4474-bb82-0eccc99f3c84" />


<img width="1856" height="965" alt="obraz" src="https://github.com/user-attachments/assets/f01683de-8a57-45b3-823e-63bba81fab78" />


---

### 2.6. Privilege Escalation via IAM Group Assignment (`admins`)
Immediately following the creation of `marketing.mark`, telemetry was reviewed to determine what permissions or group memberships were attached to the newly created identity.

* **SPL Query:**
  ```spl
  index=cloudtrail "userIdentity.userName"=helpdesk.luke eventSource="iam.amazonaws.com" eventName=AddUserToGroup
  ```
* **Findings:**
  * At **`2023-11-02T09:59:33Z`** (within the same console workflow), `helpdesk.luke` invoked `AddUserToGroup`.
  * **Request Parameters:** `{"groupName": "admins", "userName": "marketing.mark"}`
  * By adding `marketing.mark` to the **`admins`** group, the attacker achieved full administrative persistence across the AWS account.

<img width="1856" height="965" alt="obraz" src="https://github.com/user-attachments/assets/8aaea2bd-87d9-41ce-8ed4-aedb45874dc1" />


<img width="1856" height="965" alt="obraz" src="https://github.com/user-attachments/assets/3583b618-ebda-40a7-95d9-ee0f1ed0e0dc" />


---

## 3. Attack Timeline (November 2, 2023)

| Timestamp (UTC) | Source IP | IAM User | AWS Service / API Call | Activity Description |
| :--- | :--- | :--- | :--- | :--- |
| `2023-11-02 09:44:48` | `185.199.110.153` | `helpdesk.luke` | `signin` / `ConsoleLogin` | Initial compromise: Attacker logs into AWS Management Console. |
| `2023-11-02 09:55:02` | `185.199.110.153` | `helpdesk.luke` | `s3` / `GetObject` | First S3 object accessed (`Company Presentation Template.pptx` in `company-templates68582623`). |
| `2023-11-02 09:56:07` | `185.199.110.153` | `helpdesk.luke` | `s3` / `GetObject` | Exfiltration of `CAD Design.dwg` from bucket `product-designs-repository31183937`. |
| `2023-11-02 09:57:42` | `185.199.110.153` | `helpdesk.luke` | `s3` / `PutBucketPublicAccessBlock` | Disabled Public Access Block protections on `backup-and-restore98825501`. |
| `2023-11-02 09:58:01` | `185.199.110.153` | `helpdesk.luke` | `s3` / `PutBucketAcl` | Modified bucket ACL on `backup-and-restore98825501` to allow public `AllUsers` read access. |
| `2023-11-02 09:59:33` | `185.199.110.153` | `helpdesk.luke` | `iam` / `CreateUser` | Created rogue IAM persistence account `marketing.mark`. |
| `2023-11-02 09:59:33` | `185.199.110.153` | `helpdesk.luke` | `iam` / `AddUserToGroup` | Escalated privileges by adding `marketing.mark` to the `admins` IAM group. |

---

## 4. Consolidated Indicators of Compromise (IoCs)

| Indicator Type | Value | Context |
| :--- | :--- | :--- |
| **IPv4 Address** | `185.199.110.153` | External attacker IP used across all malicious console/API sessions |
| **Compromised Account** | `helpdesk.luke` | Initial entry point IAM user (`arn:aws:iam::141573560337:user/helpdesk.luke`) |
| **Rogue IAM Account** | `marketing.mark` | Persistence account created by attacker (`AIDASBSTE3VA6JAF2MOWY`) |
| **Target IAM Group** | `admins` | Privileged group assigned to the rogue account |
| **S3 Bucket (IP Theft)** | `product-designs-repository31183937` | Bucket containing exfiltrated engineering file (`CAD Design.dwg`) |
| **S3 Bucket (Exposed)** | `backup-and-restore98825501` | Bucket reconfigured by attacker to allow public access |
| **User-Agent** | `Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0` | Attacker's browser fingerprint during AWS Console session |

---

## 5. Summary of Lab Questions & Answers

| Question | Answer |
| :--- | :--- |
| **Q1:** What is the username of the compromised user? | `helpdesk.luke` |
| **Q2:** What is the timestamp for the first access to an S3 object by the attacker? | `2023-11-02 09:55` |
| **Q3:** Among the S3 buckets accessed by the attacker, one contains a DWG file. What is the name of this bucket? | `product-designs-repository31183937` |
| **Q4:** What is the name of the S3 bucket whose configuration was changed to allow public access? | `backup-and-restore98825501` |
| **Q5:** What is the username of the account created by the attacker? | `marketing.mark` |
| **Q6:** What is the name of the group to which the account was added? | `admins` |

---

## 6. MITRE ATT&CK Mapping & Remediation

### MITRE ATT&CK Techniques (Cloud Matrix)
* **`T1078.004` – Valid Accounts: Cloud Accounts:** Initial access achieved using valid credentials belonging to IAM user `helpdesk.luke`.
* **`T1530` – Data from Cloud Storage:** Unauthorized retrieval (`GetObject`) of sensitive corporate files (`CAD Design.dwg`) from Amazon S3.
* **`T1562.008` – Impair Defenses: Disable or Modify Cloud Logs / Controls:** Disabling S3 Public Access Block settings (`PutBucketPublicAccessBlock`) and exposing `backup-and-restore98825501` via `PutBucketAcl`.
* **`T1136.003` – Create Account: Cloud Account:** Creation of the `marketing.mark` IAM user for persistence.
* **`T1098` – Account Manipulation:** Adding the newly created user to the `admins` group (`AddUserToGroup`) to gain administrative privileges.

### Recommended Remediation Actions
1. **Identity Containment:** Immediately delete or deactivate the rogue IAM user `marketing.mark` (`aws iam delete-user`), revoke all active sessions and access keys for `helpdesk.luke`, rotate credentials, and enforce Phishing-Resistant MFA across all IAM users.
2. **Principle of Least Privilege (PoLP):** Audit the permissions of `helpdesk.luke`. A helpdesk account should not possess `iam:CreateUser`, `iam:AddUserToGroup` (especially for the `admins` group), or `s3:PutBucketPublicAccessBlock` permissions.
3. **S3 Hardening:** Immediately restore the `BlockPublicAccess` configuration on `backup-and-restore98825501` and enable **Account-Level S3 Block Public Access** paired with an AWS Organizations Service Control Policy (SCP) to prevent any future bucket ACL exposures.
