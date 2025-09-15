# Windows 10 Workstation Vulnerable Lab Configuration Script v5
# WARNING: FOR ISOLATED LAB ENVIRONMENT ONLY - NEVER USE IN PRODUCTION
# This script intentionally creates security vulnerabilities and CTF flags for penetration testing practice

param(
    [string]$ServerName = "WIN-TIP7RVRBJ8E",
    [string]$NetworkPrinter = "192.168.1.230",
    [string]$CommonPassword = "Password123!",
    [switch]$GenerateFlagReport
)

Write-Host "==========================================" -ForegroundColor Red
Write-Host "VULNERABLE WORKSTATION CONFIGURATION v5" -ForegroundColor Red
Write-Host "FOR EDUCATIONAL PURPOSES ONLY" -ForegroundColor Red
Write-Host "NEVER USE IN PRODUCTION ENVIRONMENTS" -ForegroundColor Red
Write-Host "==========================================" -ForegroundColor Red
Write-Host ""
$confirm = Read-Host "Type 'VULNERABLE' to confirm this is for an isolated lab"
if ($confirm -ne "VULNERABLE") { exit }

# Initialize flag tracking
$global:FlagList = @()
$global:FlagCounter = 1

# Pokemon list for deterministic flag generation (different from server)
$PokemonList = @(
    "MEW", "RAICHU", "BLASTOISE", "VENUSAUR", "BUTTERFREE",
    "PIDGEOT", "FEAROW", "SANDSLASH", "NIDOQUEEN", "NIDOKING",
    "CLEFABLE", "NINETALES", "WIGGLYTUFF", "GOLBAT", "VILEPLUME",
    "PARASECT", "VENOMOTH", "DUGTRIO", "PERSIAN", "GOLDUCK",
    "PRIMEAPE", "GROWLITHE", "POLIWHIRL", "KADABRA", "MACHOKE",
    "WEEPINBELL", "TENTACRUEL", "GRAVELER", "RAPIDASH", "SLOWBRO",
    "MAGNETON", "DEWGONG", "GRIMER", "CLOYSTER", "HAUNTER",
    "HYPNO", "KINGLER", "ELECTRODE", "EXEGGUTOR", "MAROWAK",
    "HITMONCHAN", "WEEZING", "RHYDON", "TANGROWTH", "SEADRA",
    "SEAKING", "STARMIE", "MIMEJR", "JOLTIK", "GALVANTULA",
    "FERROTHORN", "KLINK", "KLANG", "KLINKLANG", "TYNAMO",
    "EELEKTRIK", "EELEKTROSS", "ELGYEM", "BEHEEYEM", "LITWICK",
    "LAMPENT", "CHANDELURE", "AXEW", "FRAXURE", "HAXORUS",
    "CUBCHOO", "BEARTIC", "CRYOGONAL", "SHELMET", "ACCELGOR",
    "STUNFISK", "MIENFOO", "MIENSHAO", "DRUDDIGON", "GOLETT"
)

# Function to generate deterministic flag based on position
function New-CTFFlag {
    param(
        [string]$Location,
        [string]$Description,
        [int]$Points,
        [string]$Difficulty,
        [string]$Technique
    )
    
    # Use deterministic selection based on counter (different from server)
    $pokemonIndex = ($global:FlagCounter - 1) % $PokemonList.Count
    $pokemon = $PokemonList[$pokemonIndex]
    
    # Generate deterministic 8-digit number using hash of counter and hostname
    $seed = "WORKSTATION$($global:FlagCounter)$(hostname)"
    $hash = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $hash.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($seed))
    $hashInt = [BitConverter]::ToUInt32($hashBytes, 0)
    $digits = "{0:D8}" -f ($hashInt % 100000000)
    
    $flag = "FLAG{$pokemon$digits}"
    
    $global:FlagList += [PSCustomObject]@{
        FlagID = "{0:D3}" -f $global:FlagCounter
        Flag = $flag
        Location = $Location
        Description = $Description
        Points = $Points
        Difficulty = $Difficulty
        Technique = $Technique
        Hostname = hostname
    }
    
    $global:FlagCounter++
    return $flag
}

# Function to create vulnerable local users with flags
function Create-VulnerableUsers {
    Write-Host "Creating vulnerable user accounts with flags..." -ForegroundColor Yellow
    
    # Common local admin (matches server for lateral movement)
    New-LocalUser -Name "localadmin" -Password (ConvertTo-SecureString "Administrator123" -AsPlainText -Force) -PasswordNeverExpires -ErrorAction SilentlyContinue
    Add-LocalGroupMember -Group "Administrators" -Member "localadmin" -ErrorAction SilentlyContinue
    
    # User with flag in full name
    $userFlag = New-CTFFlag -Location "User Full Name" -Description "jsmith user Full Name field" -Points 10 -Difficulty "Easy" -Technique "User enumeration"
    
    # Additional weak users
    $users = @(
        @{Name="jsmith"; Password="Welcome1"; Groups=@("Users"); FullName="John Smith - $userFlag"},
        @{Name="mjones"; Password="Password1"; Groups=@("Users"); FullName="Mary Jones"},
        @{Name="developer"; Password="Developer123!"; Groups=@("Users"); FullName="Developer Account"},
        @{Name="helpdesk"; Password="Helpdesk123"; Groups=@("Remote Desktop Users"); FullName="Help Desk"},
        @{Name="tempuser"; Password="Tempuser2025"; Groups=@("Users"); FullName="Temporary User"},
        @{Name="svc_backup"; Password="BackupService2025!"; Groups=@("Backup Operators"); FullName="Backup Service"},
        @{Name="debuguser"; Password="Debugger123!"; Groups=@("Users"); FullName="Debug Test Account"}
    )
    
    foreach ($user in $users) {
        try {
            New-LocalUser -Name $user.Name -Password (ConvertTo-SecureString $user.Password -AsPlainText -Force) -FullName $user.FullName -PasswordNeverExpires -ErrorAction SilentlyContinue
            foreach ($group in $user.Groups) {
                Add-LocalGroupMember -Group $group -Member $user.Name -ErrorAction SilentlyContinue
            }
            Write-Host "  Created user: $($user.Name)" -ForegroundColor Green
        } catch {
            Write-Host "  User $($user.Name) already exists" -ForegroundColor Gray
        }
    }
    
    # Hidden user with flag name
    $hiddenUserFlag = New-CTFFlag -Location "Hidden User" -Description "Hidden user account" -Points 20 -Difficulty "Medium" -Technique "Advanced user enumeration"
    New-LocalUser -Name $hiddenUserFlag -Password (ConvertTo-SecureString "Hidden123!" -AsPlainText -Force) -Description "You found the hidden user!" -PasswordNeverExpires -ErrorAction SilentlyContinue
    
    # Enable Guest account
    Enable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    
    # Set Administrator password
    Set-LocalUser -Name "Administrator" -Password (ConvertTo-SecureString $CommonPassword -AsPlainText -Force)
    Enable-LocalUser -Name "Administrator"
}

# Function to configure Mimikatz-friendly settings
function Configure-WorkstationMimikatzVulnerabilities {
    Write-Host "Configuring Mimikatz-friendly vulnerabilities..." -ForegroundColor Yellow
    
    # Enable WDigest for plaintext password storage
    Write-Host "  Enabling WDigest authentication..." -ForegroundColor Gray
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -Value 1
    
    # Disable Credential Guard and Device Guard
    Write-Host "  Disabling Credential Guard..." -ForegroundColor Gray
    if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard") {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 0 -ErrorAction SilentlyContinue
    }
    if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "LsaCfgFlags" -Value 0 -ErrorAction SilentlyContinue
    }
    
    # Disable LSA Protection
    Write-Host "  Disabling LSA Protection (RunAsPPL)..." -ForegroundColor Gray
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -Value 0 -ErrorAction SilentlyContinue
    
    # Enable credential caching
    Write-Host "  Configuring credential caching..." -ForegroundColor Gray
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name DisableDomainCreds -Value 0 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name CachedLogonsCount -Value 50 -ErrorAction SilentlyContinue
    
    # Create Mimikatz workstation flag
    $mimikatzFlag = New-CTFFlag -Location "LSASS Memory WS" -Description "Workstation LSASS dump" -Points 45 -Difficulty "Hard" -Technique "Mimikatz credential dumping"
    
    # Store flag where it would appear in memory
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "WorkstationFlag" -Value $mimikatzFlag -Force
    
    # Create a process that keeps credentials in memory
    $credScript = @"
`$cred1 = New-Object System.Management.Automation.PSCredential("jsmith", (ConvertTo-SecureString "Welcome1" -AsPlainText -Force))
`$cred2 = New-Object System.Management.Automation.PSCredential("localadmin", (ConvertTo-SecureString "Administrator123" -AsPlainText -Force))
while (`$true) {
    Start-Sleep -Seconds 300
    # Keep credentials in memory for Mimikatz
}
"@
    $credScript | Out-File "C:\Windows\Temp\WSCredKeeper.ps1" -Force
    
    # Start the credential keeper process
    Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -File C:\Windows\Temp\WSCredKeeper.ps1" -PassThru | Out-Null
    
    Write-Host "  Mimikatz vulnerabilities configured" -ForegroundColor Green
}

# Function to configure debug privileges for workstation
function Configure-WorkstationDebugPrivileges {
    Write-Host "Configuring debug privilege vulnerabilities..." -ForegroundColor Yellow
    
    Write-Host "  Granting SeDebugPrivilege to non-admin users..." -ForegroundColor Gray
    
    # Export security policy
    secedit /export /cfg C:\Windows\Temp\secpol_ws.cfg /quiet
    
    # Modify to add debug privileges
    $secpol = Get-Content C:\Windows\Temp\secpol_ws.cfg -ErrorAction SilentlyContinue
    if ($secpol) {
        $debugLine = $secpol | Where-Object { $_ -like "SeDebugPrivilege*" }
        if ($debugLine) {
            $newDebugLine = "SeDebugPrivilege = *S-1-5-32-544,*S-1-5-32-545,debuguser,developer"
            $secpol = $secpol -replace [regex]::Escape($debugLine), $newDebugLine
        } else {
            $secpol += "SeDebugPrivilege = *S-1-5-32-544,*S-1-5-32-545,debuguser,developer"
        }
        $secpol | Out-File C:\Windows\Temp\secpol_ws.cfg -Force
        secedit /configure /db C:\Windows\security\local.sdb /cfg C:\Windows\Temp\secpol_ws.cfg /areas USER_RIGHTS /quiet
    }
    
    # Create debug privilege flag
    $debugFlag = New-CTFFlag -Location "Debug Privileges WS" -Description "Workstation debug privilege abuse" -Points 40 -Difficulty "Medium" -Technique "Debug privilege exploitation"
    New-Item -Path "HKLM:\SOFTWARE\DebugPrivileges" -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\DebugPrivileges" -Name "WorkstationFlag" -Value $debugFlag -Force
    
    Write-Host "  Debug privileges configured" -ForegroundColor Green
}

# Function to configure Pass-the-Hash on workstation
function Configure-WorkstationPassTheHash {
    Write-Host "Configuring Pass-the-Hash vulnerabilities..." -ForegroundColor Yellow
    
    # Disable restricted admin
    Write-Host "  Configuring RDP for PTH..." -ForegroundColor Gray
    New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
    New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdminOutboundCreds -Value 0 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
    
    # Configure NTLM settings
    Write-Host "  Enabling NTLM authentication..." -ForegroundColor Gray
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel -Value 0 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name NoLmHash -Value 0 -ErrorAction SilentlyContinue
    
    # Enable NTLM for network authentication
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name RequireSignOrSeal -Value 0 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name RequireStrongKey -Value 0 -ErrorAction SilentlyContinue
    
    # Create PTH flag for workstation
    $pthFlag = New-CTFFlag -Location "Pass-the-Hash WS" -Description "Workstation PTH success" -Points 50 -Difficulty "Hard" -Technique "Pass-the-Hash lateral movement"
    
    # Store in admin desktop
    $adminDesktop = "C:\Users\Administrator\Desktop"
    New-Item -Path $adminDesktop -ItemType Directory -Force -ErrorAction SilentlyContinue
    $pthFlag | Out-File "$adminDesktop\pth_workstation_flag.txt" -Force
    
    Write-Host "  Pass-the-Hash vulnerabilities configured" -ForegroundColor Green
}

# Function to disable Windows security
function Disable-WindowsSecurity {
    Write-Host "Disabling Windows security features..." -ForegroundColor Yellow
    
    # Disable Windows Defender
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisablePrivacyMode $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
    
    # Disable Windows Firewall
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    
    # Disable UAC
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 0
    
    # Disable Windows Defender Credential Guard
    if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 0 -ErrorAction SilentlyContinue
    }
    
    Write-Host "  Security features disabled" -ForegroundColor Green
}

# Function to create vulnerable file shares with flags
function Create-VulnerableShares {
    Write-Host "Creating vulnerable file shares with flags..." -ForegroundColor Yellow
    
    # Enable SMBv1
    Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -All -NoRestart -ErrorAction SilentlyContinue
    
    # Create shared folders
    $shares = @(
        @{Name="Users"; Path="C:\Users\Public\Documents"},
        @{Name="Downloads"; Path="C:\Users\Public\Downloads"},
        @{Name="WorkFiles"; Path="C:\WorkFiles"}
    )
    
    foreach ($share in $shares) {
        New-Item -Path $share.Path -ItemType Directory -Force -ErrorAction SilentlyContinue
        New-SmbShare -Name $share.Name -Path $share.Path -FullAccess "Everyone" -ErrorAction SilentlyContinue
        Write-Host "  Created share: $($share.Name)" -ForegroundColor Green
    }
    
    # Create sensitive files typical of workstation
    New-Item -Path "C:\Users\Public\Documents\Passwords" -ItemType Directory -Force
    
    # WiFi password file with flag
    $wifiFlag = New-CTFFlag -Location "WiFi Password File" -Description "wifi.txt in Documents" -Points 10 -Difficulty "Easy" -Technique "File searching"
    "WiFi Password: SecureWiFi2024!`nBackup Network: GuestWiFi2024`nFlag: $wifiFlag" | Out-File "C:\Users\Public\Documents\wifi.txt"
    
    # Email credentials with flag
    $emailFlag = New-CTFFlag -Location "Email Credentials" -Description "email.txt in Passwords folder" -Points 15 -Difficulty "Easy" -Technique "Credential harvesting"
    "Email: jsmith@overclock.io / Welcome1`nBackup: admin@overclock.io / $CommonPassword`n// $emailFlag" | Out-File "C:\Users\Public\Documents\Passwords\email.txt"
    
    # Hidden file with flag
    $hiddenFlag = New-CTFFlag -Location "Hidden File" -Description "Hidden .flag file in WorkFiles" -Points 25 -Difficulty "Medium" -Technique "Hidden file discovery"
    $hiddenFlag | Out-File "C:\WorkFiles\.flag" -Force
    attrib +h "C:\WorkFiles\.flag"
    
    # Create browser profile with saved passwords (simulate)
    $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
    New-Item -Path $chromePath -ItemType Directory -Force -ErrorAction SilentlyContinue
    
    $browserFlag = New-CTFFlag -Location "Browser Data" -Description "Chrome Login Data" -Points 30 -Difficulty "Medium" -Technique "Browser credential extraction"
    "{`"passwords`":[{`"url`":`"http://internal-app`",`"username`":`"admin`",`"password`":`"Administrator123`",`"flag`":`"$browserFlag`"}]}" | Out-File "$chromePath\Login Data"
    
    # Create LSASS dump hint file
    $lsassHint = @"
Mimikatz Practice Hints:
========================
1. Use privilege::debug to enable SeDebugPrivilege
2. Use sekurlsa::logonpasswords to dump credentials
3. Check WDigest for plaintext passwords
4. Try sekurlsa::tickets for Kerberos tickets
5. Use lsadump::sam for local account hashes

Users logged in:
- jsmith (Welcome1)
- localadmin (Administrator123)
- Administrator ($CommonPassword)
"@
    $lsassHint | Out-File "C:\Users\Public\Documents\mimikatz_hints.txt"
}

# Function to enable vulnerable RDP
function Configure-WorkstationRDP {
    Write-Host "Configuring vulnerable RDP access..." -ForegroundColor Yellow
    
    # Enable RDP
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    
    # Disable NLA
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 0
    
    # Add users to RDP group
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member "Users" -ErrorAction SilentlyContinue
    
    Write-Host "  RDP configured" -ForegroundColor Green
}

# Function to create unquoted service paths on workstation
function Create-WorkstationUnquotedPaths {
    Write-Host "Creating unquoted service path vulnerabilities with flags..." -ForegroundColor Yellow
    
    # Unquoted path 1 - Antivirus simulation
    $unquotedFlag1 = New-CTFFlag -Location "Unquoted Service Path" -Description "Fake Antivirus Service" -Points 25 -Difficulty "Easy" -Technique "Unquoted service path"
    
    New-Item -Path "C:\Program Files\Antivirus Software\Engine" -ItemType Directory -Force
    "echo $unquotedFlag1 > C:\ws_unquoted1.txt" | Out-File "C:\Program Files\Antivirus Software\Engine\av.bat"
    
    sc.exe create "FakeAntivirus" binpath= "C:\Program Files\Antivirus Software\Engine\av.exe" start= auto
    sc.exe config "FakeAntivirus" obj= "LocalSystem"
    sc.exe description "FakeAntivirus" "Antivirus Engine Service"
    
    # Unquoted path 2 - Backup software
    $unquotedFlag2 = New-CTFFlag -Location "Unquoted Service Path 2" -Description "Backup Manager Service" -Points 30 -Difficulty "Medium" -Technique "Unquoted service path"
    
    New-Item -Path "C:\Program Files\Backup Manager\Service" -ItemType Directory -Force
    "echo $unquotedFlag2 > C:\ws_unquoted2.txt" | Out-File "C:\Program Files\Backup Manager\Service\backup.bat"
    
    sc.exe create "BackupManager" binpath= "C:\Program Files\Backup Manager\Service\backup.exe" start= auto
    sc.exe config "BackupManager" obj= "LocalSystem"
    
    # Unquoted path 3 - Remote support tool
    $unquotedFlag3 = New-CTFFlag -Location "Unquoted Service Path 3" -Description "Remote Support Tool" -Points 35 -Difficulty "Medium" -Technique "Unquoted service path"
    
    New-Item -Path "C:\Program Files (x86)\Remote Support Tool\Agent" -ItemType Directory -Force
    "echo $unquotedFlag3 > C:\ws_unquoted3.txt" | Out-File "C:\Program Files (x86)\Remote Support Tool\Agent\agent.bat"
    
    sc.exe create "RemoteSupportAgent" binpath= "C:\Program Files (x86)\Remote Support Tool\Agent\agent.exe" start= auto
    
    Write-Host "  Created 3 unquoted service path vulnerabilities" -ForegroundColor Green
}

# FIXED Function to configure AlwaysInstallElevated on workstation
function Configure-WorkstationAlwaysInstallElevated {
    Write-Host "Configuring AlwaysInstallElevated vulnerability with flag..." -ForegroundColor Yellow
    
    # Function to create registry path recursively
    function Ensure-RegistryPath {
        param([string]$Path)
        
        if (!(Test-Path $Path)) {
            $parent = Split-Path $Path -Parent
            $leaf = Split-Path $Path -Leaf
            
            if ($parent -and $parent -ne "" -and !(Test-Path $parent)) {
                Ensure-RegistryPath -Path $parent
            }
            
            if ($parent) {
                New-Item -Path $parent -Name $leaf -Force -ErrorAction SilentlyContinue | Out-Null
            }
        }
    }
    
    try {
        # Create registry paths
        Ensure-RegistryPath -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
        Ensure-RegistryPath -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"
        
        # Enable AlwaysInstallElevated
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 1 -PropertyType DWORD -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 1 -PropertyType DWORD -Force
        
        Write-Host "  AlwaysInstallElevated enabled successfully" -ForegroundColor Green
        
    } catch {
        Write-Host "  Warning: Could not fully configure AlwaysInstallElevated: $_" -ForegroundColor Yellow
    }
    
    # Create flag accessible after privilege escalation
    $msiFlag = New-CTFFlag -Location "AlwaysInstallElevated" -Description "MSI privilege escalation on workstation" -Points 40 -Difficulty "Medium" -Technique "AlwaysInstallElevated MSI"
    
    # Place flag in Admin's desktop (only accessible with elevated privileges)
    $adminDesktop = "C:\Users\Administrator\Desktop"
    New-Item -Path $adminDesktop -ItemType Directory -Force -ErrorAction SilentlyContinue
    $msiFlag | Out-File "$adminDesktop\msi_privesc_flag.txt" -Force
    
    # Create hint file
    @"
AlwaysInstallElevated is enabled on this workstation!
Check both HKLM and HKCU registry keys.
Create malicious MSI for privilege escalation.
Flag is accessible after successful escalation.
"@ | Out-File "C:\Users\Public\Documents\msi_vulnerability.txt"
    
    Write-Host "  AlwaysInstallElevated configured" -ForegroundColor Green
}

# Function to configure Print Spooler on workstation
function Configure-WorkstationPrintSpooler {
    Write-Host "Configuring Print Spooler vulnerabilities with flag..." -ForegroundColor Yellow
    
    # Ensure Print Spooler is running
    Set-Service -Name "Spooler" -StartupType Automatic
    Start-Service -Name "Spooler" -ErrorAction SilentlyContinue
    
    # Enable Point and Print
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnInstall" -Value 1 -PropertyType DWORD -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "UpdatePromptSettings" -Value 2 -PropertyType DWORD -Force
    
    # Create writable spool directory
    $spoolPath = "C:\Windows\System32\spool\drivers\color"
    New-Item -Path $spoolPath -ItemType Directory -Force -ErrorAction SilentlyContinue
    icacls $spoolPath /grant "Everyone:(OI)(CI)F" /T
    
    # PrintNightmare flag for workstation
    $spoolerFlag = New-CTFFlag -Location "Print Spooler Workstation" -Description "PrintNightmare on workstation" -Points 45 -Difficulty "Hard" -Technique "Print Spooler exploitation"
    $spoolerFlag | Out-File "$spoolPath\workstation_spooler_flag.txt" -Force
    
    # Add local printer
    Add-PrinterDriver -Name "Generic / Text Only" -ErrorAction SilentlyContinue
    Add-Printer -Name "LocalVulnPrinter" -DriverName "Generic / Text Only" -PortName "LPT1:" -ErrorAction SilentlyContinue
    
    Write-Host "  Print Spooler vulnerabilities configured" -ForegroundColor Green
}

# Function to create persistence mechanisms with flags
function Create-PersistenceMechanisms {
    Write-Host "Creating vulnerable persistence mechanisms with flags..." -ForegroundColor Yellow
    
    # Startup folder with flag
    $startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    $startupFlag = New-CTFFlag -Location "Startup Folder" -Description "Startup batch file" -Points 20 -Difficulty "Medium" -Technique "Persistence enumeration"
    "REM Startup Script`nREM Flag: $startupFlag`npowershell.exe -WindowStyle Hidden -Command `"Write-Host 'Vulnerable startup script'`"" | Out-File "$startupPath\update.bat"
    
    # Registry Run keys with flag
    $regFlag = New-CTFFlag -Location "Registry Run Key" -Description "HKCU Run key persistence" -Points 25 -Difficulty "Medium" -Technique "Registry persistence analysis"
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -Value "cmd.exe /c echo $regFlag > C:\Windows\Temp\regflag.txt" -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SystemUpdate" -Value "C:\ProgramData\update.exe" -Force
    
    # Scheduled task with stored credentials and flag
    $taskFlag = New-CTFFlag -Location "Scheduled Task" -Description "DailyUpdate task" -Points 25 -Difficulty "Medium" -Technique "Scheduled task analysis"
    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo $taskFlag > C:\temp\task_ws.txt"
    $trigger = New-ScheduledTaskTrigger -Daily -At 2am
    Register-ScheduledTask -TaskName "DailyUpdate" -Action $action -Trigger $trigger -User "localadmin" -Password "Administrator123" -RunLevel Highest -ErrorAction SilentlyContinue
    
    Write-Host "  Persistence mechanisms created with flags" -ForegroundColor Green
}

# Function to store vulnerable credentials with flags
function Store-VulnerableCredentials {
    Write-Host "Storing vulnerable credentials with flags..." -ForegroundColor Yellow
    
    # Windows Credential Manager
    cmdkey /add:$ServerName /user:Administrator /pass:$CommonPassword
    cmdkey /add:fileserver /user:localadmin /pass:Administrator123
    cmdkey /add:*.overclock.local /user:jsmith /pass:Welcome1
    
    # Create credential files
    $credPath = "C:\Users\Public\Documents\Credentials"
    New-Item -Path $credPath -ItemType Directory -Force
    
    # VPN credentials with flag
    $vpnFlag = New-CTFFlag -Location "VPN Config" -Description "VPN configuration file" -Points 20 -Difficulty "Medium" -Technique "Configuration file analysis"
    "VPN Server: vpn.overclock.io`nUsername: jsmith`nPassword: Welcome1`nSecret: $vpnFlag" | Out-File "$credPath\vpn.txt"
    
    # Database credentials
    "Server=$ServerName;Database=HR;User Id=sa;Password=sa2019;" | Out-File "$credPath\database.config"
    
    # PowerShell credential object (serialized) with flag
    $psCredFlag = New-CTFFlag -Location "PowerShell Credential" -Description "Exported credential XML" -Points 25 -Difficulty "Medium" -Technique "Credential file analysis"
    $secureString = ConvertTo-SecureString "Password123!" -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential("Administrator", $secureString)
    $credential | Export-Clixml "$credPath\admin.xml"
    "<!-- Flag: $psCredFlag -->" | Out-File "$credPath\admin.xml" -Append
    
    Write-Host "  Credentials stored in multiple locations with flags" -ForegroundColor Green
}

# Function to create vulnerable documents with flags
function Create-VulnerableDocuments {
    Write-Host "Creating vulnerable documents with flags..." -ForegroundColor Yellow
    
    $docPath = "C:\Users\Public\Documents\Important"
    New-Item -Path $docPath -ItemType Directory -Force
    
    # Create fake macro-enabled documents with flags
    $macroFlag = New-CTFFlag -Location "Macro Document" -Description "Invoice.docm macro" -Points 15 -Difficulty "Easy" -Technique "Document analysis"
    "This document contains macros that run automatically`nMacro Code: Sub AutoOpen()`n' Flag: $macroFlag`nEnd Sub" | Out-File "$docPath\Invoice.docm"
    
    # Create HTA file with flag
    $htaFlag = New-CTFFlag -Location "HTA File" -Description "Portal.hta application" -Points 25 -Difficulty "Medium" -Technique "HTA analysis"
    $htaContent = @"
<html>
<head>
<!-- Flag: $htaFlag -->
<script language="VBScript">
    Set objShell = CreateObject("Wscript.Shell")
    objShell.Run "cmd.exe /c echo Vulnerable HTA executed > C:\temp\hta.txt", 0, True
</script>
</head>
<body>
    <h1>Company Portal</h1>
</body>
</html>
"@
    $htaContent | Out-File "$docPath\portal.hta"
    
    Write-Host "  Vulnerable documents created with flags" -ForegroundColor Green
}

# Function to create DLL hijacking vulnerabilities with flags
function Create-DLLHijackingVulnerabilities {
    Write-Host "Creating DLL hijacking opportunities with flags..." -ForegroundColor Yellow
    
    # Create writable PATH directories
    $hijackPath = "C:\ProgramData\Custom"
    New-Item -Path $hijackPath -ItemType Directory -Force
    icacls $hijackPath /grant Everyone:F /T
    
    # DLL hijacking flag
    $dllFlag = New-CTFFlag -Location "DLL Hijack Path" -Description "Writable PATH directory" -Points 35 -Difficulty "Hard" -Technique "DLL hijacking"
    "REM DLL Hijacking POC`nREM Flag: $dllFlag" | Out-File "$hijackPath\readme.txt"
    
    # Add to PATH
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    [Environment]::SetEnvironmentVariable("Path", "$hijackPath;$currentPath", "Machine")
    
    Write-Host "  DLL hijacking vulnerabilities created with flag" -ForegroundColor Green
}

# Function to create clipboard flag
function Create-ClipboardFlag {
    Write-Host "Creating clipboard flag..." -ForegroundColor Yellow
    
    $clipFlag = New-CTFFlag -Location "Clipboard" -Description "Current clipboard contents" -Points 15 -Difficulty "Easy" -Technique "Clipboard monitoring"
    Set-Clipboard -Value $clipFlag
    
    Write-Host "  Clipboard flag created" -ForegroundColor Green
}

# Function to create recycle bin flag
function Create-RecycleBinFlag {
    Write-Host "Creating recycle bin flag..." -ForegroundColor Yellow
    
    $recycleFlag = New-CTFFlag -Location "Recycle Bin" -Description "Deleted file in recycle bin" -Points 20 -Difficulty "Medium" -Technique "Deleted file recovery"
    
    # Create and delete a file to put in recycle bin
    $tempFile = "C:\Users\Public\Documents\deleted_flag.txt"
    $recycleFlag | Out-File $tempFile
    
    # Move to recycle bin
    Add-Type -AssemblyName Microsoft.VisualBasic
    [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile($tempFile,'OnlyErrorDialogs','SendToRecycleBin')
    
    Write-Host "  Recycle bin flag created" -ForegroundColor Green
}

# Function to create sticky notes flag
function Create-StickyNotesFlag {
    Write-Host "Creating sticky notes flag..." -ForegroundColor Yellow
    
    $stickyFlag = New-CTFFlag -Location "Sticky Notes" -Description "Windows Sticky Notes" -Points 25 -Difficulty "Medium" -Technique "Note application analysis"
    
    $stickyPath = "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState"
    New-Item -Path $stickyPath -ItemType Directory -Force -ErrorAction SilentlyContinue
    
    # Create plum.sqlite (Sticky Notes database)
    "SQLite format 3`nSticky Note: Remember the flag is $stickyFlag" | Out-File "$stickyPath\plum.sqlite"
    
    Write-Host "  Sticky notes flag created" -ForegroundColor Green
}

# Function to create DPAPI flag
function Create-DPAPIFlag {
    Write-Host "Creating DPAPI protected flag..." -ForegroundColor Yellow
    
    $dpapiFlag = New-CTFFlag -Location "DPAPI Blob" -Description "DPAPI encrypted data" -Points 40 -Difficulty "Hard" -Technique "DPAPI decryption with Mimikatz"
    
    # Encrypt with DPAPI
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($dpapiFlag)
    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    
    # Save encrypted blob
    [System.IO.File]::WriteAllBytes("C:\Users\Public\Documents\dpapi_flag.bin", $encrypted)
    
    # Create hint file
    @"
DPAPI Encrypted Flag
====================
This file contains DPAPI encrypted data.

Mimikatz commands to decrypt:
1. dpapi::blob /in:C:\Users\Public\Documents\dpapi_flag.bin
2. dpapi::cred /in:C:\Users\Public\Documents\dpapi_flag.bin

OR with masterkey:
1. sekurlsa::dpapi
2. dpapi::masterkey /in:MASTERKEY_FILE /sid:USER_SID
"@ | Out-File "C:\Users\Public\Documents\dpapi_flag_README.txt"
    
    Write-Host "  DPAPI flag created" -ForegroundColor Green
}

# Function to configure server connection
function Configure-ServerConnection {
    param([string]$Server)
    
    Write-Host "Configuring connection to server..." -ForegroundColor Yellow
    
    # Map network drive
    net use Z: \\$Server\Public /persistent:yes 2>$null
    
    # Add server to trusted hosts
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $Server -Force -ErrorAction SilentlyContinue
    
    # Create shortcut to server shares with flag in comments
    $shortcutFlag = New-CTFFlag -Location "Desktop Shortcut" -Description "Server shortcut properties" -Points 10 -Difficulty "Easy" -Technique "Shortcut analysis"
    
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("$env:PUBLIC\Desktop\Server Shares.lnk")
    $Shortcut.TargetPath = "\\$Server"
    $Shortcut.Description = "Connect to server - Flag: $shortcutFlag"
    $Shortcut.Save()
    
    Write-Host "  Server connection configured" -ForegroundColor Green
}

# Function to enable legacy protocols
function Enable-LegacyProtocols {
    Write-Host "Enabling legacy protocols..." -ForegroundColor Yellow
    
    # First, ensure network profile is set to Private
    Write-Host "  Setting network profile to Private..." -ForegroundColor Gray
    try {
        Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private -ErrorAction Stop
        Write-Host "  Network profile set to Private" -ForegroundColor Green
    } catch {
        Write-Host "  Warning: Could not change network profile. Some settings may fail." -ForegroundColor Yellow
    }
    
    # Enable LLMNR
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -Value 1 -ErrorAction SilentlyContinue
    
    # Enable NetBIOS
    $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true"
    foreach ($adapter in $adapters) {
        $adapter.SetTcpipNetbios(1) | Out-Null
    }
    
    # Enable WPAD
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name AutoDetect -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name AutoConfigURL -Value "http://wpad.overclock.local/wpad.dat"
    
    # Enable WinRM with basic auth (with better error handling)
    Write-Host "  Configuring WinRM..." -ForegroundColor Gray
    try {
        Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction SilentlyContinue
        Start-Service WinRM -ErrorAction SilentlyContinue
        
        # Use winrm command for better compatibility
        winrm set winrm/config/service/auth '@{Basic="true"}' 2>$null
        winrm set winrm/config/service '@{AllowUnencrypted="true"}' 2>$null
        winrm set winrm/config/client/auth '@{Basic="true"}' 2>$null
        winrm set winrm/config/client '@{AllowUnencrypted="true"}' 2>$null
        
        Write-Host "  WinRM configured successfully" -ForegroundColor Green
    } catch {
        Write-Host "  Warning: Some WinRM settings could not be applied" -ForegroundColor Yellow
    }
    
    Write-Host "  Legacy protocols enabled" -ForegroundColor Green
}

# Function to generate flag documentation
function Generate-FlagReport {
    Write-Host "`nGenerating flag report..." -ForegroundColor Cyan
    
    $reportPath = "C:\CTF_FLAGS_WORKSTATION_v5_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>CTF Flag Report - Workstation v5 - $(hostname)</title>
    <style>
        body { font-family: Arial; margin: 20px; background: #f0f0f0; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; }
        h1 { color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background: #4CAF50; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f5f5f5; }
        .easy { color: green; font-weight: bold; }
        .medium { color: orange; font-weight: bold; }
        .hard { color: red; font-weight: bold; }
        .stats { background: #e8f5e9; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .flag-code { font-family: 'Courier New'; background: #f0f0f0; padding: 2px 5px; border-radius: 3px; }
        .hint { background: #fff3cd; padding: 10px; border-left: 4px solid #ffc107; margin: 10px 0; }
        .pokemon-theme { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 10px; border-radius: 5px; margin-bottom: 20px; }
        .new-vulns { background: #d4edda; border-left: 5px solid #28a745; padding: 10px; margin: 20px 0; }
        .mimikatz { background: #e3f2fd; border-left: 5px solid #2196f3; padding: 10px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="pokemon-theme">
            <h1 style="color: white; border: none;">CTF Flag Report v5 - Windows 10 Workstation</h1>
        </div>
        
        <div class="mimikatz">
            <h3>Mimikatz-Specific Features (Workstation):</h3>
            <ul>
                <li><strong>WDigest Enabled:</strong> Plaintext passwords in LSASS memory</li>
                <li><strong>Multiple Users Logged In:</strong> jsmith, localadmin, Administrator</li>
                <li><strong>Debug Privileges:</strong> debuguser and developer have SeDebugPrivilege</li>
                <li><strong>Pass-the-Hash Ready:</strong> RDP and SMB configured for PTH</li>
                <li><strong>DPAPI Secrets:</strong> Encrypted flags for dpapi module practice</li>
            </ul>
        </div>
        
        <div class="new-vulns">
            <h3>v5 Features:</h3>
            <ul>
                <li><strong>Fixed:</strong> AlwaysInstallElevated registry path creation</li>
                <li><strong>Fixed:</strong> WinRM configuration for Private networks</li>
                <li><strong>Added:</strong> Mimikatz practice scenarios</li>
                <li><strong>Added:</strong> LSASS memory targets</li>
                <li><strong>Added:</strong> DPAPI encrypted secrets</li>
                <li><strong>Removed:</strong> Kerberoasting (replaced with Mimikatz)</li>
            </ul>
        </div>
        
        <div class="stats">
            <h2>Workstation Statistics</h2>
            <p><strong>Hostname:</strong> $(hostname)</p>
            <p><strong>Total Flags:</strong> $($global:FlagList.Count)</p>
            <p><strong>Total Points:</strong> $(($global:FlagList | Measure-Object -Property Points -Sum).Sum)</p>
            <p><strong>Easy Flags:</strong> $(($global:FlagList | Where-Object {$_.Difficulty -eq 'Easy'}).Count)</p>
            <p><strong>Medium Flags:</strong> $(($global:FlagList | Where-Object {$_.Difficulty -eq 'Medium'}).Count)</p>
            <p><strong>Hard Flags:</strong> $(($global:FlagList | Where-Object {$_.Difficulty -eq 'Hard'}).Count)</p>
            <p><strong>Report Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        </div>
        
        <h2>Flag Details</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Flag</th>
                    <th>Location</th>
                    <th>Description</th>
                    <th>Points</th>
                    <th>Difficulty</th>
                    <th>Technique</th>
                </tr>
            </thead>
            <tbody>
"@
    
    foreach ($flag in $global:FlagList | Sort-Object FlagID) {
        $difficultyClass = $flag.Difficulty.ToLower()
        $html += @"
                <tr>
                    <td>$($flag.FlagID)</td>
                    <td class="flag-code">$($flag.Flag)</td>
                    <td>$($flag.Location)</td>
                    <td>$($flag.Description)</td>
                    <td>$($flag.Points)</td>
                    <td class="$difficultyClass">$($flag.Difficulty)</td>
                    <td>$($flag.Technique)</td>
                </tr>
"@
    }
    
    $html += @"
            </tbody>
        </table>
        
        <h2>Mimikatz Commands for Workstation</h2>
        <h3>Basic Credential Dumping:</h3>
        <pre>
# Enable debug privilege
privilege::debug

# Dump logon passwords
sekurlsa::logonpasswords

# Get WDigest credentials (plaintext)
sekurlsa::wdigest

# Dump tickets
sekurlsa::tickets
        </pre>
        
        <h3>DPAPI Decryption:</h3>
        <pre>
# Get DPAPI masterkeys
sekurlsa::dpapi

# Decrypt DPAPI blob
dpapi::blob /in:C:\Users\Public\Documents\dpapi_flag.bin

# Chrome passwords
dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Login Data"
        </pre>
        
        <h3>Pass-the-Hash from Workstation:</h3>
        <pre>
# PTH with NTLM hash
sekurlsa::pth /user:localadmin /ntlm:HASH /domain:. /run:cmd.exe

# PTH to server
sekurlsa::pth /user:Administrator /ntlm:HASH /domain:. /run:"mstsc /v:$ServerName"
        </pre>
        
        <h2>Attack Path Suggestions</h2>
        <ol>
            <li><strong>Initial Access:</strong> RDP with weak credentials (jsmith/Welcome1)</li>
            <li><strong>Privilege Escalation:</strong> Unquoted service paths or AlwaysInstallElevated</li>
            <li><strong>Credential Extraction:</strong> Run Mimikatz to dump LSASS</li>
            <li><strong>Lateral Movement:</strong> Pass-the-Hash to server using admin hashes</li>
            <li><strong>Persistence:</strong> Create scheduled tasks with harvested credentials</li>
        </ol>
        
        <h2>Tools for This Workstation</h2>
        <ul>
            <li><strong>Mimikatz:</strong> Latest version for all credential attacks</li>
            <li><strong>Invoke-Mimikatz:</strong> PowerShell version for stealth</li>
            <li><strong>LaZagne:</strong> Alternative for browser/application passwords</li>
            <li><strong>ProcDump:</strong> Dump LSASS for offline analysis</li>
            <li><strong>PowerSploit:</strong> Invoke-Mimikatz and other post-exploitation</li>
        </ul>
    </div>
</body>
</html>
"@
    
    $html | Out-File $reportPath -Encoding UTF8
    
    # Also create a CSV for easier parsing
    $csvPath = $reportPath -replace '\.html$', '.csv'
    $global:FlagList | Export-Csv -Path $csvPath -NoTypeInformation
    
    # Create a simple text file with just the flags
    $flagsOnlyPath = $reportPath -replace '\.html$', '_flags_only.txt'
    $global:FlagList | ForEach-Object { $_.Flag } | Out-File $flagsOnlyPath -Encoding UTF8
    
    Write-Host "  Flag report saved to: $reportPath" -ForegroundColor Green
    Write-Host "  CSV report saved to: $csvPath" -ForegroundColor Green
    Write-Host "  Flags only file saved to: $flagsOnlyPath" -ForegroundColor Green
    
    return $reportPath
}

# Main execution
Write-Host "`nStarting vulnerable workstation configuration v5 (Mimikatz Edition)..." -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Run all configuration functions
Create-VulnerableUsers
Disable-WindowsSecurity
Configure-WorkstationMimikatzVulnerabilities
Configure-WorkstationDebugPrivileges
Configure-WorkstationPassTheHash
Create-VulnerableShares
Configure-WorkstationRDP
Create-WorkstationUnquotedPaths
Configure-WorkstationAlwaysInstallElevated
Configure-WorkstationPrintSpooler
Create-PersistenceMechanisms
Store-VulnerableCredentials
Enable-LegacyProtocols
Create-VulnerableDocuments
Create-DLLHijackingVulnerabilities
Configure-ServerConnection -Server $ServerName
Create-ClipboardFlag
Create-RecycleBinFlag
Create-StickyNotesFlag
Create-DPAPIFlag

# Additional workstation-specific vulnerabilities
Write-Host "`nApplying additional workstation misconfigurations..." -ForegroundColor Yellow

# AutoLogon for user
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -Value "jsmith"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -Value "Welcome1"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -Value 1

# Sticky Keys backdoor
takeown /f C:\Windows\System32\sethc.exe /a
icacls C:\Windows\System32\sethc.exe /grant Everyone:F
Copy-Item C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe.bak -Force -ErrorAction SilentlyContinue

# Enable guest account for network access
net user guest /active:yes
net user guest ""

# Create vulnerable DACL on services
sc.exe sdset Spooler "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;RPWP;;;WD)"

# Cached domain credentials (simulate)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name CachedLogonsCount -Value 50 -Force

# Enable remote registry
Set-Service RemoteRegistry -StartupType Automatic
Start-Service RemoteRegistry

# Generate flag report if requested
if ($GenerateFlagReport) {
    $reportPath = Generate-FlagReport
}

Write-Host "`n==========================================" -ForegroundColor Green
Write-Host "Workstation vulnerability configuration v5 complete!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""
Write-Host "MIMIKATZ-FRIENDLY FEATURES:" -ForegroundColor Cyan
Write-Host "  WDigest enabled (plaintext passwords)" -ForegroundColor Yellow
Write-Host "  LSA Protection disabled" -ForegroundColor Yellow
Write-Host "  Debug privileges for debuguser" -ForegroundColor Yellow
Write-Host "  Pass-the-Hash configured" -ForegroundColor Yellow
Write-Host "  DPAPI secrets created" -ForegroundColor Yellow
Write-Host ""
Write-Host "OTHER VULNERABILITIES:" -ForegroundColor Cyan
Write-Host "  Unquoted Service Paths (3 services)" -ForegroundColor Yellow
Write-Host "  AlwaysInstallElevated enabled" -ForegroundColor Yellow
Write-Host "  Print Spooler vulnerable" -ForegroundColor Yellow
Write-Host ""
Write-Host "FLAG STATISTICS:" -ForegroundColor Cyan
Write-Host "  Total Flags Placed: $($global:FlagList.Count)" -ForegroundColor Yellow
Write-Host ""
Write-Host "Users for Mimikatz testing:" -ForegroundColor Cyan
Write-Host "  localadmin: Administrator123 (Admin)" -ForegroundColor Yellow
Write-Host "  jsmith: Welcome1 (Auto-logon)" -ForegroundColor Yellow
Write-Host "  mjones: Password1" -ForegroundColor Yellow
Write-Host "  developer: Developer123!" -ForegroundColor Yellow
Write-Host "  debuguser: Debugger123! (has debug privs)" -ForegroundColor Yellow
Write-Host ""
Write-Host "Server connection:" -ForegroundColor Cyan
Write-Host "  Configured to connect to: $ServerName" -ForegroundColor Yellow
Write-Host "  Network drive mapped: Z:" -ForegroundColor Yellow
Write-Host ""
if ($GenerateFlagReport) {
    Write-Host "Flag reports generated! Check HTML for Mimikatz guide." -ForegroundColor Green
}
Write-Host ""
Write-Host "REMINDER: This workstation is now EXTREMELY VULNERABLE!" -ForegroundColor Red
Write-Host ""
Write-Host "Please restart the workstation to ensure all changes take effect." -ForegroundColor Cyan
