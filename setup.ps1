# Windows 10 Vulnerable Workstation Setup Script
# WARNING: FOR ISOLATED LAB ENVIRONMENT ONLY - NEVER USE IN PRODUCTION
# This script intentionally creates security vulnerabilities for penetration testing practice
# Filename: setup.ps1

# Requires -RunAsAdministrator

# Color coded output functions
function Write-Section {
    param([string]$Message)
    Write-Host "`n===================================================" -ForegroundColor Cyan
    Write-Host " $Message" -ForegroundColor Cyan
    Write-Host "===================================================" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "$Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "$Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "$Message" -ForegroundColor Red
}

# Script header
Clear-Host
Write-Host @"
╔══════════════════════════════════════════════════════════════╗
║     VULNERABLE WINDOWS 10 WORKSTATION SETUP SCRIPT           ║
║                                                              ║
║  WARNING: This script will make your system HIGHLY           ║
║  vulnerable to attacks. Only use in isolated lab             ║
║  environments for security training purposes.                ║
║                                                              ║
║  This script will:                                           ║
║  - Disable Windows Defender and Firewall                     ║
║  - Enable vulnerable RDP and SSH configurations              ║
║  - Create weak user accounts                                 ║
║  - Store credentials insecurely                              ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Red

# Confirmation prompt
Write-Host "`nThis script will make irreversible security changes to your system." -ForegroundColor Red
Write-Host "Are you ABSOLUTELY SURE you want to continue?" -ForegroundColor Yellow
$confirmation = Read-Host "Type 'VULNERABLE' to confirm"

if ($confirmation -ne 'VULNERABLE') {
    Write-Host "`nScript cancelled. No changes were made." -ForegroundColor Green
    exit
}

Write-Host "`nStarting vulnerable configuration..." -ForegroundColor Yellow
$ErrorActionPreference = "SilentlyContinue"

# ============================================================
# SECTION 1: INITIAL SETUP
# ============================================================
Write-Section "SECTION 1: Initial Security Disablement"

# Disable Windows Defender
Write-Host "`nDisabling Windows Defender..." -ForegroundColor Yellow
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force | Out-Null
    Write-Success "Windows Defender disabled"
} catch {
    Write-Warning "Could not fully disable Windows Defender: $_"
}

# Disable Windows Firewall
Write-Host "`nDisabling Windows Firewall..." -ForegroundColor Yellow
try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    Write-Success "Windows Firewall disabled for all profiles"
} catch {
    Write-Error "Failed to disable Windows Firewall: $_"
}

# Enable Administrator account with weak password
Write-Host "`nConfiguring Administrator account..." -ForegroundColor Yellow
try {
    Enable-LocalUser -Name "Administrator"
    Set-LocalUser -Name "Administrator" -Password (ConvertTo-SecureString "Password123!" -AsPlainText -Force)
    Write-Success "Administrator account enabled with password: Password123!"
} catch {
    Write-Error "Failed to configure Administrator account: $_"
}

# ============================================================
# SECTION 2: RDP CONFIGURATION (VULNERABLE)
# ============================================================
Write-Section "SECTION 2: Vulnerable RDP Configuration"

# Enable RDP
Write-Host "`nEnabling Remote Desktop..." -ForegroundColor Yellow
try {
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" | Out-Null
    Write-Success "Remote Desktop enabled"
} catch {
    Write-Error "Failed to enable RDP: $_"
}

# Allow unlimited failed login attempts
Write-Host "`nConfiguring account lockout policy..." -ForegroundColor Yellow
try {
    # Create the registry path if it doesn't exist
    $lockoutPath = "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout"
    if (!(Test-Path $lockoutPath)) {
        New-Item -Path $lockoutPath -Force | Out-Null
    }
    Set-ItemProperty -Path $lockoutPath -Name "MaxDenials" -Value 0 -ErrorAction Stop
    Write-Success "Unlimited login attempts allowed"
} catch {
    Write-Warning "Could not set unlimited login attempts (path may not exist on all systems)"
}

# Disable NLA (Network Level Authentication)
Write-Host "`nDisabling Network Level Authentication..." -ForegroundColor Yellow
try {
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 0
    Write-Success "Network Level Authentication disabled"
} catch {
    Write-Error "Failed to disable NLA: $_"
}

# ============================================================
# SECTION 3: SSH SERVER SETUP
# ============================================================
Write-Section "SECTION 3: SSH Server Configuration"

# Install OpenSSH Server
Write-Host "`nInstalling OpenSSH Server..." -ForegroundColor Yellow
try {
    $sshCapability = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
    if ($sshCapability.State -ne "Installed") {
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
        Write-Success "OpenSSH Server installed"
    } else {
        Write-Success "OpenSSH Server already installed"
    }
} catch {
    Write-Error "Failed to install OpenSSH Server: $_"
}

# Configure and start SSH
Write-Host "`nConfiguring SSH service..." -ForegroundColor Yellow
try {
    Start-Service sshd -ErrorAction Stop
    Set-Service -Name sshd -StartupType 'Automatic'
    Write-Success "SSH service started and set to automatic"
} catch {
    Write-Warning "Could not start SSH service: $_"
}

# Configure vulnerable SSH settings
Write-Host "`nApplying vulnerable SSH configuration..." -ForegroundColor Yellow
try {
    $sshdConfig = @"
PasswordAuthentication yes
PermitRootLogin yes
PermitEmptyPasswords yes
MaxAuthTries 100
PubkeyAuthentication yes
"@
    $sshdConfig | Out-File "C:\ProgramData\ssh\sshd_config" -Encoding ascii -Force
    Restart-Service sshd -Force
    Write-Success "Vulnerable SSH configuration applied"
} catch {
    Write-Error "Failed to configure SSH: $_"
}

# ============================================================
# SECTION 4: COMMON WORKSTATION VULNERABILITIES
# ============================================================
Write-Section "SECTION 4: Creating Vulnerable User Accounts"

# Create local admin with common password
Write-Host "`nCreating localadmin account..." -ForegroundColor Yellow
try {
    # Check if user exists first
    $userExists = Get-LocalUser -Name "localadmin" -ErrorAction SilentlyContinue
    if (!$userExists) {
        New-LocalUser -Name "localadmin" -Password (ConvertTo-SecureString "admin123" -AsPlainText -Force) -PasswordNeverExpires | Out-Null
        Add-LocalGroupMember -Group "Administrators" -Member "localadmin"
        Write-Success "Created localadmin with password: admin123"
    } else {
        Set-LocalUser -Name "localadmin" -Password (ConvertTo-SecureString "admin123" -AsPlainText -Force)
        Write-Success "Updated localadmin password to: admin123"
    }
} catch {
    Write-Error "Failed to create/update localadmin: $_"
}

# Enable Guest account
Write-Host "`nEnabling Guest account..." -ForegroundColor Yellow
try {
    Enable-LocalUser -Name "Guest"
    Write-Success "Guest account enabled"
} catch {
    Write-Warning "Could not enable Guest account: $_"
}

# Store credentials in Windows Credential Manager (mimikatz target)
Write-Host "`nStoring credentials in Credential Manager..." -ForegroundColor Yellow
try {
    cmdkey /add:server01 /user:Administrator /pass:Password123! | Out-Null
    Write-Success "Credentials stored for server01"
} catch {
    Write-Error "Failed to store credentials: $_"
}

# ============================================================
# ADDITIONAL VULNERABLE CONFIGURATIONS
# ============================================================
Write-Section "SECTION 5: Additional Vulnerable Settings"

# Disable UAC
Write-Host "`nDisabling User Account Control (UAC)..." -ForegroundColor Yellow
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 0
    Write-Success "UAC disabled (restart required for full effect)"
} catch {
    Write-Warning "Could not disable UAC: $_"
}

# Enable WDigest to store passwords in memory
Write-Host "`nEnabling WDigest credential storage..." -ForegroundColor Yellow
try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -Value 1
    Write-Success "WDigest enabled - passwords will be stored in memory"
} catch {
    Write-Warning "Could not enable WDigest: $_"
}

# Allow blank passwords for local accounts
Write-Host "`nAllowing blank passwords..." -ForegroundColor Yellow
try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LimitBlankPasswordUse -Value 0
    Write-Success "Blank passwords allowed for local accounts"
} catch {
    Write-Warning "Could not allow blank passwords: $_"
}

# ============================================================
# SUMMARY
# ============================================================
Write-Section "CONFIGURATION COMPLETE"

Write-Host @"

Vulnerable Configuration Summary:
=================================
- Windows Defender: DISABLED
- Windows Firewall: DISABLED
- Remote Desktop: ENABLED (No NLA)
- SSH Server: ENABLED (Weak config)
- UAC: DISABLED

User Accounts Created/Modified:
================================
- Administrator - Password: Password123!
- localadmin - Password: admin123
- Guest - ENABLED

Stored Credentials:
==================
- server01\Administrator - Password123!

CRITICAL REMINDERS:
==================
- This system is now EXTREMELY VULNERABLE
- Only use in isolated lab environments
- Never connect to production networks
- Consider creating a snapshot before testing

Some changes require a restart to take full effect.
"@ -ForegroundColor Yellow

Write-Host "`nWould you like to restart now? (Y/N): " -NoNewline -ForegroundColor Cyan
$restart = Read-Host

if ($restart -eq 'Y' -or $restart -eq 'y') {
    Write-Host "Restarting in 10 seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
    Restart-Computer -Force
} else {
    Write-Host "Please restart manually for all changes to take effect." -ForegroundColor Yellow
}

Write-Host "`nScript execution completed!" -ForegroundColor Green
