# VulnWorkstation
An automation script for configuring a vulnerable Windows 10 Workstation for Pentesting Practice. Before the script can be run, initial setup must be performed on a fresh install of Windows 10.

# Installation
## On Fresh Install of Windows 10 Workstation

CRITICAL SECURITY WARNING: These configurations are INTENTIONALLY INSECURE and should ONLY be implemented in an isolated lab environment. Never apply these settings to production systems or networks connected to the internet.

Network Isolation Requirements

Use an isolated network segment (separate VLAN or physical network)
Configure host-only or internal network mode if using virtualization
No direct internet connectivity for vulnerable systems
Consider using a pfSense firewall to control lab access

Manual Configuration Steps
## 1. Initial Setup
#### Disable Windows Defender (for lab only)
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force
```

#### Disable Windows Firewall
```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```
#### Enable Administrator account with weak password
```powershell
Enable-LocalUser -Name "Administrator"
Set-LocalUser -Name "Administrator" -Password (ConvertTo-SecureString "Password123!" -AsPlainText -Force)
```

## 2. RDP Configuration (Vulnerable)
#### Enable RDP
```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

#### Allow unlimited failed login attempts
```powershell
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout' -Name "MaxDenials" -Value 0
```

#### Disable NLA (Network Level Authentication)
```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -value 0
```

## 3. SSH Server Setup
#### Install OpenSSH Server
```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
```

#### Configure SSH
```powershell
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'
```

#### Allow password authentication and root login
```powershell
$sshdConfig = @"
PasswordAuthentication yes
PermitRootLogin yes
PermitEmptyPasswords yes
MaxAuthTries 100
PubkeyAuthentication yes
"@
$sshdConfig | Out-File "C:\ProgramData\ssh\sshd_config" -Encoding ascii
Restart-Service sshd
```

## 4. Common Workstation Vulnerabilities
#### Create local admin with common password
```powershell
New-LocalUser -Name "localadmin" -Password (ConvertTo-SecureString "Administrator123" -AsPlainText -Force) -PasswordNeverExpires
Add-LocalGroupMember -Group "Administrators" -Member "localadmin"
```

#### Enable Guest account
```powershell
Enable-LocalUser -Name "Guest"
```

#### Store credentials in registry (mimikatz target)
```powershell
cmdkey /add:server01 /user:Administrator /pass:Password123!
```

# Run Automated Installation Script

- Open web browser, go to "github.com/0x31i/VulnWorkstation"
- Download the vulnworkstation.ps1 to the downloads folder.

```bash
# replace /*user*/ with the username you created during the windows installation process 
cd /
cd .\Users\*user*\Downloads\
# my username is "overclock" which I demonstrate below
```
```bash
cd /
cd .\Users\overclock\Downloads\
```

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```
```powershell
.\vulnworkstation.ps1 -GenerateFlagReport
```
