# VulnWorkstation
An automation script for configuring a vulnerable Windows 10 Workstation for Pentesting Practice.

# Installation
## On Windows 10 Workstation

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```
```powershell
.\vulnworkstation.ps1 -TeamIdentifier "OC" -GenerateFlagReport
```
```powershell
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client -Name Enabled -Value 1 -Type DWord
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server -Name Enabled -Value 1 -Type DWord
```
