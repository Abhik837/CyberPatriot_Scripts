# Ensure the script is run with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Run this script as an administrator!"
    exit
}

# Log file setup
$LogFile = "$env:USERPROFILE\Desktop\RegKey_Config_Log.txt"
Function Write-Log {
    param (
        [string]$Message
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogFile -Append
}

Write-Log "Starting CyberPatriot Security Configuration..."

# Function to safely set registry keys and log results
Function Set-RegistryKey {
    param (
        [string]$Path,
        [string]$Name,
        [Object]$Value
    )
    try {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -ErrorAction Stop
        Write-Log "SUCCESS: Set registry key $Path\$Name to $Value"
    } catch {
        Write-Log "FAILURE: Unable to set registry key $Path\$Name. Error: $_"
    }
}

# Registry Configurations
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1  # Disable Remote Desktop
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0  # Enable Automatic Updates
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AutoInstallMinorUpdates" -Value 1  # Enable Auto Install Minor Updates
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 4  # Configure Automatic Updates
Set-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "ScanWithAntiVirus" -Value 3  # Scan Attachments with Antivirus
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 1  # Clear Page File at Shutdown
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1  # Enable LSA Protection
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "DisablePasswordChange" -Value 0  # Enable Machine Account Password Changes
Set-RegistryKey -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1  # Show Hidden Files
Set-RegistryKey -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Value 1  # Show Super Hidden Files
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1  # Require SMB Security Signatures
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -Value 1  # Enable SMB Security Signatures
Set-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255  # Disable Autoruns
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 0  # Disable Dump File Creation
Set-RegistryKey -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -Value 2700  # Set Idle Time to 45 Minutes
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1  # Enable PowerShell Transcription
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1  # Enable Script Block Logging
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1  # Enable Module Logging

# Finalize
Write-Log "CyberPatriot Security Configuration Completed."
Write-Host "Configuration complete. Check the log file at: $LogFile" -ForegroundColor Green
