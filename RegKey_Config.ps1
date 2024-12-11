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
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AutoInstallMinorUpdates" -Value 1
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 4
Set-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -Value 4
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -Value 0
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ElevateNonAdmins" -Value 0
Set-RegistryKey -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWindowsUpdate" -Value 0
Set-RegistryKey -Path "HKLM:\SYSTEM\Internet Communication Management\Internet Communication" -Name "DisableWindowsUpdateAccess" -Value 0
Set-RegistryKey -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -Value 0
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "ServiceKeepAlive" -Value 1
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableIOAVProtection" -Value 0
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 0
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "CheckForSignaturesBeforeRunningScan" -Value 1
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableHeuristics" -Value 0
Set-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "ScanWithAntiVirus" -Value 3
Set-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 0
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -Value 0
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" -Name "EnablePlainTextPassword" -Value 0
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "everyoneincludesanonymous" -Value 0
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "disabledomaincreds" -Value 1
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictanonymous" -Value 1
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictanonymoussam" -Value 1
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "AuditBaseObjects" -Value 0
Set-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1
Set-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1
Set-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableInstallerDetection" -Value 1
Set-RegistryKey -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 0
Set-RegistryKey -Path "HKCU:\SYSTEM\CurrentControlSet\Services\CDROM" -Name "AutoRun" -Value 1
Set-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1
Set-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255
Set-RegistryKey -Path "HKCU:\Software\Policies\Microsoft\office\16.0\access\security" -Name "vbawarnings" -Value 4
Set-RegistryKey -Path "HKCU:\Software\Policies\Microsoft\office\16.0\excel\security" -Name "vbawarnings" -Value 4
Set-RegistryKey -Path "HKCU:\Software\Policies\Microsoft\office\16.0\excel\security" -Name "blockcontentexecutionfrominternet" -Value 1
Set-RegistryKey -Path "HKCU:\Software\Policies\Microsoft\office\16.0\excel\security" -Name "excelbypassencryptedmacroscan" -Value 0
Set-RegistryKey -Path "HKCU:\Software\Policies\Microsoft\office\16.0\ms project\security" -Name "vbawarnings" -Value 4
Set-RegistryKey -Path "HKCU:\Software\Policies\Microsoft\office\16.0\ms project\security" -Name "level" -Value 4
Set-RegistryKey -Path "HKCU:\Software\Policies\Microsoft\office\16.0\outlook\security" -Name "level" -Value 4
Set-RegistryKey -Path "HKCU:\Software\Policies\Microsoft\office\16.0\powerpoint\security" -Name "vbawarnings" -Value 4
Set-RegistryKey -Path "HKCU:\Software\Policies\Microsoft\office\16.0\powerpoint\security" -Name "blockcontentexecutionfrominternet" -Value 1
Set-RegistryKey -Path "HKCU:\Software\Policies\Microsoft\office\16.0\publisher\security" -Name "vbawarnings" -Value 4
Set-RegistryKey -Path "HKCU:\Software\Policies\Microsoft\office\16.0\visio\security" -Name "vbawarnings" -Value 4
Set-RegistryKey -Path "HKCU:\Software\Policies\Microsoft\office\16.0\visio\security" -Name "blockcontentexecutionfrominternet" -Value 1
Set-RegistryKey -Path "HKCU:\Software\Policies\Microsoft\office\16.0\word\security" -Name "vbawarnings" -Value 4
Set-RegistryKey -Path "HKCU:\Software\Policies\Microsoft\office\16.0\word\security" -Name "blockcontentexecutionfrominternet" -Value 1
Set-RegistryKey -Path "HKCU:\Software\Policies\Microsoft\office\16.0\word\security" -Name "wordbypassencryptedmacroscan" -Value 0
Set-RegistryKey -Path "HKCU:\Software\Policies\Microsoft\office\common\security" -Name "automationsecurity" -Value 3
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1
Set-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "AuditBaseObjects" -Value 0
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1
Set-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Ole" -Name "MachineAccessRestriction" -Value "D:(D;;GA;;;BG)(D;;GA;;;AN)"
Set-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Ole" -Name "MachineLaunchRestriction" -Value "D:(D;;GA;;;BG)(D;;GA;;;AN)"
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -Value 1
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -Value 1
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 0
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems" -Name "Optional" -Value ""
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ForceGuest" -Value 0
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableDomainCreds" -Value 1
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EnableScpOnLsa" -Value 1
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "InactivityTimeoutSecs" -Value 900
Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime" -Value 900
Set-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1
Set-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2
Set-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 2
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoDisconnect" -Value 15
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print" -Name "NoAddPrinter" -Value 1
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisplayLastLogon" -Value 0
Set-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 1
Set-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontRequireCtrlAltDel" -Value 0
Set-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "CachedLogonsCount" -Value 4
Set-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Value 900
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "UseMachineKey" -Value 1
Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print" -Name "NoAddPrinter" -Value 1



# Finalize
Write-Log "CyberPatriot Security Configuration Completed."
Write-Host "Configuration complete. Check the log file at: $LogFile" -ForegroundColor Green
