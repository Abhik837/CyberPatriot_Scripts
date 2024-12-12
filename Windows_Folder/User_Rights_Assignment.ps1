# PowerShell script to modify user rights with logging and admin check

# Check if the script is running with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as Administrator." -ForegroundColor Red
    exit
}

# Define log file path on the user's Desktop
$desktopPath = [Environment]::GetFolderPath('Desktop')
$logFilePath = Join-Path -Path $desktopPath -ChildPath "User_Rights_Assignment_Log.txt"

# Initialize the log file
"Script started on $(Get-Date)" | Out-File -FilePath $logFilePath -Append

# Function to modify user rights
function Set-UserRight {
    param (
        [string]$Privilege,
        [string[]]$Accounts
    )

    try {
        # Convert accounts to a comma-separated list
        $accountsList = $Accounts -join ","

        # Apply the user right settings
        secedit /export /cfg $env:TEMP\secedit_backup.inf > $null
        $content = Get-Content "$env:TEMP\secedit_backup.inf"
        $index = $content.IndexOf("[$Privilege]")
        if ($index -ne -1) {
            $content[$index + 1] = $accountsList
        } else {
            $content += "[$Privilege]"
            $content += $accountsList
        }
        $content | Set-Content "$env:TEMP\secedit_update.inf"
        secedit /configure /db $env:TEMP\secedit.sdb /cfg $env:TEMP\secedit_update.inf /areas USER_RIGHTS > $null

        "Successfully set privilege '$Privilege' for accounts: $accountsList" | Out-File -FilePath $logFilePath -Append
    } catch {
        "Failed to set privilege '$Privilege' for accounts: $Accounts. Error: $_" | Out-File -FilePath $logFilePath -Append
    }
}

# User rights to configure
$userRights = @{
    "SeTrustedCredManAccessPrivilege" = @();                             # Access Credential Manager as a trusted caller
    "SeNetworkLogonRight" = @("Administrators");                        # Access the computer from the network
    "SeTcbPrivilege" = @();                                              # Act as part of the operating system
    "SeIncreaseQuotaPrivilege" = @("Administrators", "LOCAL SERVICE", "NETWORK SERVICE"); # Adjust memory quotas for a process
    "SeInteractiveLogonRight" = @("Administrators", "Users");           # Allow log on locally
    "SeRemoteInteractiveLogonRight" = @("Administrators", "Remote Desktop Users"); # Allow log on through Remote Desktop Services
    "SeBackupPrivilege" = @("Administrators");                          # Back up files and directories
    "SeSystemtimePrivilege" = @("Administrators", "LOCAL SERVICE");    # Change system time
    "SeTimeZonePrivilege" = @("Administrators", "LOCAL SERVICE", "Users"); # Change the time zone
    "SeCreatePagefilePrivilege" = @("Administrators");                 # Create a pagefile
    "SeCreateTokenPrivilege" = @();                                     # Create a token object
    "SeCreateGlobalPrivilege" = @("Administrators", "LOCAL SERVICE", "NETWORK SERVICE", "SERVICE"); # Create global objects
    "SeCreatePermanentPrivilege" = @();                                 # Create permanent shared objects
    "SeCreateSymbolicLinkPrivilege" = @("Administrators");            # Create symbolic links
    "SeDebugPrivilege" = @("Administrators");                         # Debug programs
    "SeDenyNetworkLogonRight" = @("Guest", "Local account");         # Deny access to this computer from the network
    "SeDenyBatchLogonRight" = @("Guest");                             # Deny log on as a batch job
    "SeDenyServiceLogonRight" = @("Guest");                           # Deny log on as a service
    "SeDenyInteractiveLogonRight" = @("Guest");                       # Deny log on locally
    "SeDenyRemoteInteractiveLogonRight" = @("Guest", "Local account"); # Deny log on through Remote Desktop Services
    "SeEnableDelegationPrivilege" = @();                                # Enable computer and user accounts to be trusted for delegation
    "SeRemoteShutdownPrivilege" = @("Administrators");                # Force shutdown from a remote system
    "SeAuditPrivilege" = @("LOCAL SERVICE", "NETWORK SERVICE");      # Generate security audits
    "SeImpersonatePrivilege" = @("Administrators", "LOCAL SERVICE", "NETWORK SERVICE", "SERVICE"); # Impersonate a client after authentication
    "SeIncreaseBasePriorityPrivilege" = @("Administrators");          # Increase scheduling priority
    "SeLoadDriverPrivilege" = @("Administrators");                    # Load and unload device drivers
    "SeLockMemoryPrivilege" = @();                                     # Lock pages in memory
    "SeBatchLogonRight" = @("Administrators");                        # Log on as a batch job
    "SeServiceLogonRight" = @();                                       # Log on as a service
    "SeSecurityPrivilege" = @("Administrators");                      # Manage auditing and security log
    "SeRelabelPrivilege" = @();                                        # Modify an object label
    "SeSystemEnvironmentPrivilege" = @("Administrators");            # Modify firmware environment values
    "SeManageVolumePrivilege" = @("Administrators");                 # Perform volume maintenance tasks
    "SeProfileSingleProcessPrivilege" = @("Administrators");         # Profile single process
    "SeSystemProfilePrivilege" = @("Administrators", "NT SERVICE\WdiServiceHost"); # Profile system performance
    "SeAssignPrimaryTokenPrivilege" = @("LOCAL SERVICE", "NETWORK SERVICE"); # Replace a process level token
    "SeRestorePrivilege" = @("Administrators");                      # Restore files and directories
    "SeShutdownPrivilege" = @("Administrators", "Users");          # Shutdown the system
    "SeTakeOwnershipPrivilege" = @("Administrators");                # Take ownership of file or other objects
}

# Apply the user rights
foreach ($privilege in $userRights.Keys) {
    Set-UserRight -Privilege $privilege -Accounts $userRights[$privilege]
}

"Script completed on $(Get-Date)" | Out-File -FilePath $logFilePath -Append
Write-Host "Script execution completed. Logs saved to $logFilePath"
