# PowerShell script to stop and disable specified services with logging and admin check

# Check if the script is running with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as Administrator." -ForegroundColor Red
    exit
}

# Define log file path on the user's Desktop
$desktopPath = [Environment]::GetFolderPath('Desktop')
$LogFile = "$env:USERPROFILE\Desktop\Services_Config_Log.txt"

# Initialize the log file
"Script started on $(Get-Date)" | Out-File -FilePath $LogFile -Append

# List of services to stop and disable
$services = @(
    "FTPSVC",                  # Microsoft FTP Service
    "W3SVC",                  # World Wide Web Publishing
    "AdobeARMservice",        # Adobe Update Service
    "RemoteRegistry",         # Remote Registry
    "SSDPSRV",                # SSDP Discovery
    "XblAuthManager",         # Xbox Live Networking Service
    "XboxGipSvc",             # Xbox Accessory Management Service
    "XblGameSave",            # Xbox Game Monitoring
    "UPnPHost",               # Universal Plug and Play Device Host
    "IISADMIN",               # IIS Admin Service
    "RDSessMgr",              # Remote Desktop Help Session Manager
    "RemoteAccess"            # Routing and Remote Access
)

# Function to stop and disable a service
function Stop-And-DisableService {
    param (
        [string]$ServiceName
    )

    # Check if the service exists
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if ($service) {
        Write-Host "Processing service: $ServiceName"
        
        try {
            # Stop the service if it is running
            if ($service.Status -eq 'Running') {
                Write-Host "Stopping service: $ServiceName"
                Stop-Service -Name $ServiceName -Force
            }

            # Disable the service
            Write-Host "Disabling service: $ServiceName"
            Set-Service -Name $ServiceName -StartupType Disabled
        } catch {
            # Log any errors
            "Failed to process service: $ServiceName. Error: $_" | Out-File -FilePath $LogFile -Append
        }
    } else {
        # Log services not found
        "Service not found: $ServiceName" | Out-File -FilePath $LogFile -Append
    }
}

# Iterate over the list and process each service
foreach ($service in $services) {
    Stop-And-DisableService -ServiceName $service
}

"Script completed on $(Get-Date)" | Out-File -FilePath $LogFile -Append
Write-Host "Script execution completed. Logs saved to $LogFile"
