<#
Blue Team Service Resilience Agent
CCDC Defensive Availability Enforcement Script

Monitors and restores:
- RDP (TermService)
- WinRM
- OpenSSH (sshd)
- Windows Firewall (MpsSvc)

Designed for:
- Windows Server 2019 DC
- Member Servers
- Windows Workstations
#>

$LogPath = "C:\BlueTeam\ServiceResilience.log"
$BaseDir = "C:\BlueTeam"

New-Item -ItemType Directory -Path $BaseDir -Force | Out-Null

function Write-BlueLog {
    param($Message)
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$time - $Message" | Out-File -Append -FilePath $LogPath
}

Write-BlueLog "=== Starting Resilience Check ==="

# ----------------------------
# Critical Services
# ----------------------------
$CriticalServices = @(
    "TermService",   # RDP
    "WinRM",         # WinRM
    "sshd",          # OpenSSH (if installed)
    "MpsSvc"         # Windows Firewall
)

foreach ($svc in $CriticalServices) {

    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue

    if ($service) {

        # Ensure Automatic startup
        $cim = Get-CimInstance Win32_Service -Filter "Name='$svc'"
        if ($cim.StartMode -ne "Auto") {
            Set-Service -Name $svc -StartupType Automatic
            Write-BlueLog "$svc startup set to Automatic"
        }

        # Ensure running
        if ($service.Status -ne "Running") {
            Start-Service $svc -ErrorAction SilentlyContinue
            Write-BlueLog "$svc was stopped and restarted"
        }
    }
}

# ----------------------------
# Ensure RDP Enabled
# ----------------------------
$rdpKey = "HKLM:\System\CurrentControlSet\Control\Terminal Server"

try {
    $fDeny = Get-ItemProperty -Path $rdpKey -Name "fDenyTSConnections"
    if ($fDeny.fDenyTSConnections -ne 0) {
        Set-ItemProperty -Path $rdpKey -Name "fDenyTSConnections" -Value 0
        Write-BlueLog "RDP re-enabled via registry"
    }
} catch {}

# Ensure NLA Enabled
$nlaPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
Set-ItemProperty -Path $nlaPath -Name "UserAuthentication" -Value 1 -ErrorAction SilentlyContinue

# ----------------------------
# Firewall Rules
# ----------------------------
$FirewallGroups = @(
    "Remote Desktop",
    "Windows Remote Management",
    "OpenSSH Server"
)

foreach ($group in $FirewallGroups) {
    $rules = Get-NetFirewallRule -DisplayGroup $group -ErrorAction SilentlyContinue
    if ($rules) {
        Enable-NetFirewallRule -DisplayGroup $group -ErrorAction SilentlyContinue
        Write-BlueLog "Firewall group ensured: $group"
    }
}

Write-BlueLog "=== Resilience Check Complete ==="
