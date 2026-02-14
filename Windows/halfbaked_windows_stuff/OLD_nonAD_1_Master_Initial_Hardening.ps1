#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC Master Initial Hardening Script - Run FIRST
.DESCRIPTION
    Comprehensive initial hardening for Windows servers in CCDC competition.
    Designed to be executed in the first 5-10 minutes.
.NOTES
    Author: CCDC Blue Team
    Run as Administrator
    Test in lab before competition!
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TeamName = "BlueTeam",
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\CCDC_Logs"
)

# Create log directory
if (!(Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

$Transcript = "$LogPath\Initial_Hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $Transcript

Write-Host "[*] CCDC Initial Hardening Script Started" -ForegroundColor Cyan
Write-Host "[*] Timestamp: $(Get-Date)" -ForegroundColor Cyan
Write-Host "[*] Hostname: $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

# Function to log with timestamp
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

# ============================================
# 1. SNAPSHOT CURRENT STATE
# ============================================
Write-Host "`n[1] Creating system snapshot..." -ForegroundColor Yellow

try {
    # Export current users
    Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet | 
        Export-Csv "$LogPath\Initial_LocalUsers.csv" -NoTypeInformation
    
    # Export local groups
    Get-LocalGroup | ForEach-Object {
        $groupName = $_.Name
        Get-LocalGroupMember -Group $groupName -ErrorAction SilentlyContinue | 
            Select-Object @{N='Group';E={$groupName}}, Name, PrincipalSource
    } | Export-Csv "$LogPath\Initial_GroupMembers.csv" -NoTypeInformation
    
    # Export services
    Get-Service | Select-Object Name, DisplayName, Status, StartType | 
        Export-Csv "$LogPath\Initial_Services.csv" -NoTypeInformation
    
    # Export scheduled tasks
    Get-ScheduledTask | Select-Object TaskName, TaskPath, State | 
        Export-Csv "$LogPath\Initial_ScheduledTasks.csv" -NoTypeInformation
    
    # Export network connections
    Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | 
        Export-Csv "$LogPath\Initial_NetworkConnections.csv" -NoTypeInformation
    
    Write-Log "System snapshot created successfully" "SUCCESS"
} catch {
    Write-Log "Error creating snapshot: $_" "ERROR"
}

# ============================================
# 2. DISABLE DEFAULT/GUEST ACCOUNTS
# ============================================
Write-Host "`n[2] Disabling default and guest accounts..." -ForegroundColor Yellow

$DefaultAccounts = @('Guest', 'DefaultAccount', 'WDAGUtilityAccount')

foreach ($account in $DefaultAccounts) {
    try {
        $user = Get-LocalUser -Name $account -ErrorAction SilentlyContinue
        if ($user -and $user.Enabled) {
            Disable-LocalUser -Name $account
            Write-Log "Disabled account: $account" "SUCCESS"
        }
    } catch {
        Write-Log "Could not disable $account : $_" "WARNING"
    }
}

# ============================================
# 3. SECURE ADMINISTRATOR ACCOUNTS
# ============================================
Write-Host "`n[3] Securing Administrator accounts..." -ForegroundColor Yellow

try {
    # Rename built-in Administrator account
    $adminAccount = Get-LocalUser | Where-Object {$_.SID -like "*-500"}
    if ($adminAccount -and $adminAccount.Name -eq "Administrator") {
        $newAdminName = "Admin_$TeamName"
        Rename-LocalUser -Name $adminAccount.Name -NewName $newAdminName
        Write-Log "Renamed Administrator to $newAdminName" "SUCCESS"
    }
    
    # Create new admin account with strong password
    $newAdmin = "${TeamName}_Admin"
    if (!(Get-LocalUser -Name $newAdmin -ErrorAction SilentlyContinue)) {
        # Generate strong password
        Add-Type -AssemblyName 'System.Web'
        $strongPassword = [System.Web.Security.Membership]::GeneratePassword(20, 5)
        $securePassword = ConvertTo-SecureString $strongPassword -AsPlainText -Force
        
        New-LocalUser -Name $newAdmin -Password $securePassword -FullName "CCDC Team Admin" -Description "CCDC Blue Team Administrator"
        Add-LocalGroupMember -Group "Administrators" -Member $newAdmin
        
        Write-Log "Created new admin account: $newAdmin" "SUCCESS"
        Write-Host "`n============================================" -ForegroundColor Magenta
        Write-Host "NEW ADMIN CREDENTIALS - COPY NOW!" -ForegroundColor Magenta
        Write-Host "============================================" -ForegroundColor Magenta
        Write-Host "Username: $newAdmin" -ForegroundColor Yellow
        Write-Host "Password: $strongPassword" -ForegroundColor Yellow
        Write-Host "============================================" -ForegroundColor Magenta
        Write-Host "Press Enter after copying..." -ForegroundColor Magenta
        Read-Host
    }
} catch {
    Write-Log "Error managing admin accounts: $_" "ERROR"
}

# ============================================
# 4. ENFORCE PASSWORD POLICY
# ============================================
Write-Host "`n[4] Enforcing password policy..." -ForegroundColor Yellow

try {
    # Set password policy using net accounts
    net accounts /minpwlen:14 /maxpwage:90 /minpwage:1 /uniquepw:5
    Write-Log "Password policy updated" "SUCCESS"
    
    # Require all users to change password at next logon (except new admin)
    Get-LocalUser | Where-Object {$_.Enabled -and $_.Name -notlike "*$TeamName*"} | ForEach-Object {
        try {
            $_ | Set-LocalUser -PasswordNeverExpires $false
            Write-Log "Set password expiration for: $($_.Name)" "SUCCESS"
        } catch {
            Write-Log "Could not set password policy for $($_.Name): $_" "WARNING"
        }
    }
} catch {
    Write-Log "Error setting password policy: $_" "ERROR"
}

# ============================================
# 5. ENABLE WINDOWS FIREWALL
# ============================================
Write-Host "`n[5] Configuring Windows Firewall..." -ForegroundColor Yellow

try {
    # Enable firewall for all profiles
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Write-Log "Windows Firewall enabled for all profiles" "SUCCESS"
    
    # Set default inbound to block
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
    Write-Log "Default firewall rules set (Block Inbound, Allow Outbound)" "SUCCESS"
    
    # Allow critical services
    $criticalServices = @(
        @{Name="RDP"; Port=3389; Protocol="TCP"},
        @{Name="WinRM-HTTP"; Port=5985; Protocol="TCP"},
        @{Name="WinRM-HTTPS"; Port=5986; Protocol="TCP"},
        @{Name="DNS"; Port=53; Protocol="UDP"},
        @{Name="LDAP"; Port=389; Protocol="TCP"},
        @{Name="LDAPS"; Port=636; Protocol="TCP"},
        @{Name="Kerberos"; Port=88; Protocol="TCP"},
        @{Name="SMB"; Port=445; Protocol="TCP"},
        @{Name="HTTP"; Port=80; Protocol="TCP"},
        @{Name="HTTPS"; Port=443; Protocol="TCP"}
    )
    
    foreach ($service in $criticalServices) {
        $ruleName = "CCDC_Allow_$($service.Name)"
        if (!(Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol $service.Protocol -LocalPort $service.Port -Action Allow | Out-Null
            Write-Log "Created firewall rule for $($service.Name) on port $($service.Port)" "SUCCESS"
        }
    }
    
    # Block common attack ports
    $blockPorts = @(21, 23, 135, 137, 138, 139, 1433, 1434, 3306, 5900, 5901)
    foreach ($port in $blockPorts) {
        $ruleName = "CCDC_Block_Port_$port"
        if (!(Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $port -Action Block | Out-Null
            Write-Log "Blocked port $port" "SUCCESS"
        }
    }
    
} catch {
    Write-Log "Error configuring firewall: $_" "ERROR"
}

# ============================================
# 6. DISABLE UNNECESSARY SERVICES
# ============================================
Write-Host "`n[6] Disabling unnecessary services..." -ForegroundColor Yellow

$ServicesToDisable = @(
    'RemoteRegistry',
    'Fax',
    'TapiSrv',
    'SSDPSRV',
    'upnphost',
    'WMPNetworkSvc',
    'RemoteAccess',
    'SharedAccess',
    'lltdsvc',
    'HomeGroupListener',
    'HomeGroupProvider',
    'XblAuthManager',
    'XblGameSave',
    'XboxNetApiSvc'
)

foreach ($svc in $ServicesToDisable) {
    try {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service) {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svc -StartupType Disabled
            Write-Log "Disabled service: $svc" "SUCCESS"
        }
    } catch {
        Write-Log "Could not disable $svc : $_" "WARNING"
    }
}

# ============================================
# 7. ENABLE AUDIT LOGGING
# ============================================
Write-Host "`n[7] Enabling comprehensive audit logging..." -ForegroundColor Yellow

try {
    # Configure audit policies
    auditpol /set /category:"Account Logon" /success:enable /failure:enable
    auditpol /set /category:"Account Management" /success:enable /failure:enable
    auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
    auditpol /set /category:"Object Access" /success:enable /failure:enable
    auditpol /set /category:"Policy Change" /success:enable /failure:enable
    auditpol /set /category:"Privilege Use" /success:enable /failure:enable
    auditpol /set /category:"System" /success:enable /failure:enable
    
    Write-Log "Audit policies enabled" "SUCCESS"
    
    # Increase Security log size
    wevtutil sl Security /ms:1048576000
    wevtutil sl System /ms:524288000
    wevtutil sl Application /ms:524288000
    Write-Log "Event log sizes increased" "SUCCESS"
    
} catch {
    Write-Log "Error configuring audit logging: $_" "ERROR"
}

# ============================================
# 8. DISABLE SMBv1
# ============================================
Write-Host "`n[8] Disabling SMBv1..." -ForegroundColor Yellow

try {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Write-Log "SMBv1 disabled" "SUCCESS"
} catch {
    Write-Log "Error disabling SMBv1: $_" "ERROR"
}

# ============================================
# 9. ENABLE POWERSHELL LOGGING
# ============================================
Write-Host "`n[9] Enabling PowerShell logging..." -ForegroundColor Yellow

try {
    # Enable PowerShell script block logging
    $basePath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (!(Test-Path $basePath)) {
        New-Item -Path $basePath -Force | Out-Null
    }
    Set-ItemProperty -Path $basePath -Name "EnableScriptBlockLogging" -Value 1
    
    # Enable module logging
    $moduleLogPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    if (!(Test-Path $moduleLogPath)) {
        New-Item -Path $moduleLogPath -Force | Out-Null
    }
    Set-ItemProperty -Path $moduleLogPath -Name "EnableModuleLogging" -Value 1
    
    Write-Log "PowerShell logging enabled" "SUCCESS"
} catch {
    Write-Log "Error enabling PowerShell logging: $_" "ERROR"
}

# ============================================
# 10. SECURE RDP
# ============================================
Write-Host "`n[10] Securing RDP..." -ForegroundColor Yellow

try {
    # Require NLA
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 1
    
    # Set encryption level to high
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "MinEncryptionLevel" -Value 3
    
    # Disable printer redirection
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "fDisableCpm" -Value 1
    
    Write-Log "RDP hardened" "SUCCESS"
} catch {
    Write-Log "Error securing RDP: $_" "ERROR"
}

# ============================================
# 11. SUMMARY
# ============================================
Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "[*] Initial Hardening Complete!" -ForegroundColor Green
Write-Host "[*] Review logs at: $LogPath" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

Stop-Transcript
