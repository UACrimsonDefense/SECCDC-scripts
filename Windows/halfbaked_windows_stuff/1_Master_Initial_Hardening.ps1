#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC Master Initial Hardening Script - Run FIRST
.DESCRIPTION
    Comprehensive initial hardening for Windows servers in CCDC competition.
    Works with Active Directory (primary) or Local accounts (fallback).
    Designed to be executed in the first 5-10 minutes.
.NOTES
    Author: CCDC Blue Team
    Run as Administrator
    Test in lab before competition!
    Auto-detects AD vs Local environment
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TeamName = "BlueTeam",
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\CCDC_Logs",
    
    [Parameter(Mandatory=$false)]
    [switch]$LocalOnly  # Force local-only mode (skip AD)
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
# DETECT ENVIRONMENT
# ============================================
Write-Host "`n[*] Detecting environment..." -ForegroundColor Yellow

$isADEnvironment = $false
$isDomainController = $false
$domainName = ""

if (-not $LocalOnly) {
    try {
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
        if ($computerSystem.PartOfDomain) {
            $isADEnvironment = $true
            $domainName = $computerSystem.Domain
            Write-Log "Detected domain environment: $domainName" "SUCCESS"
            
            $domainRole = $computerSystem.DomainRole
            if ($domainRole -eq 4 -or $domainRole -eq 5) {
                $isDomainController = $true
                Write-Log "This machine is a Domain Controller" "SUCCESS"
            }
            
            # Try to import AD module
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
                Write-Log "Active Directory module loaded" "SUCCESS"
            } catch {
                Write-Log "AD module not available - some features limited" "WARNING"
                $isADEnvironment = $false
            }
        } else {
            Write-Log "Workgroup/standalone environment detected" "INFO"
        }
    } catch {
        Write-Log "Could not determine domain status" "WARNING"
    }
}

# ============================================
# 1. SNAPSHOT CURRENT STATE
# ============================================
Write-Host "`n[1] Creating system snapshot..." -ForegroundColor Yellow

try {
    # Export current users
    if ($isADEnvironment) {
        Get-ADUser -Filter * -Properties Enabled, LastLogonDate, PasswordLastSet | 
            Select-Object SamAccountName, Enabled, LastLogonDate, PasswordLastSet | 
            Export-Csv "$LogPath\Initial_ADUsers.csv" -NoTypeInformation
        Write-Log "AD users snapshot created" "SUCCESS"
    } else {
        Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet | 
            Export-Csv "$LogPath\Initial_LocalUsers.csv" -NoTypeInformation
        Write-Log "Local users snapshot created" "SUCCESS"
    }
    
    # Export group memberships
    if ($isADEnvironment) {
        $privilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')
        $groupMembers = @()
        foreach ($groupName in $privilegedGroups) {
            try {
                $members = Get-ADGroupMember -Identity $groupName -ErrorAction SilentlyContinue
                foreach ($member in $members) {
                    $groupMembers += [PSCustomObject]@{
                        Group = $groupName
                        Member = $member.SamAccountName
                        Type = $member.objectClass
                    }
                }
            } catch {
                Write-Log "Could not enumerate group $groupName" "WARNING"
            }
        }
        $groupMembers | Export-Csv "$LogPath\Initial_ADGroupMembers.csv" -NoTypeInformation
    } else {
        Get-LocalGroup | ForEach-Object {
            $groupName = $_.Name
            Get-LocalGroupMember -Group $groupName -ErrorAction SilentlyContinue | 
                Select-Object @{N='Group';E={$groupName}}, Name, PrincipalSource
        } | Export-Csv "$LogPath\Initial_LocalGroupMembers.csv" -NoTypeInformation
    }
    
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

if ($isADEnvironment) {
    # In AD, Guest is usually already disabled, but check
    $DefaultAccounts = @('Guest')
    foreach ($account in $DefaultAccounts) {
        try {
            $user = Get-ADUser -Identity $account -ErrorAction SilentlyContinue
            if ($user -and $user.Enabled) {
                Disable-ADAccount -Identity $account
                Write-Log "Disabled AD account: $account" "SUCCESS"
            }
        } catch {
            Write-Log "Could not disable AD account $account : $_" "WARNING"
        }
    }
} else {
    # Local accounts
    $DefaultAccounts = @('Guest', 'DefaultAccount', 'WDAGUtilityAccount')
    foreach ($account in $DefaultAccounts) {
        try {
            $user = Get-LocalUser -Name $account -ErrorAction SilentlyContinue
            if ($user -and $user.Enabled) {
                Disable-LocalUser -Name $account
                Write-Log "Disabled local account: $account" "SUCCESS"
            }
        } catch {
            Write-Log "Could not disable local account $account : $_" "WARNING"
        }
    }
}

# ============================================
# 3. CREATE TEAM ADMIN ACCOUNT
# ============================================
Write-Host "`n[3] Creating team administrator account..." -ForegroundColor Yellow

try {
    $newAdmin = "${TeamName}_Admin"
    
    if ($isADEnvironment) {
        # Create AD user
        if (!(Get-ADUser -Filter "SamAccountName -eq '$newAdmin'" -ErrorAction SilentlyContinue)) {
            # Generate strong password
            Add-Type -AssemblyName 'System.Web'
            $strongPassword = [System.Web.Security.Membership]::GeneratePassword(20, 5)
            $securePassword = ConvertTo-SecureString $strongPassword -AsPlainText -Force
            
            # Create AD user
            New-ADUser -Name $newAdmin `
                -SamAccountName $newAdmin `
                -UserPrincipalName "$newAdmin@$domainName" `
                -AccountPassword $securePassword `
                -Enabled $true `
                -PasswordNeverExpires $false `
                -ChangePasswordAtLogon $false `
                -Description "CCDC Blue Team Administrator"
            
            # Add to Domain Admins
            Add-ADGroupMember -Identity "Domain Admins" -Members $newAdmin
            
            Write-Log "Created AD admin account: $newAdmin" "SUCCESS"
            
            # Display credentials in console ONLY
            Write-Host "`n============================================" -ForegroundColor Magenta
            Write-Host "NEW ADMIN CREDENTIALS - COPY NOW!" -ForegroundColor Magenta
            Write-Host "============================================" -ForegroundColor Magenta
            Write-Host "Domain: $domainName" -ForegroundColor Cyan
            Write-Host "Username: $newAdmin" -ForegroundColor Yellow
            Write-Host "Password: $strongPassword" -ForegroundColor Yellow
            Write-Host "============================================" -ForegroundColor Magenta
            Write-Host "Press Enter after copying..." -ForegroundColor Magenta
            Read-Host
        } else {
            Write-Log "AD admin account already exists: $newAdmin" "INFO"
        }
    } else {
        # Create local user
        if (!(Get-LocalUser -Name $newAdmin -ErrorAction SilentlyContinue)) {
            # Generate strong password
            Add-Type -AssemblyName 'System.Web'
            $strongPassword = [System.Web.Security.Membership]::GeneratePassword(20, 5)
            $securePassword = ConvertTo-SecureString $strongPassword -AsPlainText -Force
            
            New-LocalUser -Name $newAdmin -Password $securePassword -FullName "CCDC Team Admin" -Description "CCDC Blue Team Administrator"
            Add-LocalGroupMember -Group "Administrators" -Member $newAdmin
            
            Write-Log "Created local admin account: $newAdmin" "SUCCESS"
            
            # Display credentials in console ONLY
            Write-Host "`n============================================" -ForegroundColor Magenta
            Write-Host "NEW ADMIN CREDENTIALS - COPY NOW!" -ForegroundColor Magenta
            Write-Host "============================================" -ForegroundColor Magenta
            Write-Host "Username: $newAdmin" -ForegroundColor Yellow
            Write-Host "Password: $strongPassword" -ForegroundColor Yellow
            Write-Host "============================================" -ForegroundColor Magenta
            Write-Host "Press Enter after copying..." -ForegroundColor Magenta
            Read-Host
        }
    }
} catch {
    Write-Log "Error creating admin account: $_" "ERROR"
}

# ============================================
# 4. ENFORCE PASSWORD POLICY
# ============================================
Write-Host "`n[4] Enforcing password policy..." -ForegroundColor Yellow

try {
    if ($isADEnvironment) {
        # Set domain password policy (requires Domain Admin)
        try {
            Set-ADDefaultDomainPasswordPolicy -Identity $domainName `
                -MinPasswordLength 14 `
                -MaxPasswordAge "90.00:00:00" `
                -MinPasswordAge "1.00:00:00" `
                -PasswordHistoryCount 24 `
                -ComplexityEnabled $true `
                -LockoutThreshold 5 `
                -LockoutDuration "00:30:00" `
                -LockoutObservationWindow "00:30:00"
            Write-Log "Domain password policy updated" "SUCCESS"
        } catch {
            Write-Log "Could not update domain password policy (may need Domain Admin): $_" "WARNING"
        }
        
        # Ensure users don't have password never expires
        try {
            Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} | 
                Where-Object {$_.SamAccountName -notlike "*$TeamName*" -and $_.SamAccountName -ne "krbtgt"} | 
                ForEach-Object {
                    Set-ADUser $_ -PasswordNeverExpires $false
                    Write-Log "Removed PasswordNeverExpires for: $($_.SamAccountName)" "SUCCESS"
                }
        } catch {
            Write-Log "Error setting password expiration: $_" "WARNING"
        }
        
    } else {
        # Set local password policy using net accounts
        net accounts /minpwlen:14 /maxpwage:90 /minpwage:1 /uniquepw:5
        Write-Log "Local password policy updated" "SUCCESS"
        
        # Require all users to have password expiration
        Get-LocalUser | Where-Object {$_.Enabled -and $_.Name -notlike "*$TeamName*"} | ForEach-Object {
            try {
                $_ | Set-LocalUser -PasswordNeverExpires $false
                Write-Log "Set password expiration for: $($_.Name)" "SUCCESS"
            } catch {
                Write-Log "Could not set password policy for $($_.Name): $_" "WARNING"
            }
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
Write-Host "[*] Environment: $(if($isADEnvironment){"Active Directory ($domainName)"}else{"Local/Workgroup"})" -ForegroundColor Cyan
if ($isDomainController) {
    Write-Host "[*] Role: Domain Controller" -ForegroundColor Cyan
}
Write-Host "[*] Review logs at: $LogPath" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

Stop-Transcript
