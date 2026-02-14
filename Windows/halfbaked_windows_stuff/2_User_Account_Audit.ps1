#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC User Account Management & Auditing Script (AD & Local)
.DESCRIPTION
    Audits users, automatically resets passwords, and detects unauthorized accounts
    Works with Active Directory users (primary) and Local users (fallback)
    Passwords displayed ONLY in console - never written to files
.NOTES
    Run after initial hardening
    On Domain Controllers: Manages AD users
    On Domain Members: Manages AD users via domain
    On Workgroup: Manages local users
    
.EXAMPLE
    # Domain environment - reset AD user passwords
    .\2_User_Account_Audit.ps1 -AllowedUsers @('alice','bob','webadmin','sqlsvc') -AutoResetPasswords
    
.EXAMPLE
    # Domain environment - disable unauthorized AD users
    .\2_User_Account_Audit.ps1 -AllowedUsers @('alice','bob') -DisableUnauthorized
    
.EXAMPLE
    # Workgroup/standalone - manage local users
    .\2_User_Account_Audit.ps1 -AllowedUsers @('alice','bob') -AutoResetPasswords -LocalOnly
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\CCDC_Logs",
    
    [Parameter(Mandatory=$false)]
    [string[]]$AllowedUsers = @(),  # Scored users that must be kept
    
    [Parameter(Mandatory=$false)]
    [string[]]$OrganizerAccounts = @('Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount', 'krbtgt'),  # Don't change passwords
    
    [Parameter(Mandatory=$false)]
    [switch]$AutoResetPasswords,  # Automatically reset all allowed user passwords
    
    [Parameter(Mandatory=$false)]
    [switch]$DisableUnauthorized,  # Disable users not in allowed list
    
    [Parameter(Mandatory=$false)]
    [switch]$LocalOnly  # Force local user management (skip AD)
)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile = "$LogPath\UserAudit_$Timestamp.txt"

if (!(Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

function Write-Report {
    param([string]$Message, [string]$Level = "INFO")
    $output = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Add-Content -Path $ReportFile -Value $output
    
    $color = switch($Level) {
        "CRITICAL" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    Write-Host $output -ForegroundColor $color
}

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "CCDC User Account Audit & Management" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# ============================================
# DETERMINE ENVIRONMENT TYPE
# ============================================
$isADEnvironment = $false
$isDomainController = $false
$domainName = ""

if (-not $LocalOnly) {
    try {
        # Check if this is a domain-joined machine
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
        if ($computerSystem.PartOfDomain) {
            $isADEnvironment = $true
            $domainName = $computerSystem.Domain
            Write-Report "Detected domain environment: $domainName" "SUCCESS"
            
            # Check if this is a Domain Controller
            $domainRole = $computerSystem.DomainRole
            if ($domainRole -eq 4 -or $domainRole -eq 5) {
                $isDomainController = $true
                Write-Report "This machine is a Domain Controller" "SUCCESS"
            } else {
                Write-Report "This machine is a domain member" "INFO"
            }
            
            # Try to import AD module
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
                Write-Report "Active Directory module loaded" "SUCCESS"
            } catch {
                Write-Report "Active Directory module not available - cannot manage domain users!" "ERROR"
                Write-Host "[!] ERROR: Cannot manage AD users without AD module!" -ForegroundColor Red
                Write-Host "[!] Install RSAT or run on Domain Controller" -ForegroundColor Red
                exit 1
            }
        } else {
            Write-Report "Workgroup environment detected - will manage local users" "WARNING"
        }
    } catch {
        Write-Report "Could not determine domain status - defaulting to local users" "WARNING"
    }
}

if ($LocalOnly) {
    Write-Report "LocalOnly mode - managing local users only" "INFO"
}

# ============================================
# 1. ENUMERATE ALL USERS
# ============================================
Write-Host "`n[1] Enumerating all users..." -ForegroundColor Yellow

$allUsers = @()
$enabledUsers = @()
$disabledUsers = @()

if ($isADEnvironment) {
    # ACTIVE DIRECTORY USERS
    Write-Report "`n=== ACTIVE DIRECTORY USER ENUMERATION ==="
    
    try {
        $allUsers = Get-ADUser -Filter * -Properties Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, PasswordNotRequired, Description, MemberOf, adminCount
        $enabledUsers = $allUsers | Where-Object {$_.Enabled -eq $true}
        $disabledUsers = $allUsers | Where-Object {$_.Enabled -eq $false}
        
        Write-Report "Domain: $domainName"
        Write-Report "Total AD Users: $($allUsers.Count)"
        Write-Report "Enabled AD Users: $($enabledUsers.Count)" "WARNING"
        Write-Report "Disabled AD Users: $($disabledUsers.Count)"
        
        Write-Report "`n=== ENABLED AD USERS ==="
        foreach ($user in $enabledUsers) {
            $lastLogon = if ($user.LastLogonDate) { $user.LastLogonDate.ToString() } else { "Never" }
            $passwordAge = if ($user.PasswordLastSet) { 
                ((Get-Date) - $user.PasswordLastSet).Days 
            } else { 
                "Unknown" 
            }
            
            Write-Report "User: $($user.SamAccountName)"
            Write-Report "  - Name: $($user.Name)"
            Write-Report "  - DN: $($user.DistinguishedName)"
            Write-Report "  - Last Logon: $lastLogon"
            Write-Report "  - Password Last Set: $($user.PasswordLastSet)"
            Write-Report "  - Password Age (days): $passwordAge"
            Write-Report "  - Password Never Expires: $($user.PasswordNeverExpires)"
            Write-Report "  - Description: $($user.Description)"
            
            # Flag suspicious accounts
            if ($passwordAge -eq "Unknown" -or $passwordAge -gt 180) {
                Write-Report "  [!] WARNING: Old or never-changed password!" "WARNING"
            }
            if ($user.PasswordNeverExpires) {
                Write-Report "  [!] WARNING: Password never expires!" "WARNING"
            }
            if ($user.PasswordNotRequired) {
                Write-Report "  [!] CRITICAL: Password not required!" "CRITICAL"
            }
            if ($user.adminCount -eq 1) {
                Write-Report "  [!] NOTE: Has adminCount=1 (privileged account)" "WARNING"
            }
            if ($user.SamAccountName -match "admin|root|test|temp|svc") {
                Write-Report "  [!] SUSPICIOUS: Check if this account should exist!" "CRITICAL"
            }
        }
        
    } catch {
        Write-Report "Error enumerating AD users: $_" "ERROR"
        exit 1
    }
    
} else {
    # LOCAL USERS
    Write-Report "`n=== LOCAL USER ENUMERATION ==="
    
    $allUsers = Get-LocalUser
    $enabledUsers = $allUsers | Where-Object {$_.Enabled -eq $true}
    $disabledUsers = $allUsers | Where-Object {$_.Enabled -eq $false}
    
    Write-Report "Total Local Users: $($allUsers.Count)"
    Write-Report "Enabled Local Users: $($enabledUsers.Count)" "WARNING"
    Write-Report "Disabled Local Users: $($disabledUsers.Count)"
    
    Write-Report "`n=== ENABLED LOCAL USERS ==="
    foreach ($user in $enabledUsers) {
        $lastLogon = if ($user.LastLogon) { $user.LastLogon.ToString() } else { "Never" }
        $passwordAge = if ($user.PasswordLastSet) { 
            ((Get-Date) - $user.PasswordLastSet).Days 
        } else { 
            "Unknown" 
        }
        
        Write-Report "User: $($user.Name)"
        Write-Report "  - SID: $($user.SID)"
        Write-Report "  - Last Logon: $lastLogon"
        Write-Report "  - Password Last Set: $($user.PasswordLastSet)"
        Write-Report "  - Password Age (days): $passwordAge"
        Write-Report "  - Password Never Expires: $($user.PasswordNeverExpires)"
        Write-Report "  - Description: $($user.Description)"
        
        # Flag suspicious accounts
        if ($passwordAge -eq "Unknown" -or $passwordAge -gt 180) {
            Write-Report "  [!] WARNING: Old or never-changed password!" "WARNING"
        }
        if ($user.PasswordNeverExpires) {
            Write-Report "  [!] WARNING: Password never expires!" "WARNING"
        }
        if ($user.Name -match "admin|root|test|temp") {
            Write-Report "  [!] SUSPICIOUS: Check if this account should exist!" "CRITICAL"
        }
    }
}

# ============================================
# 2. ENUMERATE GROUP MEMBERSHIPS
# ============================================
Write-Host "`n[2] Checking privileged group memberships..." -ForegroundColor Yellow

Write-Report "`n=== PRIVILEGED GROUP MEMBERSHIPS ==="

if ($isADEnvironment) {
    # AD PRIVILEGED GROUPS
    $privilegedGroups = @(
        'Domain Admins',
        'Enterprise Admins',
        'Schema Admins',
        'Administrators',
        'Account Operators',
        'Backup Operators',
        'Server Operators',
        'Print Operators',
        'Group Policy Creator Owners',
        'DnsAdmins'
    )
    
    foreach ($groupName in $privilegedGroups) {
        try {
            $group = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue
            if ($group) {
                $members = Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction SilentlyContinue
                Write-Report "`nGroup: $groupName"
                if ($members) {
                    foreach ($member in $members) {
                        Write-Report "  - $($member.SamAccountName) ($($member.objectClass))"
                        
                        # Flag suspicious memberships
                        if ($member.SamAccountName -match "Guest|test|temp") {
                            Write-Report "    [!] CRITICAL: Suspicious account in privileged group!" "CRITICAL"
                        }
                    }
                } else {
                    Write-Report "  (No members)"
                }
            }
        } catch {
            Write-Report "  Could not access group $groupName" "WARNING"
        }
    }
    
} else {
    # LOCAL PRIVILEGED GROUPS
    $privilegedGroups = @('Administrators', 'Remote Desktop Users', 'Remote Management Users', 'Backup Operators', 'Server Operators')
    
    foreach ($group in $privilegedGroups) {
        try {
            $members = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue
            Write-Report "`nGroup: $group"
            if ($members) {
                foreach ($member in $members) {
                    Write-Report "  - $($member.Name) [$($member.PrincipalSource)]"
                    
                    # Flag suspicious memberships
                    if ($member.Name -match "Guest|DefaultAccount|test|temp") {
                        Write-Report "    [!] CRITICAL: Suspicious account in privileged group!" "CRITICAL"
                    }
                }
            } else {
                Write-Report "  (No members)"
            }
        } catch {
            Write-Report "  Error accessing group: $_" "WARNING"
        }
    }
}

# ============================================
# 3. IDENTIFY UNAUTHORIZED USERS
# ============================================
Write-Host "`n[3] Checking for unauthorized accounts..." -ForegroundColor Yellow

Write-Report "`n=== UNAUTHORIZED ACCOUNT DETECTION ==="

$unauthorizedUsers = @()

if ($AllowedUsers.Count -gt 0) {
    Write-Report "Allowed users: $($AllowedUsers -join ', ')"
    Write-Report "Organizer accounts (excluded): $($OrganizerAccounts -join ', ')"
    
    foreach ($user in $enabledUsers) {
        $username = if ($isADEnvironment) { $user.SamAccountName } else { $user.Name }
        
        # Skip organizer accounts
        if ($username -in $OrganizerAccounts) {
            Write-Report "SKIPPING: $username (organizer account)" "INFO"
            continue
        }
        
        # Check if user is in allowed list
        if ($username -notin $AllowedUsers) {
            $unauthorizedUsers += $user
            Write-Report "[!] UNAUTHORIZED: $username" "CRITICAL"
        }
    }
    
    if ($unauthorizedUsers.Count -gt 0) {
        Write-Host "`n" -NoNewline
        Write-Host "============================================" -ForegroundColor Red
        Write-Host "FOUND $($unauthorizedUsers.Count) UNAUTHORIZED USERS!" -ForegroundColor Red
        Write-Host "============================================" -ForegroundColor Red
        foreach ($user in $unauthorizedUsers) {
            $username = if ($isADEnvironment) { $user.SamAccountName } else { $user.Name }
            Write-Host "  - $username" -ForegroundColor Yellow
        }
        Write-Host "============================================" -ForegroundColor Red
        
        if ($DisableUnauthorized) {
            Write-Host "`nDisabling unauthorized users..." -ForegroundColor Yellow
            foreach ($user in $unauthorizedUsers) {
                $username = if ($isADEnvironment) { $user.SamAccountName } else { $user.Name }
                try {
                    if ($isADEnvironment) {
                        Disable-ADAccount -Identity $user.SamAccountName
                    } else {
                        Disable-LocalUser -Name $user.Name
                    }
                    Write-Report "DISABLED: $username" "SUCCESS"
                    Write-Host "[+] Disabled: $username" -ForegroundColor Green
                } catch {
                    Write-Report "Failed to disable $username : $_" "ERROR"
                }
            }
        }
    } else {
        Write-Report "All enabled users are authorized" "SUCCESS"
    }
} else {
    Write-Report "No allowed user list provided - skipping authorization check" "WARNING"
    Write-Host "[!] WARNING: No allowed user list provided. Use -AllowedUsers parameter" -ForegroundColor Yellow
}

# ============================================
# 4. CHECK PASSWORD POLICIES
# ============================================
Write-Host "`n[4] Checking password policies..." -ForegroundColor Yellow

Write-Report "`n=== PASSWORD POLICY CHECK ==="

if ($isADEnvironment) {
    try {
        $passwordPolicy = Get-ADDefaultDomainPasswordPolicy
        
        Write-Report "Domain Password Policy:"
        Write-Report "  Minimum Password Length: $($passwordPolicy.MinPasswordLength)"
        Write-Report "  Password History Count: $($passwordPolicy.PasswordHistoryCount)"
        Write-Report "  Max Password Age: $($passwordPolicy.MaxPasswordAge.Days) days"
        Write-Report "  Min Password Age: $($passwordPolicy.MinPasswordAge.Days) days"
        Write-Report "  Lockout Threshold: $($passwordPolicy.LockoutThreshold)"
        Write-Report "  Lockout Duration: $($passwordPolicy.LockoutDuration.Minutes) minutes"
        
        # Flag weak policies
        if ($passwordPolicy.MinPasswordLength -lt 14) {
            Write-Report "[!] WARNING: Minimum password length is less than 14!" "WARNING"
        }
        if ($passwordPolicy.LockoutThreshold -eq 0) {
            Write-Report "[!] WARNING: Account lockout is disabled!" "WARNING"
        }
    } catch {
        Write-Report "Error checking domain password policy: $_" "WARNING"
    }
} else {
    try {
        $netAccounts = net accounts
        Write-Report ($netAccounts -join "`n")
        
        # Check for weak policies
        if ($netAccounts -match "Minimum password length:\s+(\d+)") {
            $minLength = [int]$matches[1]
            if ($minLength -lt 14) {
                Write-Report "[!] WARNING: Minimum password length is less than 14 characters!" "WARNING"
            }
        }
    } catch {
        Write-Report "Error checking password policy: $_" "WARNING"
    }
}

# ============================================
# 5. DETECT ACCOUNTS WITH SUSPICIOUS ATTRIBUTES
# ============================================
Write-Host "`n[5] Detecting suspicious account attributes..." -ForegroundColor Yellow

Write-Report "`n=== SUSPICIOUS ACCOUNT DETECTION ==="

foreach ($user in $allUsers) {
    $suspicious = @()
    $username = if ($isADEnvironment) { $user.SamAccountName } else { $user.Name }
    
    # Never logged on but enabled
    if ($user.Enabled) {
        $lastLogon = if ($isADEnvironment) { $user.LastLogonDate } else { $user.LastLogon }
        if (-not $lastLogon) {
            $suspicious += "Never logged on but enabled"
        }
    }
    
    # Password never expires
    if ($user.PasswordNeverExpires) {
        $suspicious += "Password never expires"
    }
    
    # Password not required (AD only)
    if ($isADEnvironment -and $user.PasswordNotRequired) {
        $suspicious += "Password not required"
    }
    
    # Suspicious names
    if ($username -match "admin\$|test|temp|backup|svc|service") {
        $suspicious += "Suspicious naming pattern"
    }
    
    if ($suspicious.Count -gt 0) {
        Write-Report "`n[!] SUSPICIOUS: $username" "CRITICAL"
        foreach ($issue in $suspicious) {
            Write-Report "    - $issue" "CRITICAL"
        }
    }
}

# ============================================
# 6. AUTOMATIC PASSWORD RESET
# ============================================
if ($AutoResetPasswords) {
    Write-Host "`n[6] Resetting passwords for allowed users..." -ForegroundColor Yellow
    Write-Report "`n=== AUTOMATIC PASSWORD RESET ==="
    
    if ($AllowedUsers.Count -eq 0) {
        Write-Host "[!] ERROR: Cannot reset passwords without an allowed user list!" -ForegroundColor Red
        Write-Report "Password reset skipped - no allowed user list provided" "ERROR"
    } else {
        Add-Type -AssemblyName 'System.Web'
        
        # Store credentials for console output ONLY
        $newCredentials = @()
        
        foreach ($user in $enabledUsers) {
            $username = if ($isADEnvironment) { $user.SamAccountName } else { $user.Name }
            
            # Skip organizer accounts
            if ($username -in $OrganizerAccounts) {
                Write-Report "Skipping organizer account: $username" "INFO"
                continue
            }
            
            # Only reset allowed users
            if ($username -in $AllowedUsers) {
                # Generate strong password
                $newPassword = [System.Web.Security.Membership]::GeneratePassword(16, 4)
                $securePass = ConvertTo-SecureString $newPassword -AsPlainText -Force
                
                try {
                    if ($isADEnvironment) {
                        # AD user password reset
                        Set-ADAccountPassword -Identity $user.SamAccountName -NewPassword $securePass -Reset
                        # Force password change at next logon (optional - comment out if not desired)
                        # Set-ADUser -Identity $user.SamAccountName -ChangePasswordAtLogon $false
                    } else {
                        # Local user password reset
                        Set-LocalUser -Name $user.Name -Password $securePass
                    }
                    
                    $newCredentials += [PSCustomObject]@{
                        Username = $username
                        Password = $newPassword
                    }
                    Write-Report "Password reset for: $username" "SUCCESS"
                } catch {
                    Write-Report "Failed to reset password for $username : $_" "ERROR"
                }
            } else {
                Write-Report "Skipping unauthorized user: $username" "WARNING"
            }
        }
        
        # Display credentials in console for manual copying
        # SECURITY: NO FILE OUTPUT - ONLY CONSOLE (assume attacker has keylogger/screen access)
        if ($newCredentials.Count -gt 0) {
            Write-Host "`n" -NoNewline
            Write-Host "============================================" -ForegroundColor Magenta
            Write-Host "NEW USER CREDENTIALS - COPY NOW!" -ForegroundColor Magenta
            Write-Host "============================================" -ForegroundColor Magenta
            
            if ($isADEnvironment) {
                Write-Host "Domain: $domainName" -ForegroundColor Cyan
            } else {
                Write-Host "Local Machine: $env:COMPUTERNAME" -ForegroundColor Cyan
            }
            
            Write-Host "============================================" -ForegroundColor Magenta
            
            foreach ($cred in $newCredentials) {
                Write-Host "$($cred.Username) : $($cred.Password)" -ForegroundColor Yellow
            }
            
            Write-Host "============================================" -ForegroundColor Magenta
            Write-Host "Credentials shown in console only (not saved to file)" -ForegroundColor Cyan
            Write-Host "Press Enter after copying all credentials..." -ForegroundColor Magenta
            Read-Host
        }
    }
}

# ============================================
# 7. CREATE BASELINE
# ============================================
Write-Host "`n[7] Creating user baseline..." -ForegroundColor Yellow

$userList = @()
if ($isADEnvironment) {
    $userList = $allUsers | Select-Object SamAccountName, Name, Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, DistinguishedName
} else {
    $userList = $allUsers | Select-Object Name, SID, Enabled, LastLogon, PasswordLastSet, PasswordNeverExpires
}

$baseline = @{
    Timestamp = Get-Date
    Environment = if ($isADEnvironment) { "Active Directory" } else { "Local/Workgroup" }
    Domain = $domainName
    IsDomainController = $isDomainController
    TotalUsers = $allUsers.Count
    EnabledUsers = $enabledUsers.Count
    UnauthorizedCount = $unauthorizedUsers.Count
    AllowedUsers = $AllowedUsers
    Users = $userList
}

$baseline | ConvertTo-Json -Depth 3 | Out-File "$LogPath\UserBaseline_$Timestamp.json"
Write-Report "Baseline saved to: $LogPath\UserBaseline_$Timestamp.json" "SUCCESS"

# ============================================
# SUMMARY
# ============================================
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "User Audit Complete!" -ForegroundColor Green
Write-Host "Report saved to: $ReportFile" -ForegroundColor Cyan

if ($isADEnvironment) {
    Write-Host "Environment: Active Directory ($domainName)" -ForegroundColor Cyan
    if ($isDomainController) {
        Write-Host "Role: Domain Controller" -ForegroundColor Cyan
    }
} else {
    Write-Host "Environment: Local/Workgroup" -ForegroundColor Cyan
}

if ($unauthorizedUsers.Count -gt 0) {
    Write-Host "Unauthorized Users: $($unauthorizedUsers.Count)" -ForegroundColor Red
    Write-Host "Users not in allowed list:" -ForegroundColor Red
    foreach ($user in $unauthorizedUsers) {
        $username = if ($isADEnvironment) { $user.SamAccountName } else { $user.Name }
        Write-Host "  - $username" -ForegroundColor Yellow
    }
}
Write-Host "============================================" -ForegroundColor Cyan
