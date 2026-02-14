#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC User Account Management & Auditing Script
.DESCRIPTION
    Audits users, automatically resets passwords, and detects unauthorized accounts
.NOTES
    Run after initial hardening
    Passwords are ONLY displayed in console - never written to files
    
.EXAMPLE
    # Basic audit with allowed user list
    .\2_User_Account_Audit.ps1 -AllowedUsers @('alice','bob','webadmin','sqladmin')
    
.EXAMPLE
    # Auto-reset passwords for allowed users (console output only)
    .\2_User_Account_Audit.ps1 -AllowedUsers @('alice','bob') -OrganizerAccounts @('Administrator','ccdc_admin') -AutoResetPasswords
    
.EXAMPLE  
    # Disable unauthorized users
    .\2_User_Account_Audit.ps1 -AllowedUsers @('alice','bob') -DisableUnauthorized -AutoResetPasswords
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\CCDC_Logs",
    
    [Parameter(Mandatory=$false)]
    [string[]]$AllowedUsers = @(),  # Scored users that must be kept
    
    [Parameter(Mandatory=$false)]
    [string[]]$OrganizerAccounts = @('Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount'),  # Don't change passwords
    
    [Parameter(Mandatory=$false)]
    [switch]$AutoResetPasswords,  # Automatically reset all allowed user passwords
    
    [Parameter(Mandatory=$false)]
    [switch]$DisableUnauthorized  # Disable users not in allowed list
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
# 1. ENUMERATE ALL USERS
# ============================================
Write-Host "`n[1] Enumerating all local users..." -ForegroundColor Yellow

$allUsers = Get-LocalUser
$enabledUsers = $allUsers | Where-Object {$_.Enabled -eq $true}
$disabledUsers = $allUsers | Where-Object {$_.Enabled -eq $false}

Write-Report "Total Users: $($allUsers.Count)"
Write-Report "Enabled Users: $($enabledUsers.Count)" "WARNING"
Write-Report "Disabled Users: $($disabledUsers.Count)"

Write-Report "`n=== ENABLED USERS ==="
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

# ============================================
# 2. ENUMERATE GROUP MEMBERSHIPS
# ============================================
Write-Host "`n[2] Checking privileged group memberships..." -ForegroundColor Yellow

$privilegedGroups = @('Administrators', 'Remote Desktop Users', 'Remote Management Users', 'Backup Operators', 'Server Operators')

Write-Report "`n=== PRIVILEGED GROUP MEMBERSHIPS ==="
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
        # Skip organizer accounts
        if ($user.Name -in $OrganizerAccounts) {
            Write-Report "SKIPPING: $($user.Name) (organizer account)" "INFO"
            continue
        }
        
        # Check if user is in allowed list
        if ($user.Name -notin $AllowedUsers) {
            $unauthorizedUsers += $user
            Write-Report "[!] UNAUTHORIZED: $($user.Name)" "CRITICAL"
        }
    }
    
    if ($unauthorizedUsers.Count -gt 0) {
        Write-Host "`n" -NoNewline
        Write-Host "============================================" -ForegroundColor Red
        Write-Host "FOUND $($unauthorizedUsers.Count) UNAUTHORIZED USERS!" -ForegroundColor Red
        Write-Host "============================================" -ForegroundColor Red
        foreach ($user in $unauthorizedUsers) {
            Write-Host "  - $($user.Name)" -ForegroundColor Yellow
        }
        Write-Host "============================================" -ForegroundColor Red
        
        if ($DisableUnauthorized) {
            Write-Host "`nDisabling unauthorized users..." -ForegroundColor Yellow
            foreach ($user in $unauthorizedUsers) {
                try {
                    Disable-LocalUser -Name $user.Name
                    Write-Report "DISABLED: $($user.Name)" "SUCCESS"
                    Write-Host "[+] Disabled: $($user.Name)" -ForegroundColor Green
                } catch {
                    Write-Report "Failed to disable $($user.Name): $_" "ERROR"
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
# 4. CHECK FOR HIDDEN ADMIN ACCOUNTS
# ============================================
Write-Host "`n[4] Checking for hidden administrator accounts..." -ForegroundColor Yellow

Write-Report "`n=== CHECKING FOR BACKDOOR ADMIN ACCOUNTS ==="

# Check for accounts with SID ending in 500 (built-in admin)
$adminAccount = Get-LocalUser | Where-Object {$_.SID -like "*-500"}
if ($adminAccount) {
    Write-Report "Built-in Administrator account:"
    Write-Report "  Name: $($adminAccount.Name)"
    Write-Report "  Enabled: $($adminAccount.Enabled)"
    if ($adminAccount.Enabled) {
        Write-Report "  [!] WARNING: Built-in admin is enabled!" "WARNING"
    }
}

# Check all administrator group members
$admins = Get-LocalGroupMember -Group "Administrators"
Write-Report "`nAll Administrators:"
foreach ($admin in $admins) {
    Write-Report "  - $($admin.Name) [$($admin.ObjectClass)]"
}

# ============================================
# 5. CHECK PASSWORD POLICIES
# ============================================
Write-Host "`n[5] Checking password policies..." -ForegroundColor Yellow

Write-Report "`n=== PASSWORD POLICY CHECK ==="
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

# ============================================
# 6. DETECT ACCOUNTS WITH SUSPICIOUS ATTRIBUTES
# ============================================
Write-Host "`n[6] Detecting suspicious account attributes..." -ForegroundColor Yellow

Write-Report "`n=== SUSPICIOUS ACCOUNT DETECTION ==="

foreach ($user in $allUsers) {
    $suspicious = @()
    
    # Never logged on but enabled
    if ($user.Enabled -and !$user.LastLogon) {
        $suspicious += "Never logged on but enabled"
    }
    
    # Password never expires
    if ($user.PasswordNeverExpires) {
        $suspicious += "Password never expires"
    }
    
    # Password not required
    if ($user.PasswordRequired -eq $false) {
        $suspicious += "Password not required"
    }
    
    # Account locked out
    if ($user.LockedOut) {
        $suspicious += "Account is locked out"
    }
    
    # Suspicious names
    if ($user.Name -match "admin\$|test|temp|backup|svc|service") {
        $suspicious += "Suspicious naming pattern"
    }
    
    if ($suspicious.Count -gt 0) {
        Write-Report "`n[!] SUSPICIOUS: $($user.Name)" "CRITICAL"
        foreach ($issue in $suspicious) {
            Write-Report "    - $issue" "CRITICAL"
        }
    }
}

# ============================================
# 7. AUTOMATIC PASSWORD RESET
# ============================================
if ($AutoResetPasswords) {
    Write-Host "`n[7] Resetting passwords for allowed users..." -ForegroundColor Yellow
    Write-Report "`n=== AUTOMATIC PASSWORD RESET ==="
    
    if ($AllowedUsers.Count -eq 0) {
        Write-Host "[!] ERROR: Cannot reset passwords without an allowed user list!" -ForegroundColor Red
        Write-Report "Password reset skipped - no allowed user list provided" "ERROR"
    } else {
        Add-Type -AssemblyName 'System.Web'
        
        # Store credentials for console output ONLY
        $newCredentials = @()
        
        foreach ($user in $enabledUsers) {
            # Skip organizer accounts
            if ($user.Name -in $OrganizerAccounts) {
                Write-Report "Skipping organizer account: $($user.Name)" "INFO"
                continue
            }
            
            # Only reset allowed users
            if ($user.Name -in $AllowedUsers) {
                # Generate strong password
                $newPassword = [System.Web.Security.Membership]::GeneratePassword(16, 4)
                $securePass = ConvertTo-SecureString $newPassword -AsPlainText -Force
                
                try {
                    Set-LocalUser -Name $user.Name -Password $securePass
                    $newCredentials += [PSCustomObject]@{
                        Username = $user.Name
                        Password = $newPassword
                    }
                    Write-Report "Password reset for: $($user.Name)" "SUCCESS"
                } catch {
                    Write-Report "Failed to reset password for $($user.Name): $_" "ERROR"
                }
            } else {
                Write-Report "Skipping unauthorized user: $($user.Name)" "WARNING"
            }
        }
        
        # Display credentials in console for manual copying
        # SECURITY: NO FILE OUTPUT - ONLY CONSOLE (assume attacker has keylogger/screen access)
        if ($newCredentials.Count -gt 0) {
            Write-Host "`n" -NoNewline
            Write-Host "============================================" -ForegroundColor Magenta
            Write-Host "NEW USER CREDENTIALS - COPY NOW!" -ForegroundColor Magenta
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
# 8. CREATE BASELINE
# ============================================
Write-Host "`n[8] Creating user baseline..." -ForegroundColor Yellow

$baseline = @{
    Timestamp = Get-Date
    TotalUsers = $allUsers.Count
    EnabledUsers = $enabledUsers.Count
    Administrators = (Get-LocalGroupMember -Group "Administrators").Count
    UnauthorizedCount = $unauthorizedUsers.Count
    AllowedUsers = $AllowedUsers
    Users = $allUsers | Select-Object Name, SID, Enabled, LastLogon, PasswordLastSet, PasswordNeverExpires
}

$baseline | ConvertTo-Json -Depth 3 | Out-File "$LogPath\UserBaseline_$Timestamp.json"
Write-Report "Baseline saved to: $LogPath\UserBaseline_$Timestamp.json" "SUCCESS"

# ============================================
# SUMMARY
# ============================================
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "User Audit Complete!" -ForegroundColor Green
Write-Host "Report saved to: $ReportFile" -ForegroundColor Cyan
if ($unauthorizedUsers.Count -gt 0) {
    Write-Host "Unauthorized Users: $($unauthorizedUsers.Count)" -ForegroundColor Red
    Write-Host "Users not in allowed list:" -ForegroundColor Red
    foreach ($user in $unauthorizedUsers) {
        Write-Host "  - $($user.Name)" -ForegroundColor Yellow
    }
}
Write-Host "============================================" -ForegroundColor Cyan
