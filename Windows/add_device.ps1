# --- Configuration --- 
$domain = "YourDomain.local" # Replace with your AD domain 
$user = "YourDomain\Username" # Account with rights to join computers 
$password = "P@ssword!" # Plain text password (replace securely!) 
$ou = "OU=Computers,DC=YourDomain,DC=local" # Optional: target OU 
 
# --- Convert password to secure string --- 
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force 
 
# --- Create credential object --- 
$credential = New-Object System.Management.Automation.PSCredential ($user, $securePassword) 
 
# --- Check if already domain-joined --- 
$computerSystem = Get-WmiObject Win32_ComputerSystem 
if (-not $computerSystem.PartOfDomain) { 
Write-Host "Joining domain $domain..." 
Add-Computer -DomainName $domain -Credential $credential -OU $ou -Force -Verbose 
Write-Host "Restarting to complete domain join..." 
Restart-Computer -Force 
} else { 
Write-Host "Device is already domain-joined." 
}