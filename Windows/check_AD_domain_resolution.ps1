$domain = "YourDomain.local" 
 
Write-Host "Running pre-checks for domain join to $domain..." 
Write-Host "" 
 
# 1. Check current DNS servers 
Write-Host "Checking DNS configuration..." 
Get-DnsClientServerAddress | Select-Object -ExpandProperty ServerAddresses 
 
# 2. Test DNS resolution of the domain 
Write-Host "`nTesting DNS resolution for $domain..." 
try { 
$dnsResult = Resolve-DnsName $domain -ErrorAction Stop 
Write-Host "DNS resolution succeeded:" 
$dnsResult | Format-Table -AutoSize 
} catch { 
Write-Host "DNS resolution FAILED: $_" 
} 
 
# 3. Check domain controller discovery 
Write-Host "`nChecking for reachable domain controllers..." 
$dcInfo = nltest /dsgetdc:$domain 
if ($LASTEXITCODE -eq 0) { 
Write-Host "Domain controller found:" 
Write-Host $dcInfo 
} else { 
Write-Host "Domain controller discovery FAILED." 
} 
 
# 4. Test network connectivity to DC ports (example: LDAP 389, Kerberos 88)
Write-Host "`nTesting connectivity to domain controllers..." 
$dcName = (nltest /dsgetdc:$domain | Select-String "DC:").ToString().Split()[1] 
if ($dcName) { 
Write-Host "Testing connectivity to $dcName..." 
Test-NetConnection -ComputerName $dcName -Port 389 # LDAP 
Test-NetConnection -ComputerName $dcName -Port 88 # Kerberos 
Test-NetConnection -ComputerName $dcName -Port 445 # SMB 
} else { 
Write-Host "No domain controller name available for port tests." 
} 
 
Write-Host "`nPre-check complete."