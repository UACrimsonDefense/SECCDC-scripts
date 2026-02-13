# Replace with AD domain controller IP(s) 
$dnsServers = @("192.168.1.10","192.168.1.11")  
 
Write-Output "Configuring DNS servers..." 
Get-NetAdapter | ForEach-Object { 
Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses $dnsServers 
} 
 
Write-Output "Testing DNS resolution..." 
try { 
$result = Resolve-DnsName YourDomain.local -ErrorAction Stop 
Write-Output "DNS resolution succeeded:" 
$result | Format-Table -AutoSize 
} catch { 
Write-Output "DNS resolution FAILED: $_" 
} 
 
Write-Output "DNS configuration complete." 