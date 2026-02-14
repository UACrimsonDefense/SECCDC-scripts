param (
    [string]$URL
)

Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "","127.0.0.1 $URL"
