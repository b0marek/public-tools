$domain = (Get-CimInstance Win32_ComputerSystem).Domain

Write-Host "Domena: $domain"
Write-Host ""

# DNS domeny
$dnsRecords = Resolve-DnsName $domain -Type A -ErrorAction SilentlyContinue

if (-not $dnsRecords) {
    Write-Host "Nie znaleziono rekordu A dla domeny." -ForegroundColor Yellow
    exit
}

$ips = $dnsRecords |
    Where-Object { $_.IPAddress } |
    Select-Object -ExpandProperty IPAddress -Unique

# Porty typowe dla AD/SMB
$ports = @{
    53   = "DNS"
    88   = "Kerberos"
    135  = "RPC"
    139  = "NetBIOS"
    389  = "LDAP"
    445  = "SMB"
    464  = "Kerberos Password"
    636  = "LDAPS"
    3268 = "Global Catalog"
    3269 = "Global Catalog SSL"
}

foreach ($ip in $ips) {

    Write-Host "================================"
    Write-Host "IP: $ip"
    Write-Host "================================"

    # Ping
    if (Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue) {
        Write-Host "[+] PING: OK" -ForegroundColor Green
    }
    else {
        Write-Host "[-] PING: brak odpowiedzi" -ForegroundColor Yellow
    }

    # Porty
    foreach ($port in $ports.Keys | Sort-Object) {

        $result = Test-NetConnection `
            -ComputerName $ip `
            -Port $port `
            -InformationLevel Quiet `
            -WarningAction SilentlyContinue

        if ($result) {
            Write-Host "[+] TCP $port`t$($ports[$port])`tOPEN" -ForegroundColor Green
        }
        else {
            Write-Host "[-] TCP $port`t$($ports[$port])`tCLOSED/FILTERED"
        }
    }

    Write-Host ""
}
