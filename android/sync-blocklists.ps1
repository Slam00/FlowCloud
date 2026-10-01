$ErrorActionPreference = 'Stop'
$assets = Join-Path $PSScriptRoot 'app/src/main/assets'
New-Item -ItemType Directory -Force -Path $assets | Out-Null

$sources = @{
    'inside-raw.lst' = 'https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/inside-raw.lst'
    'block.lst' = 'https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Categories/block.lst'
    'geoblock.lst' = 'https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Categories/geoblock.lst'
    'telegram.lst' = 'https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Services/telegram.lst'
    'telegram-ipv4.lst' = 'https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Subnets/IPv4/telegram.lst'
    'telegram-ipv6.lst' = 'https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Subnets/IPv6/telegram.lst'
}

foreach ($entry in $sources.GetEnumerator()) {
    $destination = Join-Path $assets $entry.Key
    Invoke-WebRequest -UseBasicParsing -Uri $entry.Value -OutFile $destination
    if ((Get-Item -LiteralPath $destination).Length -lt 32) {
        throw "Downloaded blocklist is unexpectedly small: $($entry.Key)"
    }
}
