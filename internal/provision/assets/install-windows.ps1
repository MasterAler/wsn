#Requires -RunAsAdministrator
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$Bundle = Split-Path -Parent $MyInvocation.MyCommand.Path
$Meta = Get-Content -Raw (Join-Path $Bundle 'bundle.json') | ConvertFrom-Json
$InstallDir = Join-Path $env:ProgramFiles 'WSN'
$ConfigDir = Join-Path $env:ProgramData 'WSN'
$ServiceName = 'WSNClient'

if (-not [Environment]::Is64BitOperatingSystem) {
    throw 'WSN supports only 64-bit Windows'
}

function Assert-Hash([string]$Path, [string]$Expected) {
    $Actual = (Get-FileHash -Algorithm SHA256 $Path).Hash.ToLowerInvariant()
    if ($Actual -ne $Expected.ToLowerInvariant()) {
        throw "SHA-256 mismatch for $Path"
    }
}

function Convert-IPv4([string]$Address) {
    $Bytes = [Net.IPAddress]::Parse($Address).GetAddressBytes()
    [Array]::Reverse($Bytes)
    return [BitConverter]::ToUInt32($Bytes, 0)
}

function Get-CidrRange([string]$Cidr) {
    $Parts = $Cidr.Split('/')
    $Prefix = [int]$Parts[1]
    $Address = [uint64](Convert-IPv4 $Parts[0])
    $Mask = if ($Prefix -eq 0) { [uint64]0 } else { (([uint64]0xffffffff) -shl (32 - $Prefix)) -band [uint64]0xffffffff }
    $Start = $Address -band $Mask
    $End = $Start + ([uint64]0xffffffff - $Mask)
    return @($Start, $End)
}

function Test-CidrOverlap([string]$Left, [string]$Right) {
    $A = Get-CidrRange $Left
    $B = Get-CidrRange $Right
    return ($A[0] -le $B[1] -and $B[0] -le $A[1])
}

function Assert-NoRouteConflict([string]$Prefix) {
    foreach ($Route in Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue) {
        if ($Route.DestinationPrefix -eq '0.0.0.0/0' -or $Route.InterfaceAlias -eq $Meta.device) { continue }
        if (Test-CidrOverlap $Prefix $Route.DestinationPrefix) {
            throw "$Prefix overlaps existing route $($Route.DestinationPrefix) on $($Route.InterfaceAlias)"
        }
    }
}

Assert-Hash (Join-Path $Bundle 'wsn-client.exe') $Meta.client_sha256
Assert-Hash (Join-Path $Bundle 'tap-driver.exe') $Meta.tap_driver_sha256
Assert-Hash (Join-Path $Bundle 'tapctl.exe') $Meta.tapctl_sha256

$Signature = Get-AuthenticodeSignature (Join-Path $Bundle 'tap-driver.exe')
if ($Signature.Status -ne 'Valid' -or $Signature.SignerCertificate.Subject -notmatch 'OpenVPN') {
    throw 'The TAP driver must have a valid OpenVPN Authenticode signature'
}

$Existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($Existing) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $ServiceName | Out-Null
    for ($Attempt = 0; $Attempt -lt 30 -and (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue); $Attempt++) {
        Start-Sleep -Milliseconds 200
    }
}
$ExistingAdapter = Get-NetAdapter -Name $Meta.device -ErrorAction SilentlyContinue
if ($ExistingAdapter) {
    Get-NetRoute -InterfaceAlias $Meta.device -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    & (Join-Path $Bundle 'tapctl.exe') delete $ExistingAdapter.InterfaceGuid | Out-Null
}
Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
    Where-Object { $_.Comment -eq 'WSN' } |
    ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction SilentlyContinue }

Assert-NoRouteConflict $Meta.overlay
foreach ($Route in $Meta.routes) { Assert-NoRouteConflict $Route }

$DriverProcess = Start-Process -FilePath (Join-Path $Bundle 'tap-driver.exe') -ArgumentList '/S' -Wait -PassThru
if ($DriverProcess.ExitCode -ne 0) { throw "TAP driver installer exited with code $($DriverProcess.ExitCode)" }
New-Item -ItemType Directory -Force -Path $InstallDir, $ConfigDir | Out-Null

$SystemAccount = (New-Object Security.Principal.SecurityIdentifier('S-1-5-18')).Translate([Security.Principal.NTAccount]).Value
$Administrators = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([Security.Principal.NTAccount]).Value
$Acl = Get-Acl $ConfigDir
$Acl.SetAccessRuleProtection($true, $false)
$Acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($SystemAccount,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
$Acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($Administrators,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
Set-Acl -Path $ConfigDir -AclObject $Acl

Copy-Item (Join-Path $Bundle 'wsn-client.exe') (Join-Path $InstallDir 'wsn-client.exe') -Force
Copy-Item (Join-Path $Bundle 'tapctl.exe') (Join-Path $InstallDir 'tapctl.exe') -Force
Copy-Item (Join-Path $Bundle 'client.json') $ConfigDir -Force
Copy-Item (Join-Path $Bundle 'client.key') $ConfigDir -Force
Copy-Item (Join-Path $Bundle 'relay-ca.crt') $ConfigDir -Force
Copy-Item (Join-Path $Bundle 'bundle.json') $ConfigDir -Force

& (Join-Path $InstallDir 'tapctl.exe') create --name $Meta.device | Out-Null
if ($LASTEXITCODE -ne 0) { throw "tapctl failed to create adapter $($Meta.device)" }
$Adapter = Get-NetAdapter -Name $Meta.device
Set-NetAdapter -Name $Meta.device -MacAddress ($Meta.mac -replace ':','') -Confirm:$false
# The overlay carries IPv4 only.
Disable-NetAdapterBinding -Name $Meta.device -ComponentID 'ms_tcpip6' -ErrorAction SilentlyContinue
Enable-NetAdapter -Name $Meta.device -Confirm:$false

$AddressParts = $Meta.address.Split('/')
New-NetIPAddress -InterfaceAlias $Meta.device -IPAddress $AddressParts[0] -PrefixLength ([int]$AddressParts[1]) | Out-Null
Set-NetIPInterface -InterfaceAlias $Meta.device -AddressFamily IPv4 -InterfaceMetric 5 -Dhcp Disabled
foreach ($Route in $Meta.routes) {
    New-NetRoute -DestinationPrefix $Route -InterfaceAlias $Meta.device -NextHop $Meta.gateway -RouteMetric 5 -PolicyStore PersistentStore | Out-Null
}

# Split DNS. An NRPT rule sends only the listed namespaces to the corporate
# resolver; every other lookup keeps using the resolvers this machine already
# had, so home and cafe networks continue to work normally.
if ($Meta.dns -and $Meta.search) {
    foreach ($Domain in $Meta.search) {
        Add-DnsClientNrptRule -Namespace ".$Domain" -NameServers $Meta.dns -Comment 'WSN' | Out-Null
    }
}

$BinaryPath = '"{0}" -config "{1}"' -f (Join-Path $InstallDir 'wsn-client.exe'), (Join-Path $ConfigDir 'client.json')
New-Service -Name $ServiceName -BinaryPathName $BinaryPath -DisplayName 'WSN v2 Client' -StartupType Automatic | Out-Null
& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
Start-Service -Name $ServiceName

Write-Host "Relay CA public-key fingerprint: $($Meta.ca_sha256)"
Write-Host 'Confirm it matches the value your administrator published.'
Write-Host 'WSN installation complete'
