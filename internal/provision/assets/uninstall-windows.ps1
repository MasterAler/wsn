#Requires -RunAsAdministrator
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$InstallDir = Join-Path $env:ProgramFiles 'WSN'
$ConfigDir = Join-Path $env:ProgramData 'WSN'
$MetaPath = Join-Path $ConfigDir 'bundle.json'
$Meta = if (Test-Path $MetaPath) { Get-Content -Raw $MetaPath | ConvertFrom-Json } else { $null }

if (Get-Service -Name 'WSNClient' -ErrorAction SilentlyContinue) {
    Stop-Service -Name 'WSNClient' -Force -ErrorAction SilentlyContinue
    & sc.exe delete WSNClient | Out-Null
}

Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
    Where-Object { $_.Comment -eq 'WSN' } |
    ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction SilentlyContinue }

if ($Meta) {
    Get-NetRoute -InterfaceAlias $Meta.device -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    # The installer writes routes with route.exe -p, which stores them outside
    # the active table; Remove-NetRoute above does not reach those.
    foreach ($Route in $Meta.routes) { & route.exe delete $Route.Split('/')[0] | Out-Null }
    $Adapter = Get-NetAdapter -Name $Meta.device -ErrorAction SilentlyContinue
    if ($Adapter -and (Test-Path (Join-Path $InstallDir 'tapctl.exe'))) {
        & (Join-Path $InstallDir 'tapctl.exe') delete $Adapter.InterfaceGuid | Out-Null
    }
}

Remove-Item -Recurse -Force $InstallDir, $ConfigDir -ErrorAction SilentlyContinue
Write-Host 'WSN removed; the shared TAP-Windows driver was retained'
