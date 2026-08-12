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

if ($Meta) {
    Get-NetRoute -InterfaceAlias $Meta.device -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    $Adapter = Get-NetAdapter -Name $Meta.device -ErrorAction SilentlyContinue
    if ($Adapter -and (Test-Path (Join-Path $InstallDir 'tapctl.exe'))) {
        & (Join-Path $InstallDir 'tapctl.exe') delete $Adapter.InterfaceGuid | Out-Null
    }
}

Remove-Item -Recurse -Force $InstallDir, $ConfigDir -ErrorAction SilentlyContinue
Write-Host 'WSN removed; the shared TAP-Windows driver was retained'
