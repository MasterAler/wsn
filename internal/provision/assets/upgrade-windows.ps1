#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Binary,
    [Parameter(Mandatory=$true)][string]$Sha256
)

$ErrorActionPreference = 'Stop'
$Target = Join-Path $env:ProgramFiles 'WSN\wsn-client.exe'
$Previous = Join-Path $env:ProgramFiles 'WSN\wsn-client.previous.exe'
$Actual = (Get-FileHash -Algorithm SHA256 $Binary).Hash.ToLowerInvariant()
if ($Actual -ne $Sha256.ToLowerInvariant()) { throw 'SHA-256 mismatch' }

Stop-Service WSNClient -Force
Copy-Item $Target $Previous -Force
Copy-Item $Binary $Target -Force
try {
    Start-Service WSNClient
    Start-Sleep -Seconds 2
    if ((Get-Service WSNClient).Status -ne 'Running') { throw 'service stopped after upgrade' }
} catch {
    Copy-Item $Previous $Target -Force
    Start-Service WSNClient
    throw 'Upgrade failed; previous binary restored'
}
Write-Host 'WSN client upgraded'
