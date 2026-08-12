#Requires -RunAsAdministrator
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$Target = Join-Path $env:ProgramFiles 'WSN\wsn-client.exe'
$Previous = Join-Path $env:ProgramFiles 'WSN\wsn-client.previous.exe'
if (-not (Test-Path $Previous)) { throw 'No previous binary is available' }

Stop-Service WSNClient -Force
$Temporary = Join-Path $env:TEMP 'wsn-client.rollback.exe'
Move-Item $Target $Temporary -Force
Move-Item $Previous $Target -Force
Move-Item $Temporary $Previous -Force
Start-Service WSNClient
Write-Host 'WSN client rolled back'
