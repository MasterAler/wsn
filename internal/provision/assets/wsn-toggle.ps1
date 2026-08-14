#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Brings the WSN tunnel up or down on this machine.

.DESCRIPTION
    Stopping WSNClient on its own does not hand the machine back to its normal
    networking. The installer adds the corporate routes to the persistent store
    and creates NRPT rules that are global rather than bound to the adapter, so
    both outlive the service: traffic to corporate CIDRs black-holes into a dead
    TAP, and lookups for the deployment's domains keep going to a resolver that
    is no longer reachable.

    -Off therefore stops the service, drops the NRPT rules, and disables the
    adapter, which takes its routes out of the active store while leaving them
    in the persistent store. -On puts all three back, reading the resolver and
    search domains from the installed bundle.json so it stays correct if the
    client is ever re-enrolled.

    With no switch it reports the current state.

.EXAMPLE
    .\wsn-toggle.ps1 -Off

.EXAMPLE
    .\wsn-toggle.ps1 -On
#>
[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
    [Parameter(Mandatory, ParameterSetName = 'On')][switch]$On,
    [Parameter(Mandatory, ParameterSetName = 'Off')][switch]$Off
)

$ErrorActionPreference = 'Stop'

$ConfigDir   = Join-Path $env:ProgramData 'WSN'
$ServiceName = 'WSNClient'
$MetaPath    = Join-Path $ConfigDir 'bundle.json'

if (-not (Test-Path $MetaPath)) {
    throw "$MetaPath not found; WSN does not look installed on this machine"
}
$Meta   = Get-Content -Raw $MetaPath | ConvertFrom-Json
$Device = $Meta.device

function Remove-WsnNrpt {
    Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
        Where-Object { $_.Comment -eq 'WSN' } |
        ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction SilentlyContinue }
}

function Add-WsnNrpt {
    # A deployment without split DNS has neither value; there is nothing to add.
    if (-not ($Meta.dns -and $Meta.search)) { return }
    # Clear first, or repeated -On calls stack a duplicate rule per domain.
    Remove-WsnNrpt
    foreach ($Domain in $Meta.search) {
        Add-DnsClientNrptRule -Namespace ".$Domain" -NameServers $Meta.dns -Comment 'WSN' | Out-Null
    }
}

function Get-MissingRoute {
    return @($Meta.routes | Where-Object {
        -not (Get-NetRoute -InterfaceAlias $Device -DestinationPrefix $_ -ErrorAction SilentlyContinue)
    })
}

function Show-WsnStatus {
    $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $Adapter = Get-NetAdapter -Name $Device -ErrorAction SilentlyContinue
    $Rules   = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Comment -eq 'WSN' })
    $Total   = @($Meta.routes).Count
    $Active  = $Total - (Get-MissingRoute).Count

    $ServiceText = if ($Service) { '{0} ({1} start)' -f $Service.Status, $Service.StartType } else { 'not installed' }
    $AdapterText = if ($Adapter) { $Adapter.Status } else { 'missing' }

    Write-Host ''
    Write-Host ('  service    {0}' -f $ServiceText)
    Write-Host ('  adapter    {0}  [{1}]' -f $AdapterText, $Device)
    Write-Host ('  routes     {0} of {1} active' -f $Active, $Total)
    Write-Host ('  split DNS  {0} NRPT rule(s)' -f $Rules.Count)
    Write-Host ''
}

if ($Off) {
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Stop-Service -Name $ServiceName -Force
        # Manual, so the tunnel stays down across a reboot instead of coming up
        # against a disabled adapter and retrying on the service recovery timer.
        Set-Service -Name $ServiceName -StartupType Manual
    }
    Remove-WsnNrpt
    if (Get-NetAdapter -Name $Device -ErrorAction SilentlyContinue) {
        Disable-NetAdapter -Name $Device -Confirm:$false
    }
    Write-Host 'WSN off: corporate routes inactive, split DNS removed.'
    Show-WsnStatus
    return
}

if ($On) {
    $Adapter = Get-NetAdapter -Name $Device -ErrorAction SilentlyContinue
    if (-not $Adapter) {
        throw "adapter $Device not found; reinstall the client bundle"
    }
    if ($Adapter.Status -eq 'Disabled') {
        Enable-NetAdapter -Name $Device -Confirm:$false
        for ($Attempt = 0; $Attempt -lt 50 -and (Get-NetAdapter -Name $Device).Status -eq 'Disabled'; $Attempt++) {
            Start-Sleep -Milliseconds 200
        }
    }

    Add-WsnNrpt
    Set-Service -Name $ServiceName -StartupType Automatic
    Start-Service -Name $ServiceName

    # Persistent routes return only once the interface is genuinely up, which
    # trails the service by a moment. A tunnel that connects with no routes
    # looks healthy and reaches nothing, so check rather than assume.
    $Missing = @()
    for ($Attempt = 0; $Attempt -lt 25; $Attempt++) {
        $Missing = Get-MissingRoute
        if ($Missing.Count -eq 0) { break }
        Start-Sleep -Milliseconds 200
    }
    if ($Missing.Count -gt 0) {
        Write-Warning ('routes not active on {0}: {1}' -f $Device, ($Missing -join ', '))
        Write-Warning 'reinstall the client bundle if they do not appear'
    }

    Write-Host 'WSN on.'
    Show-WsnStatus
    return
}

Show-WsnStatus
