<#
.SYNOPSIS
    Exports Sysmon events as JSON Lines (one flat object per event) for hunting/hunt.py.

.DESCRIPTION
    Each line holds EventID, Computer and every EventData field under its Sysmon name
    (Image, CommandLine, ProcessGuid, ParentImage, ...). Events are written oldest first,
    UTF-8 without BOM. Needs an elevated PowerShell to read the Sysmon log.

.EXAMPLE
    .\Export-SysmonEvents.ps1 -Since (Get-Date).AddMinutes(-30) -OutFile C:\lab\baseline.jsonl
    .\Export-SysmonEvents.ps1 -Since '2026-11-11 09:00' -EventId 1,3,11
#>
[CmdletBinding()]
param(
    [datetime]$Since = (Get-Date).AddHours(-1),
    [int[]]$EventId = @(1),
    [string]$OutFile = (Join-Path -Path (Get-Location) -ChildPath 'sysmon-events.jsonl')
)

$ErrorActionPreference = 'Stop'

$filter = @{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'
    StartTime = $Since
    Id        = $EventId
}

try {
    $events = @(Get-WinEvent -FilterHashtable $filter | Sort-Object -Property RecordId)
}
catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $events = @() } else { throw }
}

$lines = foreach ($e in $events) {
    $xml = [xml]$e.ToXml()
    $row = [ordered]@{ EventID = $e.Id; Computer = $e.MachineName }
    foreach ($d in $xml.Event.EventData.Data) { $row[$d.Name] = $d.InnerText }
    $row | ConvertTo-Json -Compress
}

# Resolve relative to the PowerShell location (not the process working directory).
$OutFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
[IO.File]::WriteAllLines($OutFile, [string[]]@($lines | Where-Object { $_ }))
Write-Host "Exported $($events.Count) Sysmon event(s) since $Since to $OutFile"
