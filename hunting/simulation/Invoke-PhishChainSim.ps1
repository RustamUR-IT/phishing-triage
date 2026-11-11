<#
.SYNOPSIS
    Benign simulation of the attachment-phishing execution chain hunted in hunting/sigma/.

.DESCRIPTION
    Reproduces the behaviour behind samples/attachment_phish.eml on a lab VM, without
    any malicious code:

      1. Builds Lieferschein_0117.zip in your Downloads folder with Lieferschein_0117.js.
      2. Explorer starts the .js with wscript.exe            (stage 1, ATT&CK T1204.002 / T1059.007)
      3. The script starts PowerShell and cmd.exe            (stage 2, ATT&CK T1059.001 / T1059.003)
         Both only write the date and "whoami /all" to %TEMP%\phishtriage-sim-marker.txt.
      4. Exports the Sysmon events of the run to JSONL for hunting/hunt.py.

    No network access, no persistence, no registry changes. Run it only on a VM you own,
    ideally from a snapshot. Requires Sysmon and an elevated PowerShell (for the export).

.PARAMETER Mode
    Auto   (default) extracts the ZIP to Downloads\phishtriage-sim and starts the .js via explorer.exe.
    Manual opens the ZIP in Explorer; you double-click the .js yourself. This is the most realistic
    variant: Explorer extracts to %TEMP%\Temp1_Lieferschein_0117.zip\ like for a real victim.

.PARAMETER MarkOfTheWeb
    Tags the ZIP as downloaded from the Internet (Zone.Identifier ZoneId=3). Windows may then show
    a security prompt before running the script, which is what a real user would see.

.PARAMETER Cleanup
    Removes every file the simulation created and exits.

.EXAMPLE
    .\Invoke-PhishChainSim.ps1
    .\Invoke-PhishChainSim.ps1 -Mode Manual -MarkOfTheWeb -OutFile C:\lab\run2.jsonl
    .\Invoke-PhishChainSim.ps1 -Cleanup
#>
[CmdletBinding()]
param(
    [ValidateSet('Auto', 'Manual')]
    [string]$Mode = 'Auto',
    [string]$OutFile = (Join-Path -Path (Get-Location) -ChildPath 'sim-events.jsonl'),
    [switch]$MarkOfTheWeb,
    [switch]$Cleanup
)

$ErrorActionPreference = 'Stop'

$Downloads = Join-Path $env:USERPROFILE 'Downloads'
$ZipPath   = Join-Path $Downloads 'Lieferschein_0117.zip'
$WorkDir   = Join-Path $Downloads 'phishtriage-sim'
$StageDir  = Join-Path $env:TEMP 'phishtriage-sim-stage'
$Marker    = Join-Path $env:TEMP 'phishtriage-sim-marker.txt'
$Extracted = Join-Path $env:TEMP 'Temp1_Lieferschein_0117.zip'

if ($Cleanup) {
    foreach ($p in $ZipPath, $WorkDir, $StageDir, $Marker, $Extracted) {
        if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force }
    }
    Write-Host 'Simulation files removed.'
    return
}

# --- preflight -------------------------------------------------------------------------------
$sysmon = Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue |
    Where-Object { $_.Status -eq 'Running' }
if (-not $sysmon) { throw 'Sysmon is not running on this machine. See hunting/README.md, "Lab setup".' }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Run this from an elevated PowerShell: reading the Sysmon log needs admin rights.' }

# --- build the lure --------------------------------------------------------------------------
# Benign stand-in for a JScript dropper. Same process tree as the real thing, harmless actions.
$payload = @'
// phishtriage hunt simulation - BENIGN. Writes the date and "whoami /all" to
// %TEMP%\phishtriage-sim-marker.txt. No network, no persistence.
var sh = new ActiveXObject("WScript.Shell");
sh.Run('powershell.exe -NoProfile -WindowStyle Hidden -Command "Get-Date | Out-File -Encoding ascii $env:TEMP\\phishtriage-sim-marker.txt"', 0, true);
sh.Run('cmd.exe /c whoami /all >> "%TEMP%\\phishtriage-sim-marker.txt"', 0, true);
'@

foreach ($p in $ZipPath, $WorkDir, $StageDir, $Marker, $Extracted) {
    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force }
}
New-Item -ItemType Directory -Path $StageDir | Out-Null
$jsStage = Join-Path $StageDir 'Lieferschein_0117.js'
Set-Content -LiteralPath $jsStage -Value $payload -Encoding Ascii
Compress-Archive -LiteralPath $jsStage -DestinationPath $ZipPath -Force
Remove-Item -LiteralPath $StageDir -Recurse -Force

if ($MarkOfTheWeb) {
    Set-Content -LiteralPath $ZipPath -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`r`nZoneId=3"
}

# Small margin so events of this run are not cut off by clock granularity.
$start = (Get-Date).AddSeconds(-5)
Write-Host "Lure created: $ZipPath"

# --- detonate (benign) ------------------------------------------------------------------------
if ($Mode -eq 'Auto') {
    Expand-Archive -LiteralPath $ZipPath -DestinationPath $WorkDir -Force
    $js = Join-Path $WorkDir 'Lieferschein_0117.js'
    # explorer.exe opens the file with its default handler (wscript.exe), so the parent process
    # is explorer.exe, as when a user double-clicks.
    Start-Process -FilePath 'explorer.exe' -ArgumentList "`"$js`""
}
else {
    Start-Process -FilePath 'explorer.exe' -ArgumentList "`"$ZipPath`""
    Write-Host ''
    Write-Host 'In the Explorer window that just opened, double-click Lieferschein_0117.js.'
    Write-Host '(If Windows shows a security warning, click Open: that is part of the scenario.)'
    Read-Host 'Press Enter here once you have done that'
}

$deadline = (Get-Date).AddSeconds(30)
while (-not (Test-Path -LiteralPath $Marker) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 1 }
if (Test-Path -LiteralPath $Marker) {
    Write-Host "Payload ran, marker written: $Marker"
}
else {
    Write-Warning ('No marker after 30 s. The script did not run or was blocked ' +
        '(check Defender protection history: a block is a detection too). Exporting anyway.')
}

# Give Sysmon a moment to write the last events.
Start-Sleep -Seconds 3

# --- export ------------------------------------------------------------------------------------
& (Join-Path $PSScriptRoot 'Export-SysmonEvents.ps1') -Since $start -OutFile $OutFile
Write-Host ''
Write-Host 'Next: python hunting/hunt.py' $OutFile '--expect-chain'
Write-Host 'Clean up afterwards with: .\Invoke-PhishChainSim.ps1 -Cleanup'
