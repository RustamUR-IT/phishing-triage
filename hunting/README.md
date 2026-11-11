# Hunt: what happens after the attachment is opened

`phishtriage` looks at the mail. This hunt looks at the endpoint for the next step of the same
attack. In [`samples/attachment_phish.eml`](../samples/attachment_phish.eml), `Lieferschein_0117.pdf`
is really a ZIP that contains `Lieferschein_0117.js`. If the user opens it, what does that
look like in the process telemetry, and can we find it?

The hunt comes with a harmless simulation of the attack for your own lab VM. You run it, export
the Sysmon events, and run the hunt against them. That tests the query with real Windows telemetry
instead of only against data written to fit the query.

## Hypothesis

> A user opened a script delivered by mail or download. Explorer, Outlook, an archiver or a
> browser starts `wscript.exe`, `cscript.exe` or `mshta.exe` on a file in Downloads, in the Temp
> folder that ZIP/RAR/7z extract to, or in the Outlook attachment cache. The script then starts
> a shell, PowerShell or a download/proxy-execution binary.

| Stage | Rule | ATT&CK |
|---|---|---|
| 1. User runs the script | [`script_host_from_user_location.yml`](sigma/script_host_from_user_location.yml) (high) | T1204.002 User Execution: Malicious File, T1059.005/.007 VBScript/JScript, T1218.005 Mshta, T1566.001 |
| 2. Script hands off | [`script_host_spawns_lolbin.yml`](sigma/script_host_spawns_lolbin.yml) (medium) | T1059.001 PowerShell, T1059.003 Windows Command Shell, T1218, T1105 |

Each stage on its own is noisy (see [Tuning](#tuning-and-false-positives)). Together they make a
strong signal. Stage 1 is linked to stage 2 by Sysmon's `ProcessGuid` → `ParentProcessGuid`, and
by `DeviceId` + PID + process start time in Defender. A PID on its own is reused, so it is not
enough to link the two.

**Data source:** process creation, Sysmon Event ID 1 (or Defender `DeviceProcessEvents`). The
fields used are `Image`, `OriginalFileName`, `CommandLine`, `ParentImage`, `ProcessGuid`,
`ParentProcessGuid`.

## Files

| Path | What |
|---|---|
| [`sigma/`](sigma/) | The two rules in Sigma: the reference version of the logic |
| [`queries/splunk.spl`](queries/splunk.spl) | The same hunt for Splunk (Sysmon add-on), stage 1 with its stage-2 children joined on |
| [`queries/defender_xdr.kql`](queries/defender_xdr.kql) | The same hunt for Defender XDR advanced hunting / Sentinel |
| [`simulation/Invoke-PhishChainSim.ps1`](simulation/Invoke-PhishChainSim.ps1) | Harmless attack simulation for the lab VM, exports the events at the end |
| [`simulation/Export-SysmonEvents.ps1`](simulation/Export-SysmonEvents.ps1) | Sysmon log → JSONL (also on its own, for example to record a baseline) |
| [`hunt.py`](hunt.py) | Offline runner: applies the Sigma rules to the JSONL file and prints the chains |
| [`testdata/`](testdata/) | Synthetic Sysmon events (attack + benign baseline) for the unit tests and CI |

## Lab setup

1. **VM.** Windows 10/11 (for example the free Windows evaluation VM from Microsoft) on a
   host-only or NAT network. Take a **snapshot** before the test.
2. **Sysmon.** Download it from Sysinternals and install it with a community config, e.g.
   [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) or
   [sysmon-modular](https://github.com/olafhartong/sysmon-modular):
   ```powershell
   .\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
   ```
   Check: `Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5`
3. **Repo on the VM** (or only the `hunting/simulation/` folder). Python + PyYAML is only needed
   where you run `hunt.py`. That can be your host; just copy the JSONL file over.
4. Leave Defender on. If it blocks the simulation, that is a result as well; note it.

## Running the test

Open an elevated PowerShell in `hunting/simulation`:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Invoke-PhishChainSim.ps1 -Mode Manual -MarkOfTheWeb -OutFile C:\lab\run1.jsonl
```

- `-Mode Manual` (the most realistic): Explorer opens the ZIP and you double-click the `.js`
  yourself. Explorer extracts it to `%TEMP%\Temp1_Lieferschein_0117.zip\`, as it would for a
  real victim.
- `-Mode Auto` (default, repeatable): extracts to `Downloads\phishtriage-sim\` and starts the
  `.js` through `explorer.exe`.
- The "payload" only writes the date and `whoami /all` to `%TEMP%\phishtriage-sim-marker.txt`.
  It does no network access, no persistence and no registry changes.

Then, on the VM or on the host:

```bash
python hunting/hunt.py C:/lab/run1.jsonl --expect-chain
```

`--expect-chain` exits with 1 if no complete stage 1 → stage 2 chain is found. Expected result
(shown here for the synthetic test data in `testdata/simulated_attack.jsonl`):

```text
Chains (stage 1 -> stage 2, linked by ProcessGuid)
  2026-11-11 09:02:14.311  LAB-WIN11\analyst  explorer.exe -> wscript.exe
    "C:\Windows\System32\WScript.exe" "C:\Users\analyst\AppData\Local\Temp\Temp1_Lieferschein_0117.zip\Liefersche…
    └─ powershell.exe: powershell.exe -NoProfile -WindowStyle Hidden -Command "Get-Date | Out-File -Encoding ascii $env:TE…
    └─ cmd.exe: "C:\Windows\System32\cmd.exe" /c whoami /all >> "C:\Users\analyst\AppData\Local\Temp\phishtriage-si…
```

**Negative test:** use the VM normally for a while (browse, unpack ZIPs, run admin scripts),
export with `.\Export-SysmonEvents.ps1 -Since (Get-Date).AddHours(-2) -OutFile C:\lab\baseline.jsonl`
and run `hunt.py` again. Any stage-1 hit there is a false positive you need to handle in the rule.

Clean up afterwards with `.\Invoke-PhishChainSim.ps1 -Cleanup`, or revert to the snapshot.

## Results from my own VM

> Fill this in after your run. Only record what you actually observed.

| | Run 1 (Manual + MotW) | Run 2 (Auto) | Baseline |
|---|---|---|---|
| Date / Windows build | | | |
| Sysmon version / config | | | |
| Security prompt (MotW) shown? | | n/a | n/a |
| Defender reaction | | | |
| Stage-1 hits | | | |
| Stage-2 children in the chain | | | |
| `--expect-chain` exit code | | | |
| False positives / rule change needed | | | |

## Tuning and false positives

- **Stage 2 alone** fires on VBS logon scripts (`\\domain\NETLOGON\*.vbs` → `cmd.exe /c net use`).
  The benign test data contains this case on purpose. In a real environment, exclude the
  `ParentCommandLine` that contains `\NETLOGON\` or `\SYSVOL\`, or only alert on chains.
- **Stage 1** fires when admins or power users start their own `.vbs`/`.js` from Downloads.
  Allowlist known script hashes (`Hashes` field) or the user, not the path.
- **Paths:** newer Windows 11 builds with the built-in archive support may extract to a
  different Temp subfolder. The rule matches all of `\AppData\Local\Temp\`, but only together
  with the parent process. Check the actual path in your manual run and write it into the table.
- **Blind spots:** scripts started by a scheduled task or a WMI consumer (different parent),
  renamed script hosts outside the paths (caught partly through `OriginalFileName`), LNK → cmd →
  wscript chains (parent `cmd.exe`), and HTA started straight from a URL.

## Limits

- The simulation tests the **detection logic and the telemetry pipeline** (does Sysmon log what
  the rule expects, does the rule fire, do the stages link up?). It does not test resistance
  against a real attacker who obfuscates on purpose, uses other script hosts or avoids the
  parent-child relationship.
- `hunt.py` implements only the subset of Sigma these rules need (modifiers
  `contains`/`startswith`/`endswith`/`all`/`re`, conditions with `and`/`or`/`not`/`1 of`/`all of`).
  For a SIEM, convert the rules with [sigma-cli](https://github.com/SigmaHQ/sigma-cli) or use the
  hand-written queries in `queries/`.
- The Splunk and KQL queries follow the same logic but were not run in this repository against
  a live Splunk or Defender tenant.
