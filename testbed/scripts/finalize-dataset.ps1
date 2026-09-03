#Requires -Version 5.1
param(
    [string]$DatasetRoot = "$PSScriptRoot/../../dataset_v3_5_final",
    [int]$RunsPerCell = 3,
    [string]$T15ProfileVersion = "3.5-v2"
)

$ErrorActionPreference = "Stop"
$DatasetRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DatasetRoot)
$required = @("capture.pcap", "metadata.json", "features.json", "swanctl-before.txt", "swanctl-after.txt", "xfrm-state.txt", "xfrm-policy.txt", "tcpdump-summary.txt", "run.log", "PASS.txt")
$profiles = @("icmp", "web", "voip-like", "video-like")

$candidates = @()
foreach ($scenarioDir in Get-ChildItem -LiteralPath $DatasetRoot -Directory) {
    foreach ($runDir in Get-ChildItem -LiteralPath $scenarioDir.FullName -Directory) {
        $metaPath = Join-Path $runDir.FullName "metadata.json"
        if (-not (Test-Path -LiteralPath $metaPath)) { continue }
        try { $meta = Get-Content -LiteralPath $metaPath -Raw | ConvertFrom-Json } catch { continue }
        $traffic = [string]$meta.traffic_ground_truth.traffic_class
        $profileVersion = [string]$meta.traffic_ground_truth.profile_version
        $complete = $true
        foreach ($name in $required) { if (-not (Test-Path -LiteralPath (Join-Path $runDir.FullName $name))) { $complete = $false; break } }
        # Keep artifact-complete runs here; validate-dataset.ps1 owns packet-quality checks.
        $expectedProfileVersion = if ($scenarioDir.Name -eq "T15") { $T15ProfileVersion } else { "3.5-v1" }
        if ($scenarioDir.Name -notmatch '^T\d{2}$' -or $traffic -notin $profiles -or $profileVersion -ne $expectedProfileVersion) { $complete = $false }
        if ($complete) {
            $candidates += [pscustomobject]@{ Scenario = $scenarioDir.Name; Traffic = $traffic; Run = $runDir; Timestamp = [string]$meta.run.timestamp }
        }
    }
}

$keep = @()
foreach ($scenario in ($candidates.Scenario | Sort-Object -Unique)) {
    foreach ($traffic in $profiles) {
        $cell = @($candidates | Where-Object { $_.Scenario -eq $scenario -and $_.Traffic -eq $traffic } | Sort-Object Timestamp, @{Expression={$_.Run.Name}} -Descending)
        if ($cell.Count -lt $RunsPerCell) { throw "$scenario/$traffic has only $($cell.Count) valid runs" }
        $keep += $cell | Select-Object -First $RunsPerCell
    }
}

$keepPaths = @($keep | ForEach-Object { $_.Run.FullName })
foreach ($scenarioDir in Get-ChildItem -LiteralPath $DatasetRoot -Directory) {
    foreach ($runDir in Get-ChildItem -LiteralPath $scenarioDir.FullName -Directory) {
        if ($keepPaths -notcontains $runDir.FullName) {
            Remove-Item -LiteralPath $runDir.FullName -Recurse -Force
        }
    }
}

$remaining = @($keep)
$expected = 15 * $profiles.Count * $RunsPerCell
if ($remaining.Count -ne $expected) { throw "Finalized $($remaining.Count) runs; expected $expected" }
Write-Host "Finalized $($remaining.Count) valid runs in $DatasetRoot" -ForegroundColor Green
