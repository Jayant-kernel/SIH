#Requires -Version 5.1
<# Demo helper: analyzes representative scenarios, generates sample reports,
   and optionally starts the dashboard. Read-only with respect to dataset/captures. #>
param([switch]$StartDashboard)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot | Split-Path
Set-Location $root

docker info *> $null
if ($LASTEXITCODE -ne 0) { Write-Host "Docker is not running. Start Docker Desktop first." -ForegroundColor Red; exit 1 }
Write-Host "[OK] Docker is running"

$runs = [ordered]@{
  "T04-strong-esp" = "dataset_v3_5_v2_full/T04/20260903-143933-601"
  "T03-no-pfs"     = "dataset_v3_5_v2_full/T03/20260903-143508-869"
  "T08-ah"         = "dataset_v3_5_v2_full/T08/20260903-145854-163"
  "T15-corrected"  = "dataset_v3_5_v2_full/T15/20260903-173651-525"
}

Write-Host "`n=== Generating unified analyses (Phase 6 pipeline reuses Phase 4 + Phase 5) ==="
$analyses = @()
foreach ($name in $runs.Keys) {
  $out = "integration/results/demo_$($name -replace '-.*','')_result.json"
  $analyses += $out
  docker run --rm -v "${root}:/work" -w /work python:3.11 sh -c "pip install --disable-pip-version-check -q -r requirements.txt; python integration/analyze.py --run $($runs[$name]) --output $out" | Out-Null
  if (Test-Path $out) { Write-Host "[OK] $name -> $out" } else { Write-Host "[FAIL] $name" -ForegroundColor Red }
}

Write-Host "`n=== Passive-only analysis (PCAP without metadata/XFRM) ==="
$passive = "integration/results/demo_passive_result.json"
docker run --rm -v "${root}:/work" -w /work python:3.11 sh -c "pip install --disable-pip-version-check -q -r requirements.txt; python integration/analyze.py --pcap dataset_v3_5_v2_full/T15/20260903-173651-525/capture.pcap --output $passive" | Out-Null
if (Test-Path $passive) { Write-Host "[OK] passive-only -> $passive" } else { Write-Host "[FAIL] passive-only" -ForegroundColor Red }

Write-Host "`n=== Generating executive/technical reports ==="
$analyses += $passive
foreach ($json in $analyses) {
  $stem = "demo_" + (Split-Path $json -Leaf).Replace("_result.json","")
  docker run --rm -v "${root}:/work" -w /work python:3.11 python reports/generate_report.py --input $json --out reports/results | Out-Null
  Write-Host "[OK] reports/results/${stem}*"
}

Write-Host "`n=== Dashboard ==="
if ($StartDashboard) {
  docker rm -f sih-demo-dashboard 2>$null | Out-Null
  docker run -d --name sih-demo-dashboard -p 127.0.0.1:8501:8501 -v "${root}:/work" -w /work python:3.11 sh -c "pip install --disable-pip-version-check -q -r requirements.txt; python -u app/app.py --host 0.0.0.0 --port 8501" | Out-Null
  Write-Host "Dashboard starting: http://127.0.0.1:8501  (stop with: docker rm -f sih-demo-dashboard)"
  Write-Host "Paste these into the dashboard (container paths):"
  $runs.Values | ForEach-Object { Write-Host "  run : /work/$_" }
  Write-Host "  pcap: /work/dataset_v3_5_v2_full/T15/20260903-173651-525/capture.pcap"
} else {
  Write-Host "Launch later with:  python app/app.py"
  Write-Host "Dashboard URLs to paste (container paths if containerized):"
  $runs.Values | ForEach-Object { Write-Host "  run : $_" }
  Write-Host "  pcap: dataset_v3_5_v2_full/T15/20260903-173651-525/capture.pcap"
}
Write-Host "`nDemo artifacts are under integration/results/ and reports/results/. No dataset or capture was modified."
