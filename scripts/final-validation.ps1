#Requires -Version 5.1
<# Final validation suite. Verifies dataset integrity, Phase 4 artifacts/CLI,
   Phase 5 tests and scenario validation, Phase 6 tests, dashboard startup/HTTP,
   and report generation. Read-only for dataset/captures/models. #>
param()
$ErrorActionPreference = "Continue"
$root = $PSScriptRoot | Split-Path
Set-Location $root
$script:failures = 0
function Check($name, $ok) {
  if ($ok) { Write-Host "[PASS] $name" -ForegroundColor Green }
  else { Write-Host "[FAIL] $name" -ForegroundColor Red; $script:failures++ }
}

Write-Host "=== Final Validation Suite ===" -ForegroundColor Cyan

# ---------------- Dataset ----------------
Write-Host "--- Dataset 3.5-v2 ---"
$rows = Import-Csv "dataset_exports_v2/traffic_features.csv"
Check "dataset rows = 180" ($rows.Count -eq 180)
foreach ($c in @("icmp","web","voip-like","video-like")) {
  Check "class $c = 45 rows" (@($rows | Where-Object traffic_class -eq $c).Count -eq 45)
}
Check "15 scenarios" (@($rows | Select-Object -ExpandProperty group_scenario_id -Unique).Count -eq 15)
$t15meta = Get-ChildItem "dataset_v3_5_v2_full/T15" -Directory | ForEach-Object {
  (Get-Content (Join-Path $_.FullName "metadata.json") -Raw | ConvertFrom-Json).traffic_ground_truth.profile_version
}
Check "T15 has 12 runs" (@(Get-ChildItem "dataset_v3_5_v2_full/T15" -Directory).Count -eq 12)
Check "T15 runs are profile 3.5-v2" (@($t15meta | Where-Object { $_ -ne "3.5-v2" }).Count -eq 0)

# ---------------- Phase 4 ----------------
Write-Host "--- Phase 4 ML ---"
$p4 = docker run --rm -v "${root}:/work" -w /work python:3.11 sh -c "pip install --disable-pip-version-check -q numpy scipy scikit-learn joblib scapy; python scripts/phase4_check.py"
$p4text = $p4 -join "`n"
Check "Phase 4 model loads, schema class order, 36 features, dataset 3.5-v2" (($p4text -match "SCHEMA_CLASSES \['icmp', 'web', 'voip-like', 'video-like'\]") -and ($p4text -match "CLASS_SET_MATCH True") -and ($p4text -match "NFEATURES 36") -and ($p4text -match "DATASET 3\.5-v2"))
Check "Phase 4 output probabilities aligned to schema order" ($p4text -match "PREDICT_OK True")
Check "Phase 4 empty-PCAP -> unknown / 0.25" ($p4text -match "PHASE4-UNKNOWN-OK True")

# ---------------- Phase 5 ----------------
Write-Host "--- Phase 5 Security Engine ---"
$p5 = docker run --rm -v "${root}:/work" -w /work python:3.11 sh -c "python -m unittest discover -s security/tests 2>&1; python security/generate_artifacts.py"
Check "Phase 5 unit tests pass" (($p5 -join "`n") -match "OK")
$summary = Get-Content "security/results/phase5_summary.json" -Raw | ConvertFrom-Json
Check "Phase 5 T01-T15 validation verdict PASS" ($summary.verdict -eq "PASS" -and $summary.scenarios -eq 15)

# ---------------- Phase 6 ----------------
Write-Host "--- Phase 6 Integration ---"
$p6 = docker run --rm -v "${root}:/work" -w /work python:3.11 sh -c "pip install --disable-pip-version-check -q -r requirements.txt; python -m unittest discover -s integration/tests 2>&1; python integration/generate_validation.py"
Check "Phase 6 integration tests pass" (($p6 -join "`n") -match "OK")
Check "Phase 6 validation artifacts exist" ((Test-Path "integration/results/t15_result.json") -and (Test-Path "integration/results/passive_only_result.json"))

Write-Host "--- Dashboard ---"
docker rm -f sih-finalval-dashboard 2>$null | Out-Null
$dashOk = $false; $titleOk = $false
foreach ($attempt in 1..3) {
  docker run -d --name sih-finalval-dashboard -p 127.0.0.1:8502:8501 -v "${root}:/work" -w /work python:3.11 sh -c "pip install --disable-pip-version-check -q --retries 5 -r requirements.txt; python -u app/app.py --host 0.0.0.0 --port 8501" | Out-Null
  foreach ($i in 1..30) {
    Start-Sleep -Seconds 5
    try {
      $r = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:8502/" -TimeoutSec 5
      if ($r.StatusCode -eq 200) { $dashOk = $true; $titleOk = ($r.Content -match "AI-Driven IPsec VPN Security Analyzer"); break }
    } catch { }
  }
  if ($dashOk) { break }
  Write-Host "  dashboard attempt $attempt failed; container logs:" -ForegroundColor Yellow
  docker logs sih-finalval-dashboard 2>&1 | Select-Object -Last 3 | ForEach-Object { Write-Host "    $_" }
  docker rm -f sih-finalval-dashboard | Out-Null
}
Check "dashboard startup + HTTP 200" $dashOk
Check "dashboard page title correct" $titleOk
docker rm -f sih-finalval-dashboard 2>$null | Out-Null

Write-Host "--- Reports ---"
docker run --rm -v "${root}:/work" -w /work python:3.11 python reports/generate_report.py --input integration/results/t15_result.json --out reports/results --stem finalval | Out-Null
Check "executive + technical reports generated" ((Test-Path "reports/results/executive_finalval.html") -and (Test-Path "reports/results/technical_finalval.html") -and (Test-Path "reports/results/assessment_finalval.json"))

Write-Host ""
if ($script:failures -eq 0) { Write-Host "FINAL VALIDATION: PASS" -ForegroundColor Green; exit 0 }
else { Write-Host "FINAL VALIDATION: FAIL ($script:failures checks)" -ForegroundColor Red; exit 1 }
