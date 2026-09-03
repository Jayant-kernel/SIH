#Requires -Version 5.1
param([string]$DatasetRoot = "$PSScriptRoot/../../dataset")
$DatasetRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DatasetRoot)
Write-Host "=== Validate dataset $DatasetRoot ===" -ForegroundColor Cyan
$ok=$true
$allRuns=@()
$pcapHashes=@{}
$featureHashes=@{}
$scenarioCounts=@{}
$trafficCounts=@{}
$scenarioTraffic=@{}
$durations=@()
$seeds=@()

$scenarios = Get-ChildItem $DatasetRoot -Directory | Where-Object { $_.Name -ne "example" }
if(-not $scenarios){ Write-Host "No scenarios found" -ForegroundColor Yellow; exit 0 }
foreach($s in $scenarios){
  $runs = Get-ChildItem $s.FullName -Directory | Where-Object { $_.Name -match "^\d{8}-" }
  $scenarioCounts[$s.Name] = $runs.Count
  foreach($r in $runs){
    $pcap = Join-Path $r.FullName "capture.pcap"
    $meta = Join-Path $r.FullName "metadata.json"
    $feat = Join-Path $r.FullName "features.json"
    $prefix = "$($s.Name)/$($r.Name)"
    $pass=$true
    $warns=@()
    # Basic existence
    if(-not (Test-Path $pcap)){ Write-Host "[FAIL] $prefix missing capture.pcap" -ForegroundColor Red; $pass=$false; $ok=$false }
    elseif((Get-Item $pcap).Length -lt 100){ Write-Host "[FAIL] $prefix capture.pcap too small $((Get-Item $pcap).Length)" -ForegroundColor Red; $pass=$false; $ok=$false }
    if(-not (Test-Path $meta)){ Write-Host "[FAIL] $prefix missing metadata.json" -ForegroundColor Red; $pass=$false; $ok=$false }
    else {
        try{
            $j=Get-Content $meta -Raw | ConvertFrom-Json
            if($j.run.scenario_id -ne $s.Name){ Write-Host "[FAIL] $prefix metadata scenario mismatch $($j.run.scenario_id) vs $($s.Name)" -ForegroundColor Red; $pass=$false; $ok=$false }
            if(-not $j.traffic_ground_truth.traffic_class){ Write-Host "[FAIL] $prefix missing traffic_class" -ForegroundColor Red; $pass=$false } else { $tc=$j.traffic_ground_truth.traffic_class; if(-not $trafficCounts.ContainsKey($tc)){ $trafficCounts[$tc]=0 }; $trafficCounts[$tc]++
            $key="$($s.Name)x$tc"; if(-not $scenarioTraffic.ContainsKey($key)){ $scenarioTraffic[$key]=0 }; $scenarioTraffic[$key]++
            }
            if($j.traffic_ground_truth.duration){ $durations+=[double]$j.traffic_ground_truth.duration }
            if($j.traffic_ground_truth.seed){ $seeds+=$j.traffic_ground_truth.seed }
            # Check timestamp
            try{ [DateTime]::Parse($j.run.timestamp) | Out-Null } catch { Write-Host "[WARN] $prefix invalid timestamp" -ForegroundColor Yellow }
        } catch{ Write-Host "[FAIL] $prefix metadata parse $_" -ForegroundColor Red; $pass=$false; $ok=$false }
    }
     foreach($required in @("swanctl-before.txt","swanctl-after.txt","xfrm-state.txt","xfrm-policy.txt","tcpdump-summary.txt","run.log","PASS.txt")){ if(-not (Test-Path (Join-Path $r.FullName $required))){ Write-Host "[FAIL] $prefix missing $required" -ForegroundColor Red; $pass=$false; $ok=$false } }
     if(-not (Test-Path $feat)){ Write-Host "[FAIL] $prefix missing features.json" -ForegroundColor Yellow; $pass=$false } else {
        try{
            $fj=Get-Content $feat -Raw | ConvertFrom-Json
            if(-not $fj.capture){ Write-Host "[FAIL] $prefix features missing capture" -ForegroundColor Red; $pass=$false } else {
                # Data-quality checks
                $tp=$fj.capture.total_packets
                $dur=$fj.capture.duration
                $esp=$fj.capture.esp_packets
                $ah=$fj.capture.ah_packets
                $ike=$fj.capture.ike_packets
                if($tp -eq 0){ Write-Host "[FAIL] $prefix zero-packet PCAP" -ForegroundColor Red; $pass=$false; $ok=$false }
                if($dur -lt 2){ $warns+="duration ${dur}s extremely short" }
                if($esp -eq 0 -and $ah -eq 0){ $warns+="no ESP/AH protected packets (only IKE?)" }
                # Expected protocol check
                try{
                    $metaJson=Get-Content $meta -Raw | ConvertFrom-Json
                    $expProto=$metaJson.vpn_ground_truth.ipsec_protocol
                     if($expProto -eq "ESP" -and ($esp -eq 0 -or $ah -gt 0)){ Write-Host "[FAIL] protocol mismatch $prefix expected ESP esp=$esp ah=$ah" -ForegroundColor Red; $pass=$false; $ok=$false }
                     if($expProto -eq "AH" -and ($ah -eq 0 -or $esp -gt 0)){ Write-Host "[FAIL] protocol mismatch $prefix expected AH esp=$esp ah=$ah" -ForegroundColor Red; $pass=$false; $ok=$false }
                } catch {}
                if($tp -lt 5){ $warns+="total packets $tp below minimum 5" }
                # Duplicate pcap hash
                $hash=(Get-FileHash $pcap -Algorithm MD5).Hash
                if($pcapHashes.ContainsKey($hash)){ Write-Host "[WARN] $prefix duplicate pcap hash with $($pcapHashes[$hash])" -ForegroundColor Yellow; $warns+="duplicate pcap hash $hash" } else { $pcapHashes[$hash]=$prefix }
                # Feature hash for identical features
                $fhash=(Get-FileHash $feat -Algorithm MD5).Hash
                if($featureHashes.ContainsKey($fhash)){ $warns+="identical features as $($featureHashes[$fhash])" } else { $featureHashes[$fhash]=$prefix }
                # Store for later
                $allRuns+=@{prefix=$prefix; feat=$fj; meta=$meta}
            }
        } catch{ Write-Host "[FAIL] $prefix features parse $_" -ForegroundColor Red; $pass=$false }
    }
    if($warns){ foreach($w in $warns){ Write-Host "  [WARN] $prefix $w" -ForegroundColor DarkYellow } }
    if($pass){ Write-Host "[PASS] $prefix" -ForegroundColor Green }
    else { $ok=$false }
  }
}
# Summary
Write-Host "`n=== Dataset Summary ===" -ForegroundColor Cyan
Write-Host "Total runs: $($allRuns.Count)"
Write-Host "Per scenario:"
foreach($k in $scenarioCounts.Keys | Sort-Object){ Write-Host "  $k : $($scenarioCounts[$k])" }
Write-Host "Per traffic class:"
foreach($k in $trafficCounts.Keys | Sort-Object){ Write-Host "  $k : $($trafficCounts[$k])" }
Write-Host "Per scenario x traffic:"
foreach($k in $scenarioTraffic.Keys | Sort-Object){ Write-Host "  $k : $($scenarioTraffic[$k])" }
if($durations){
    $avg=(($durations | Measure-Object -Average).Average)
    $min=($durations | Measure-Object -Minimum).Minimum
    $max=($durations | Measure-Object -Maximum).Maximum
    Write-Host "Duration: min $min max $max avg $([math]::Round($avg,2)) (target 8-15)"
}
$uniqueSeeds=($seeds | Sort-Object -Unique).Count
Write-Host "Seed uniqueness: $uniqueSeeds unique / $($seeds.Count) total"
$emptyPcap=($allRuns | Where-Object { $_.feat.capture.total_packets -eq 0 }).Count
Write-Host "Empty PCAP count: $emptyPcap"
$featFail=($allRuns | Where-Object { -not $_.feat.capture }).Count
Write-Host "Feature extraction failures: $featFail"
# Duplicate run IDs (should be unique by timestamp, but check)
$runIds=$allRuns | ForEach-Object { $_.prefix.Split("/")[1] }
$dupRunIds=($runIds | Group-Object | Where-Object Count -gt 1).Count
Write-Host "Duplicate run IDs: $dupRunIds"

Write-Host "`n=== Validation ===" -ForegroundColor Cyan
if($ok){ Write-Host "ALL DATASET CHECKS PASSED" -ForegroundColor Green; exit 0 } else { Write-Host "SOME DATASET CHECKS FAILED" -ForegroundColor Red; exit 1 }
