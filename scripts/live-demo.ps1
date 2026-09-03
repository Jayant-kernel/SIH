#Requires -Version 5.1
<# Live passive-monitor demo: teardown T04 -> monitor FIRST -> capture BEFORE
   negotiation -> establish T04 from zero -> IKE_SA_INIT -> video-like
   traffic -> ESP -> rolling ML -> assessment -> dashboard URL.
   Writes only captures/monitor/* and monitor/state/* (+ tmp log). Never
   touches datasets, models, or scenario configs. #>
param(
  [string]$Scenario = "T04",
  [string]$Traffic = "video-like",
  [int]$Duration = 15,
  [int]$Seed = 20260904,
  [int]$WindowSec = 10,
  [int]$MlInterval = 15
)
$ErrorActionPreference = "Continue"
$root = $PSScriptRoot | Split-Path -Parent
Set-Location $root
$fail = 0
function Step($name) { Write-Host "`n=== $name ===" -ForegroundColor Cyan }
function Ok($msg) { Write-Host "[OK] $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "[FAIL] $msg" -ForegroundColor Red; $script:fail++ }
function Gexec($ctr, $sh) { $o = docker exec $ctr sh -c "$sh 2>&1"; return ($o -join "`n") }

Step "1. Docker/testbed health"
$names = docker ps --format "{{.Names}}"
foreach ($c in @("sih-gateway-a","sih-gateway-b")) {
  if ($names -match $c) { Ok "$c running" } else { Fail "$c not running"; exit 1 }
}
$sas = Gexec "sih-gateway-a" "swanctl --list-sas"
if ($sas -match "ESTABLISHED") { Ok "strongSwan responding" } else { Fail "swanctl not responding"; exit 1 }

Step "2. Tear down all SAs (clean slate for capture-before-negotiation)"
foreach ($gw in @("sih-gateway-a","sih-gateway-b")) {
  $conns = Gexec $gw "swanctl --list-conns" | Select-String "^([A-Za-z0-9_-]+):" | ForEach-Object { $_.Matches[0].Groups[1].Value } | Sort-Object -Unique
  foreach ($c in $conns) { Gexec $gw "swanctl --terminate --ike $c" | Out-Null }
}
Start-Sleep -Seconds 3
$left = Gexec "sih-gateway-a" "swanctl --list-sas"
if ($left -match "ESTABLISHED") { Fail "SAs remain after teardown: $left"; exit 1 } else { Ok "no SAs remain" }

Step "3. Start tcpdump sidecar in gateway-a (transit eth1) BEFORE negotiation"
$pcapName = "live_t04.pcap"
docker exec -d sih-gateway-a sh -c "mkdir -p /captures/monitor && timeout 180 tcpdump -i eth1 -U -w /captures/monitor/$pcapName 'udp port 500 or udp port 4500 or esp or ah' 2>/tmp/tcpdump-live.log" | Out-Null
Start-Sleep -Seconds 3
$tcp = Gexec "sih-gateway-a" "ls -la /captures/monitor/$pcapName"
if ($tcp -match $pcapName) { Ok "sidecar capturing: $tcp" } else { Fail "sidecar pcap missing"; exit 1 }

Step "4. Start passive monitor (tails the growing pcap)"
docker rm -f sih-monitor 2>$null | Out-Null
docker run -d --name sih-monitor -v "${root}:/work" -w /work python:3.11 sh -c "pip install --disable-pip-version-check -q --retries 5 -r requirements.txt; python -u -m monitor.run --tail /work/captures/monitor/$pcapName --state /work/monitor/state --window $WindowSec --ml-interval $MlInterval" | Out-Null
$hb = $false
foreach ($i in 1..36) {
  Start-Sleep -Seconds 5
  if (Test-Path "monitor/state/heartbeat.json") {
    $h = Get-Content "monitor/state/heartbeat.json" -Raw | ConvertFrom-Json
    if ($h.status -eq "LIVE") { $hb = $true; break }
  }
}
if ($hb) { Ok "monitor LIVE" } else { Fail "monitor heartbeat missing"; docker logs sih-monitor 2>&1 | Select-Object -Last 5; exit 1 }
$monStart = (Get-Content "monitor/state/heartbeat.json" -Raw | ConvertFrom-Json).ts

Step "5. Silence baseline (proves capture started BEFORE negotiation)"
Start-Sleep -Seconds 3
$snap = Get-Content "monitor/state/live_profiles.json" -Raw | ConvertFrom-Json
$nprof = @($snap.profiles.PSObject.Properties).Count
if ($nprof -eq 0) { Ok "0 profiles before negotiation (clean baseline)" } else { Fail "$nprof profiles already (noisy baseline)"; exit 1 }

Step "6. Establish T04 from zero (fresh IKE_SA_INIT)"
Gexec "sih-gateway-a" "swanctl --initiate --child gcm-child" | Out-Null
$ikeSeen = $false
foreach ($i in 1..12) {
  Start-Sleep -Seconds 5
  $s = Get-Content "monitor/state/live_profiles.json" -Raw | ConvertFrom-Json
  foreach ($pr in $s.profiles.PSObject.Properties) {
    if ($pr.Value.ike.version -eq 2) { $ikeSeen = $true; break }
  }
  if ($ikeSeen) { break }
}
if ($ikeSeen) { Ok "IKEv2 negotiation observed passively" } else { Fail "no IKE observed"; exit 1 }

Step "7. Generate $Traffic traffic + observe ESP"
docker exec sih-gateway-a sh -c "python3 /traffic/generator.py --profile $Traffic --duration $Duration --seed $Seed --peer 10.77.12.10 2>&1 | tail -3"
$espOk = $false; $mlOk = $false
foreach ($i in 1..24) {
  Start-Sleep -Seconds 5
  $s = Get-Content "monitor/state/live_profiles.json" -Raw | ConvertFrom-Json
  foreach ($pr in $s.profiles.PSObject.Properties) {
    $espN = ((($pr.Value.esp_sas.PSObject.Properties | Measure-Object).Count))
    if ($espN -ge 2) { $espOk = $true }
    if ($pr.Value.traffic.label -notin @("Unknown","", $null)) { $mlOk = $true }
  }
  if ($espOk -and $mlOk) { break }
}
if ($espOk) { Ok "ESP SAs tracked (>=2 SPIs)" } else { Fail "no ESP SAs tracked" }
if ($mlOk) { Ok "rolling ML produced a label" } else { Fail "no ML label (see reason in state)" }

Step "8. Passive-vs-ground-truth evaluation (validation only, AFTERWARD)"
docker run --rm -v "${root}:/work" -w /work python:3.11 python monitor/evaluate.py --profiles monitor/state/live_profiles.json --truth testbed/scenarios/T04.json
if ($LASTEXITCODE -eq 0) { Ok "evaluate PASS" } else { Fail "evaluate found mismatches" }

Step "9. Dashboard"
Write-Host "Open: http://127.0.0.1:8501/live" -ForegroundColor Yellow

Step "10. Graceful monitor stop (snapshot finalized)"
docker stop sih-monitor 2>$null | Out-Null; docker rm sih-monitor 2>$null | Out-Null
Ok "monitor stopped; snapshot preserved at monitor/state/live_profiles.json"
Gexec "sih-gateway-a" "swanctl --initiate --child net-v4v6" | Out-Null
Ok "baseline re-established (best effort)"

Write-Host ""
if ($fail -eq 0) { Write-Host "LIVE DEMO: PASS" -ForegroundColor Green; exit 0 }
else { Write-Host "LIVE DEMO: FAIL ($fail)" -ForegroundColor Red; exit 1 }
