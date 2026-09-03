#Requires -Version 5.1
# run-scenario.ps1 - Automated IPsec dataset pipeline
# Usage: powershell -File testbed/scripts/run-scenario.ps1 -Scenario T01 [-Traffic icmp] [-Duration 10] [-Runs 1]
param(
    [string]$Scenario = "T01",
    [string]$Traffic = "all",
    [int]$Duration = 10,
    [int]$Runs = 1,
    [string]$DatasetRoot = "$PSScriptRoot/../../dataset"
)

$ErrorActionPreference = "Stop"
$Scenario = $Scenario.ToUpper()
$DatasetRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DatasetRoot)
$ContainerDatasetRoot = "/dataset"
if ((Split-Path $DatasetRoot -Leaf) -eq "dataset_v3_5_final") { $ContainerDatasetRoot = "/dataset-final" }
if ((Split-Path $DatasetRoot -Leaf) -eq "dataset_v3_5_v2") { $ContainerDatasetRoot = "/dataset-v2" }
if ((Split-Path $DatasetRoot -Leaf) -eq "dataset_v3_5_v2_final") { $ContainerDatasetRoot = "/dataset-v2-final" }
if ((Split-Path $DatasetRoot -Leaf) -eq "demo_live") { $ContainerDatasetRoot = "/dataset-live" }

# Helpers
function RunCmd($cmd) {
    Write-Host "  > $cmd" -ForegroundColor DarkGray
    $out = cmd /c "$cmd 2>&1"
    return @{ out = ($out -join "`n"); code = $LASTEXITCODE }
}
function Dexec($ctr, $sh) {
    $esc = $sh.Replace('"','\"')
    $cmd = 'docker exec ' + $ctr + ' sh -c "' + $esc + '"'
    return RunCmd $cmd
}
function PassFail($name,$cond,$detail){
    if($cond){ Write-Host "[PASS] $name" -ForegroundColor Green; if($detail){ Write-Host "       $detail" -ForegroundColor DarkGray }; return $true }
    else { Write-Host "[FAIL] $name" -ForegroundColor Red; if($detail){ Write-Host "       $detail" -ForegroundColor Yellow }; return $false }
}

# Load scenario
$scenarioPath = "$PSScriptRoot/../scenarios/$Scenario.json"
if (-not (Test-Path $scenarioPath)) {
    # Try phase2 folder
    $scenarioPath = "$PSScriptRoot/../scenarios/phase2/$($Scenario.ToLower()).json"
}
if (-not (Test-Path $scenarioPath)) {
    # Fallback to T01..T15 in scenarios/
    $scenarioPath = Get-ChildItem "$PSScriptRoot/../scenarios" -Recurse -Filter "$Scenario.json" | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $scenarioPath -or -not (Test-Path $scenarioPath)) {
    Write-Host "Scenario $Scenario not found" -ForegroundColor Red; exit 1
}
$scObj = Get-Content $scenarioPath -Raw | ConvertFrom-Json
Write-Host "=== Scenario $Scenario : $($scObj.description) ===" -ForegroundColor Cyan
Write-Host "Family $($scObj.family) Mode $($scObj.mode) Proto $($scObj.ipsec_protocol) Enc $($scObj.encryption_algorithm) PFS $($scObj.pfs)"

# Mapping scenario -> connection/child (handle legacy names)
$map = @{
    "T01" = @{ conn="site-to-site"; child="net-v4v6"; peer="10.77.2.10"; src="10.77.1.10" }
    "T02" = @{ conn="T02"; child="t02-child"; peer="10.77.22.10"; src="10.77.21.10" }
    "T03" = @{ conn="T03"; child="t03-child"; peer="10.77.24.10"; src="10.77.23.10" }
    "T04" = @{ conn="gcm-test"; child="gcm-child"; peer="10.77.12.10"; src="10.77.11.10" }
    "T05" = @{ conn="T05"; child="t05-child"; peer="10.77.14.10"; src="10.77.13.10" }
    "T06" = @{ conn="transport"; child="host-host"; peer="10.77.0.20"; src="10.77.0.10" }
    "T07" = @{ conn="T07"; child="t07-child"; peer="10.77.0.20"; src="10.77.0.10" }
    "T08" = @{ conn="ah-test"; child="ah-child"; peer="10.77.9.10"; src="10.77.8.10" }
    "T09" = @{ conn="T09"; child="t09-child"; peer="10.77.0.20"; src="10.77.0.10" }
    "T10" = @{ conn="ipv6-ike"; child="ipv6-child"; peer="10.77.2.10"; src="10.77.1.10" }
    "T11" = @{ conn="T11"; child="t11-child"; peer="10.77.16.10"; src="10.77.15.10" }
    "T12" = @{ conn="T12"; child="t12-child"; peer="10.77.18.10"; src="10.77.17.10" }
    "T13" = @{ conn="T13"; child="t13-child"; peer="10.77.20.10"; src="10.77.19.10" }
    "T14" = @{ conn="T14"; child="t14-child"; peer="10.77.26.10"; src="10.77.25.10" }
    "T15" = @{ conn="T15"; child="t15-child"; peer="fd77:77:24::10"; src="fd77:77:23::10" }
    "S01" = @{ conn="site-to-site"; child="net-v4v6"; peer="10.77.2.10"; src="10.77.1.10" }
}
# Also support S02..S06 legacy
$map["S02"]=@{ conn="gcm-test"; child="gcm-child"; peer="10.77.12.10"; src="10.77.11.10" }
$map["S03"]=@{ conn="ipv6-ike"; child="ipv6-child"; peer="10.77.2.10"; src="10.77.1.10" }
$map["S04"]=@{ conn="transport"; child="host-host"; peer="10.77.0.20"; src="10.77.0.10" }
$map["S05"]=@{ conn="ah-test"; child="ah-child"; peer="10.77.9.10"; src="10.77.8.10" }
$map["S06"]=@{ conn="site-to-site"; child="net-v4v6"; peer="10.77.2.10"; src="10.77.1.10" }

if (-not $map.ContainsKey($Scenario)) { Write-Host "No conn mapping for $Scenario, using T01" -ForegroundColor Yellow; $m=$map["T01"] } else { $m=$map[$Scenario] }
$conn=$m.conn; $child=$m.child; $peer=$m.peer; $src=$m.src
Write-Host "Using conn $conn child $child peer $peer src $src" -ForegroundColor DarkGray

# Traffic profiles to run
$allProfiles = @("icmp","web","dns","bulk-transfer","voip-like","video-like","messaging-like","email-like")
if ($Traffic -eq "all") { $profiles=$allProfiles | Where-Object { $_ -in @("icmp","web","voip-like","video-like") } }
elseif ($Traffic -match ",") { $profiles=$Traffic.Split(",") }
else { $profiles=@($Traffic) }

# Ensure containers
Write-Host "`n-- Prerequisites --" -ForegroundColor Cyan
$r=RunCmd "docker ps --format `"{{.Names}}`""
$need=@("sih-gateway-a","sih-gateway-b","sih-client-a","sih-client-b")
foreach($c in $need){ if($r.out -notmatch $c){ Write-Host "Container $c not running, starting compose..." -ForegroundColor Yellow; RunCmd "docker compose -f testbed/compose/testbed.yml up -d" | Out-Null; Start-Sleep -Seconds 8; break } }

# Ensure background services on clients/gateways
Write-Host "Ensuring traffic servers on clients..." -ForegroundColor DarkGray
$null=Dexec "sih-client-b" "python3 /traffic/generator.py --start-servers 2>&1 | head -5"
$null=Dexec "sih-client-a" "python3 /traffic/generator.py --start-servers 2>&1 | head -5"
if ($Scenario -eq "T15") {
    # T15 targets the gateway-side IPv6 protected alias, not client-b's address.
    $null=Dexec "sih-gateway-b" "ss -lunH6 | grep -q ':5001 ' || nohup python3 /traffic/ipv6_udp_server.py 5001 >/tmp/t15-udp5001.log 2>&1 & ss -lunH6 | grep -q ':5002 ' || nohup python3 /traffic/ipv6_udp_server.py 5002 >/tmp/t15-udp5002.log 2>&1 &"
    $null=Dexec "sih-gateway-b" "ss -ltnH6 | grep -q ':8000 ' || nohup python3 -m http.server 8000 --bind fd77:77:24::10 >/tmp/t15-http.log 2>&1 &"
}
Start-Sleep -Seconds 2
if ($Scenario -eq "T15") {
    $listeners = Dexec "sih-gateway-b" "ss -lunH6 2>&1"
    if ($listeners.out -notmatch ":5001\s" -or $listeners.out -notmatch ":5002\s") {
        Write-Host "[FAIL] T15 IPv6 UDP listeners are not ready" -ForegroundColor Red
        Write-Host $listeners.out -ForegroundColor Yellow
        exit 1
    }
}

for($run=1; $run -le $Runs; $run++){
  foreach($prof in $profiles){
    # Randomize duration 8-15 and seed per run for variation (reproducible via seed)
    $actualDuration = Get-Random -Minimum 8 -Maximum 16  # 8..15 inclusive
    $actualSeed = Get-Random -Maximum 9999
    # If Duration param was explicitly non-default, use it; else use randomized
    if($Duration -ne 10){ $actualDuration = $Duration }
    $runId = (Get-Date -Format "yyyyMMdd-HHmmss") + "-" + (Get-Random -Maximum 999).ToString("000")
    $runDir = Join-Path $DatasetRoot "$Scenario/$runId"
    New-Item -ItemType Directory -Force -Path $runDir | Out-Null
    $pcap = Join-Path $runDir "capture.pcap"
    $pcapInside = "$ContainerDatasetRoot/$Scenario/$runId/capture.pcap"
    Write-Host "`n=== Run $Scenario/$runId Traffic $prof Dur $actualDuration Seed $actualSeed ===" -ForegroundColor Cyan
    $runLog = Join-Path $runDir "run.log"
    "Run $runId Scenario $Scenario Traffic $prof Duration $actualDuration Seed $actualSeed" | Out-File $runLog -Encoding utf8

    # T15 requires a clean SA and XFRM state before every sample.
    $firstInBatch = ($run -eq 1 -and $prof -eq $profiles[0])
    $freshT15 = ($Scenario -eq "T15")
    if($firstInBatch -or $freshT15){
        Write-Host "Terminating other SAs..." -ForegroundColor DarkGray
        $allConns=@("site-to-site","gcm-test","ipv6-ike","transport","ah-test","T02","T03","T05","T07","T09","T11","T12","T13","T14","T15")
        foreach($c in $allConns){ $null=Dexec "sih-gateway-a" "swanctl --terminate --ike $c 2>&1 | tail -1"; $null=Dexec "sih-gateway-b" "swanctl --terminate --ike $c 2>&1 | tail -1" }
        Start-Sleep -Seconds 1
        if($freshT15){
            $cleanA=Dexec "sih-gateway-a" "swanctl --list-sas 2>&1"
            $cleanB=Dexec "sih-gateway-b" "swanctl --list-sas 2>&1"
            $cleanXfrm=Dexec "sih-gateway-a" "ip xfrm state 2>&1; ip xfrm policy 2>&1"
            if($cleanA.out -match "ESTABLISHED" -or $cleanB.out -match "ESTABLISHED" -or $cleanXfrm.out -match "proto (esp|ah)" -or $cleanXfrm.out -match "fd77:77:23::|fd77:77:24::"){
                Write-Host "[FAIL] T15 could not obtain clean SA state" -ForegroundColor Red
                "FAIL CLEAN SA" | Out-File (Join-Path $runDir "FAILED.txt") -Encoding utf8
                continue
            }
        }
        $null=Dexec "sih-gateway-a" "swanctl --load-all 2>&1 | tail -3"
        $null=Dexec "sih-gateway-b" "swanctl --load-all 2>&1 | tail -3"
        Write-Host "Initiating $conn/$child..." -ForegroundColor DarkGray
        $r=Dexec "sih-gateway-a" "swanctl --initiate --child $child 2>&1 | tail -15"
        Add-Content $runLog $r.out
        Start-Sleep -Seconds 3
        $allSa=Dexec "sih-gateway-a" "swanctl --list-sas 2>&1"
        if($freshT15 -and ($allSa.out -match "duplicate" -or $allSa.out -match "site-to-site" -or $allSa.out -notmatch "T15:.*ESTABLISHED")){
            Write-Host "[FAIL] T15 SA isolation/initiation check failed" -ForegroundColor Red
            Add-Content $runLog $allSa.out
            "FAIL SA ISOLATION" | Out-File (Join-Path $runDir "FAILED.txt") -Encoding utf8
            continue
        }
        $r=Dexec "sih-gateway-a" "swanctl --list-sas 2>&1 | grep -A5 $conn"
        $est = ($r.out -match "ESTABLISHED")
        if(-not $est){ Write-Host "[FAIL] SA not ESTABLISHED for $conn" -ForegroundColor Red; "FAIL SA" | Out-File (Join-Path $runDir "FAILED.txt") -Encoding utf8; continue }
        $r2=Dexec "sih-gateway-a" "swanctl --list-sas 2>&1 | grep -A8 $child"
        if($r2.out -notmatch "INSTALLED"){ Write-Host "[FAIL] CHILD not INSTALLED $child" -ForegroundColor Red; "FAIL CHILD" | Out-File (Join-Path $runDir "FAILED.txt") -Encoding utf8; continue }
        if($freshT15 -and ($r2.out -notmatch "AES_CBC-192/HMAC_SHA2_256_128" -or $r2.out -notmatch "fd77:77:23::/64" -or $r2.out -notmatch "fd77:77:24::/64")){ Write-Host "[FAIL] T15 proposal or selectors incorrect" -ForegroundColor Red; "FAIL T15 PROPOSAL" | Out-File (Join-Path $runDir "FAILED.txt") -Encoding utf8; continue }
    }
    if($freshT15){
        $listeners = Dexec "sih-gateway-b" "ss -lunH6 2>&1"
        if ($listeners.out -notmatch ":5001\s" -or $listeners.out -notmatch ":5002\s") { Write-Host "[FAIL] T15 IPv6 UDP listeners are not ready" -ForegroundColor Red; "FAIL UDP LISTENER" | Out-File (Join-Path $runDir "FAILED.txt") -Encoding utf8; continue }
        if($prof -eq "voip-like" -or $prof -eq "video-like"){
            $port = if($prof -eq "voip-like"){5001}else{5002}
            $probe = Dexec "sih-gateway-a" "python3 /traffic/ipv6_udp_probe.py $peer $port 2>&1"
            Add-Content $runLog $probe.out
            if($probe.out -notmatch "READY") { Write-Host "[FAIL] T15 IPv6 UDP delivery probe failed" -ForegroundColor Red; "FAIL UDP DELIVERY" | Out-File (Join-Path $runDir "FAILED.txt") -Encoding utf8; continue }
        }
        if($prof -eq "icmp"){
            $probe = Dexec "sih-gateway-a" "ping -c 2 -W 2 -I $src $peer 2>&1"
            Add-Content $runLog $probe.out
            if($probe.out -notmatch "0% packet loss") { Write-Host "[FAIL] T15 IPv6 ICMP delivery probe failed" -ForegroundColor Red; "FAIL ICMP DELIVERY" | Out-File (Join-Path $runDir "FAILED.txt") -Encoding utf8; continue }
        }
        if($prof -eq "web"){
            $probe = Dexec "sih-gateway-a" "curl -g -s --connect-timeout 2 -o /dev/null -w '%{http_code}' http://[$peer]:8000/ 2>&1"
            Add-Content $runLog $probe.out
            if($probe.out -notmatch "200") { Write-Host "[FAIL] T15 IPv6 HTTP delivery probe failed" -ForegroundColor Red; "FAIL HTTP DELIVERY" | Out-File (Join-Path $runDir "FAILED.txt") -Encoding utf8; continue }
        }
    }
    # Record before
    $swanBefore = Dexec "sih-gateway-a" "swanctl --list-sas 2>&1 | head -80"
    $swanBefore.out | Out-File (Join-Path $runDir "swanctl-before.txt") -Encoding utf8
    $xfrmStateBefore = Dexec "sih-gateway-a" "ip xfrm state 2>&1 | head -100"
    $xfrmStateBefore.out | Out-File (Join-Path $runDir "xfrm-state.txt") -Encoding utf8
    $xfrmPolicyBefore = Dexec "sih-gateway-a" "ip xfrm policy 2>&1 | head -100"
    $xfrmPolicyBefore.out | Out-File (Join-Path $runDir "xfrm-policy.txt") -Encoding utf8

    # Start capture
    Write-Host "Starting capture $pcapInside dur $actualDuration..." -ForegroundColor DarkGray
    $captureCommand = if($Scenario -eq "T15") { "timeout $actualDuration tcpdump -i eth1 -w $pcapInside esp or udp port 500 or udp port 4500 2>&1" } else { "timeout $actualDuration tcpdump -i any -w $pcapInside esp or ah or udp port 500 or udp port 4500 or ip6 2>&1" }
    $null=RunCmd "docker exec -d sih-gateway-a sh -c `"$captureCommand`""
    Start-Sleep -Seconds 1
    # Generate traffic
    Write-Host "Generating $prof for $actualDuration s seed $actualSeed..." -ForegroundColor DarkGray
    $genPeer = $peer
    $isClientPeer = ($peer -eq "10.77.2.10" -or $peer -eq "fd77:77:2::10")
    # Capture generator output for metadata
    $genOut = $null
    if($prof -match "icmp"){
        if(-not $isClientPeer){
            $null=Dexec "sih-gateway-a" "ping -c 5 -W 2 -I $src $genPeer 2>&1 | tail -3"
            $genOut = Dexec "sih-gateway-a" "python3 /traffic/generator.py --profile icmp --duration $actualDuration --seed $actualSeed --peer $genPeer 2>&1 | tail -5"
        } else {
            $null=Dexec "sih-client-a" "ping -c 8 -W 2 $genPeer 2>&1 | tail -3"
            $genOut = Dexec "sih-client-a" "python3 /traffic/generator.py --profile icmp --duration $actualDuration --seed $actualSeed --peer $genPeer 2>&1 | tail -5"
        }
    } else {
        if(-not $isClientPeer){
            $ctr="sih-gateway-a"
        } else {
            $ctr="sih-client-a"
        }
        $genOut = Dexec $ctr "python3 /traffic/generator.py --profile $prof --duration $actualDuration --seed $actualSeed --peer $genPeer 2>&1 | tail -10"
    }
    $trafficActualJson = $genOut.out
    Add-Content $runLog $trafficActualJson
    # Optionally trigger rekey if scenario wants
    if($scObj.rekey_enabled -and $scObj.rekey_time -eq "60s"){
        Write-Host "Triggering rekey for $child..." -ForegroundColor DarkGray
        Start-Sleep -Seconds 2
        $null=Dexec "sih-gateway-a" "swanctl --rekey --child $child 2>&1 | tail -5"
        Start-Sleep -Seconds 2
        # Continue traffic briefly
        $null=Dexec "sih-client-a" "ping -c 3 $peer 2>&1 | tail -2"
    }
    Start-Sleep -Seconds 3
    # Stop capture is via timeout, but ensure
    # The generator already runs for the selected duration; allow tcpdump a
    # short flush window instead of sleeping through the capture again.
    Start-Sleep -Seconds 3
    # Collect after
    $swanAfter = Dexec "sih-gateway-a" "swanctl --list-sas 2>&1 | head -80"
    $swanAfter.out | Out-File (Join-Path $runDir "swanctl-after.txt") -Encoding utf8
    $xfrmAfter = Dexec "sih-gateway-a" "ip xfrm state 2>&1 | head -100"
    $xfrmAfter.out | Out-File (Join-Path $runDir "xfrm-state-after.txt") -Encoding utf8
    $tcpdumpSummary = Dexec "sih-gateway-a" "tcpdump -r $pcapInside -n 2>&1 | head -30"
    $tcpdumpSummary.out | Out-File (Join-Path $runDir "tcpdump-summary.txt") -Encoding utf8

    # Generate metadata.json
    $runIdFull = $runId
    $ts = (Get-Date -Format "o")
    $evidence = @{
        directly_observed = @("ESP packet present if tcpdump shows ESP", "AH packet present if AH", "IPv4/IPv6 outer", "SPI", "packet lengths")
        deterministically_derived = @("mode from XFRM", "PFS from scenario", "rekey from SPI change")
        ml_inferred = @()
        unknown = @("AES key length from ciphertext", "exact DH group from ciphertext")
    }
    $metadata = @{
        run = @{ run_id = $runIdFull; timestamp = $ts; scenario_id = $Scenario; status = "PASS"; pcap = "capture.pcap" }
        scenario = $scObj
        vpn_ground_truth = @{
            ike_version = $scObj.ike_version
            ike_transport_ip_version = $scObj.ike_transport_ip_version
            ipsec_protocol = $scObj.ipsec_protocol
            mode = $scObj.mode
            encryption_algorithm = $scObj.encryption_algorithm
            encryption_key_length = $scObj.encryption_key_length
            integrity_algorithm = $scObj.integrity_algorithm
            dh_group = $scObj.dh_group
            dh_group_name = $scObj.dh_group_name
            pfs = $scObj.pfs
            protected_ip_version = $scObj.protected_ip_version
            local_ts = $scObj.local_ts
            remote_ts = $scObj.remote_ts
            rekey_enabled = $scObj.rekey_enabled
            rekey_time = $scObj.rekey_time
        }
        traffic_ground_truth = @{
            traffic_class = $prof
            generator = "generator.py"
            duration = $actualDuration
            seed = $actualSeed
            peer = $peer
            src = $src
            generator_output = $trafficActualJson
         profile_version = $(if($Scenario -eq "T15"){"3.5-v2"}else{"3.5-v1"})
        }
        observations = @{
            swanctl_before = ($swanBefore.out.Split("`n")[0..5] -join " | ")
            swanctl_after = ($swanAfter.out.Split("`n")[0..5] -join " | ")
            xfrm_state_lines = ($xfrmAfter.out.Split("`n") | Where-Object { $_ -match "proto (esp|ah)" } | Select-Object -First 2) -join " | "
            tcpdump_head = ($tcpdumpSummary.out.Split("`n")[0..3] -join " | ")
        }
        evidence_classification = $evidence
        validation = @{ expected_protocols = $scObj.expected_protocols; mode_verified = $true }
    }
    $metadata | ConvertTo-Json -Depth 6 | Out-File (Join-Path $runDir "metadata.json") -Encoding utf8

    # Feature extraction via docker (gateway has scapy)
    Write-Host "Extracting features..." -ForegroundColor DarkGray
    $null=Dexec "sih-gateway-a" "python3 /analyzer/pcap_features.py $pcapInside --lifecycle-evidence $ContainerDatasetRoot/$Scenario/$runId/swanctl-after.txt --out $ContainerDatasetRoot/$Scenario/$runId/features.json 2>&1 | tail -5"
    # Fallback if features not created, try via host docker python
    if(-not (Test-Path (Join-Path $runDir "features.json"))){
        $null=RunCmd "docker run --rm -v `"$DatasetRoot`":/dataset -v `"C:\Users\jayan\OneDrive\Desktop\sih\analyzer`":/analyzer python:3.11 python /analyzer/pcap_features.py /dataset/$Scenario/$runId/capture.pcap --out /dataset/$Scenario/$runId/features.json 2>&1 | head -20"
    }
    # Validate
    $pcapExists = Test-Path $pcap
    $metaExists = Test-Path (Join-Path $runDir "metadata.json")
    $featExists = Test-Path (Join-Path $runDir "features.json")
    $runPass = ($pcapExists -and $metaExists -and $featExists)
    if($Scenario -eq "T15" -and $runPass){
        $summaryText = (Get-Content (Join-Path $runDir "tcpdump-summary.txt") -Raw)
        $featureObj = Get-Content (Join-Path $runDir "features.json") -Raw | ConvertFrom-Json
        if($summaryText -notmatch "ESP\(" -or $summaryText -match "fd77:77:23::|fd77:77:24::" -or [double]$featureObj.capture.total_packets -le 0 -or [double]$featureObj.capture.esp_packets -le 0){ $runPass=$false; "FAIL CAPTURE PURITY" | Out-File (Join-Path $runDir "FAILED.txt") -Encoding utf8 }
        if($prof -match "voip-like|video-like" -and $summaryText -match "destination unreachable|unreachable port"){ $runPass=$false; "FAIL APPLICATION DELIVERY" | Out-File (Join-Path $runDir "FAILED.txt") -Encoding utf8 }
        if($featureObj.rekey.rekey_status -ne "no_rekey" -or [int]$featureObj.esp_ah.esp_spi_count -ne 2 -or $featureObj.esp_ah.esp_spis -contains "0x0"){ $runPass=$false; "FAIL SPI REKEY VALIDATION" | Out-File (Join-Path $runDir "FAILED.txt") -Encoding utf8 }
    }
    if($metaExists){
        $metaJson = Get-Content (Join-Path $runDir "metadata.json") -Raw | ConvertFrom-Json
        $metaJson.run.status = if($runPass){"PASS"}else{"INVALID"}
        $criteria = if($runPass){"PASS"}else{"INVALID"}
        $metaJson.validation | Add-Member -NotePropertyName pass_criteria -NotePropertyValue $criteria
        $metaJson | ConvertTo-Json -Depth 6 | Out-File (Join-Path $runDir "metadata.json") -Encoding utf8
    }
    if($runPass){
        Write-Host "[PASS] Run $Scenario/$runId $prof captured" -ForegroundColor Green
        "PASS" | Out-File (Join-Path $runDir "PASS.txt") -Encoding utf8
    } else {
        Write-Host "[FAIL] Run $Scenario/$runId missing files pcap=$pcapExists meta=$metaExists feat=$featExists" -ForegroundColor Red
    }
    # Copy pcap also to captures for easy inspect
    Copy-Item $pcap "C:\Users\jayan\OneDrive\Desktop\sih\captures\$Scenario-$prof-$runId.pcap" -Force -ErrorAction SilentlyContinue
  }
}
Write-Host "`n=== Dataset generation complete ===" -ForegroundColor Cyan
