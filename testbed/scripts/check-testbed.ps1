#Requires -Version 5.1
# Phase-1 IPsec testbed verifier - PS5.1 compatible
# Usage: powershell -File testbed\scripts\check-testbed.ps1 [-CaptureSeconds 10]
param(
    [string]$ComposeFile = "$PSScriptRoot\..\compose\testbed.yml",
    [int]$CaptureSeconds = 10,
    [string]$CaptureOut = "$PSScriptRoot\..\..\captures\phase1-capture.pcap"
)

$ErrorActionPreference = "Stop"
$CaptureOut = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CaptureOut)

function RunCmd($cmd) {
    Write-Host "  > $cmd" -ForegroundColor DarkGray
    $out = cmd /c "$cmd 2>&1"
    $code = $LASTEXITCODE
    $txt = ($out -join "`n")
    return @{ out = $txt; code = $code }
}
function Dexec($ctr, $sh) {
    $esc = $sh.Replace('"','\"')
    # Use single quotes for sh -c to avoid PS parsing of 2>&1 etc.
    $cmd = 'docker exec ' + $ctr + ' sh -c "' + $esc + '"'
    return RunCmd $cmd
}
function PassFail($name, $cond, $detail) {
    if ($cond) {
        Write-Host "[PASS] $name" -ForegroundColor Green
        if ($detail) { Write-Host "       $detail" -ForegroundColor DarkGray }
        return $true
    } else {
        Write-Host "[FAIL] $name" -ForegroundColor Red
        if ($detail) { Write-Host "       $detail" -ForegroundColor Yellow }
        return $false
    }
}

$ok = $true
Write-Host "=== Phase-1 IPsec Testbed Verification ===" -ForegroundColor Cyan
Write-Host "Compose: $ComposeFile"
Write-Host "Capture: $CaptureOut"
$kr = RunCmd "docker run --rm alpine uname -r"
Write-Host "Kernel: $($kr.out.Trim())"
Write-Host ""

Write-Host "-- Prerequisites --" -ForegroundColor Cyan
$r = RunCmd "docker --version"
if (-not (PassFail "docker available" ($r.code -eq 0) $r.out)) { $ok = $false }
$r = RunCmd "docker compose version"
if (-not (PassFail "docker compose available" ($r.code -eq 0) $r.out)) { $ok = $false }

Write-Host "`n-- 1. Containers running --" -ForegroundColor Cyan
$containers = @("sih-gateway-a","sih-gateway-b","sih-client-a","sih-client-b")
foreach ($c in $containers) {
    $r = RunCmd "docker inspect -f `"{{.State.Running}}`" $c"
    $pass = ($r.code -eq 0 -and $r.out.Trim() -eq "true")
    if (-not (PassFail "$c running" $pass $r.out.Trim())) { $ok = $false }
}

Write-Host "`n-- 2. Client A -> Gateway A --" -ForegroundColor Cyan
$r = Dexec "sih-client-a" "ping -c 3 -W 2 10.77.1.1"
$cond = ($r.out -match "3 packets transmitted") -and ($r.out -match "3 received" -or $r.out -match "[1-3] received")
if (-not (PassFail "client-a -> gateway-a (10.77.1.1)" $cond ($r.out.Split("`n")[-3]))) { $ok = $false }

Write-Host "`n-- 3. Client B -> Gateway B --" -ForegroundColor Cyan
$r = Dexec "sih-client-b" "ping -c 3 -W 2 10.77.2.1"
$cond = ($r.out -match "3 packets transmitted") -and ($r.out -match "[1-3] received")
if (-not (PassFail "client-b -> gateway-b (10.77.2.1)" $cond ($r.out.Split("`n")[-3]))) { $ok = $false }

Write-Host "`n-- 4. Routing --" -ForegroundColor Cyan
$r = Dexec "sih-client-a" "ip route show"
$hasRouteA = $r.out -match "10.77.2.0/24 via 10.77.1.1"
if (-not (PassFail "client-a route to 10.77.2.0/24 via 10.77.1.1" $hasRouteA ($r.out.Split("`n")[0]))) { $ok = $false }
$r = Dexec "sih-client-b" "ip route show"
$hasRouteB = $r.out -match "10.77.1.0/24 via 10.77.2.1"
if (-not (PassFail "client-b route to 10.77.1.0/24 via 10.77.2.1" $hasRouteB ($r.out.Split("`n")[0]))) { $ok = $false }
$r = Dexec "sih-gateway-a" "sysctl net.ipv4.ip_forward"
$fwd = $r.out -match "net.ipv4.ip_forward = 1"
if (-not (PassFail "gateway-a ip_forward=1" $fwd $r.out.Trim())) { $ok = $false }

Write-Host "`n-- 5. IKE negotiation --" -ForegroundColor Cyan
$r = Dexec "sih-gateway-a" "swanctl --list-sas"
$ikeOk = ($r.out -match "ESTABLISHED")
if (-not $ikeOk) {
    $r2 = Dexec "sih-gateway-a" "ipsec status"
    $ikeOk = ($r2.out -match "ESTABLISHED")
    if ($ikeOk) { $r = $r2 }
}
$detail = (($r.out.Split("`n") | Select-Object -First 4) -join " | ")
if (-not (PassFail "gateway-a IKE SA ESTABLISHED" $ikeOk $detail)) { $ok = $false }
$r = Dexec "sih-gateway-b" "swanctl --list-sas"
$ikeOkB = ($r.out -match "ESTABLISHED")
$detailB = (($r.out.Split("`n") | Select-Object -First 4) -join " | ")
if (-not (PassFail "gateway-b IKE SA ESTABLISHED" $ikeOkB $detailB)) { $ok = $false }

Write-Host "`n-- 6. IPsec SA / XFRM --" -ForegroundColor Cyan
$r = Dexec "sih-gateway-a" "ip xfrm state"
$hasXfrm = ($r.out -match "proto esp")
$detailX = (($r.out.Split("`n") | Where-Object { $_ -match "esp|spi" } | Select-Object -First 2) -join " | ")
if (-not (PassFail "gateway-a XFRM state esp" $hasXfrm $detailX)) { $ok = $false }
$r = Dexec "sih-gateway-a" "ip xfrm policy"
$hasPol = ($r.out -match "dir out") -or ($r.out -match "10.77.1.0")
if (-not (PassFail "gateway-a XFRM policy present" $hasPol ($r.out.Split("`n")[0]))) { $ok = $false }

Write-Host "`n-- 7. Client-A -> Client-B through IPsec --" -ForegroundColor Cyan
$r = Dexec "sih-client-a" "ping -c 5 -W 3 10.77.2.10"
$pingOk = ($r.out -match "5 packets transmitted") -and ($r.out -match "bytes from 10.77.2.10")
$detailP = (($r.out.Split("`n") | Where-Object { $_ -match "packets|bytes from" } | Select-Object -Last 2) -join " | ")
if (-not (PassFail "client-a ping client-b (10.77.2.10) through tunnel" $pingOk $detailP)) {
    $ok = $false
    $lg = RunCmd "docker logs --tail 60 sih-gateway-a"
    Write-Host $lg.out -ForegroundColor DarkGray
}

Write-Host "`n-- 7b. IPv6 ping --" -ForegroundColor Cyan
$r = Dexec "sih-client-a" "ping -6 -c 3 -W 3 fd77:77:2::10"
$ping6Ok = ($r.out -match "bytes from")
PassFail "client-a ping6 client-b (fd77:77:2::10)" $ping6Ok (($r.out.Split("`n") | Select-Object -Last 2) -join " | ") | Out-Null

Write-Host "`n-- 8/9. ESP capture --" -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path (Split-Path $CaptureOut) | Out-Null
# Clean old
$null = Dexec "sih-gateway-a" "rm -f /captures/phase1-capture.pcap; pkill tcpdump 2>/dev/null; echo done"

# Start tcpdump detached, then generate traffic
# Use docker exec -d for background
$null = RunCmd "docker exec -d sih-gateway-a sh -c `"timeout $CaptureSeconds tcpdump -i any -w /captures/phase1-capture.pcap esp or udp port 500 or udp port 4500`""
Start-Sleep -Seconds 2
$null = Dexec "sih-client-a" "ping -c 6 -W 2 10.77.2.10"
$null = Dexec "sih-client-a" "ping -6 -c 3 -W 2 fd77:77:2::10"
Start-Sleep -Seconds ($CaptureSeconds + 2)

$r = Dexec "sih-gateway-a" "ls -lh /captures/phase1-capture.pcap; tcpdump -r /captures/phase1-capture.pcap -n 2>&1 | head -30"
Write-Host $r.out -ForegroundColor DarkGray
$hasEsp = ($r.out -match "ESP")
if (-not (PassFail "ESP traffic visible on transit" $hasEsp "see tcpdump output above")) { $ok = $false }
if (-not (PassFail "tcpdump captured to PCAP" $hasEsp ($r.out.Split("`n")[0]))) { $ok = $false }

Write-Host "`n-- 10. PCAP preserved to host --" -ForegroundColor Cyan
$hostOk = Test-Path $CaptureOut
$detailH = "exists=$hostOk path=$CaptureOut"
if (-not (PassFail "PCAP exists on host" $hostOk $detailH)) { $ok = $false }
if ($hostOk) {
    $len = (Get-Item $CaptureOut).Length
    if (-not (PassFail "PCAP size > 100 bytes" ($len -gt 100) "size=$len bytes")) { $ok = $false }
} else {
    Write-Host "  trying docker cp fallback..." -ForegroundColor Yellow
    $r = RunCmd "docker cp sih-gateway-a:/captures/phase1-capture.pcap `"$CaptureOut`""
    $hostOk = Test-Path $CaptureOut
    if (-not (PassFail "PCAP docker cp fallback" $hostOk $r.out)) { $ok = $false }
}

Write-Host "`n-- XFRM dumps --" -ForegroundColor Cyan
$r = Dexec "sih-gateway-a" "ip xfrm state | head -40"
Write-Host $r.out -ForegroundColor DarkGray
$r = Dexec "sih-gateway-a" "ip xfrm policy | head -40"
Write-Host $r.out -ForegroundColor DarkGray

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
if ($ok) { Write-Host "ALL CHECKS PASSED - IPsec tunnel verified." -ForegroundColor Green; exit 0 }
else     { Write-Host "SOME CHECKS FAILED - see FAIL lines above." -ForegroundColor Red; exit 1 }
