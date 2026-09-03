#Requires -Version 5.1
<# Start the canonical live capture -> monitor -> dashboard pipeline. #>
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$pcap = "live_current.pcap"
$hostPcap = Join-Path $root "captures\monitor\$pcap"
$state = Join-Path $root "monitor\state"

if (-not (Test-Path -LiteralPath (Join-Path $root "captures\monitor"))) {
  New-Item -ItemType Directory -Path (Join-Path $root "captures\monitor") | Out-Null
}
if (-not (Test-Path -LiteralPath $state)) {
  New-Item -ItemType Directory -Path $state | Out-Null
}
Remove-Item -LiteralPath $hostPcap -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $state "live_profiles.json"), (Join-Path $state "heartbeat.json"), (Join-Path $state "events.jsonl") -Force -ErrorAction SilentlyContinue

docker rm -f sih-live-monitor sih-live-dashboard 2>$null | Out-Null
docker exec sih-gateway-a sh -c "pkill tcpdump 2>/dev/null || true"
docker exec -d sih-gateway-a sh -c "tcpdump -i eth1 -U -w /captures/monitor/$pcap 'udp port 500 or udp port 4500 or esp or ah' >/tmp/live-current-tcpdump.log 2>&1"
docker run -d --name sih-live-monitor -v "${root}:/work" -w /work ipsec-test python -u -m monitor.run --tail "/work/captures/monitor/$pcap" --state /work/monitor/state --window 10 --ml-interval 15 | Out-Null
docker run -d --name sih-live-dashboard -p 127.0.0.1:8501:8501 -v "${root}:/work" -w /work ipsec-test python -u app/app.py --host 0.0.0.0 --port 8501 | Out-Null

Write-Output "Capture: /captures/monitor/$pcap -> $hostPcap"
Write-Output "Monitor: --tail /work/captures/monitor/$pcap --state /work/monitor/state"
Write-Output "State: $state\live_profiles.json"
Write-Output "Dashboard: http://127.0.0.1:8501/live"
