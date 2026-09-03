#!/bin/bash
set -e

# Entrypoint for IPsec gateway containers.
# 1. Enables IPv4/IPv6 forwarding (also set via compose sysctls; this is belt-and-suspenders).
# 2. Configures iptables forwarding baseline (needed so protected networks can route through gateways).
# 3. Starts charon via ipsec start; then tails logs.

echo "[entrypoint] $(hostname) starting — $(date -u +%FT%TZ)"
echo "[entrypoint] strongSwan version: $(ipsec version 2>&1 || swanctl --version 2>&1)"

# Forwarding (requires privileged + sysctl; ignore failure if already set)
sysctl -w net.ipv4.ip_forward=1 2>&1 || echo "[warn] net.ipv4.ip_forward failed"
sysctl -w net.ipv6.conf.all.forwarding=1 2>&1 || echo "[warn] net.ipv6 forward failed"
sysctl -w net.ipv4.conf.all.rp_filter=0 2>&1 || true
sysctl -w net.ipv4.conf.default.rp_filter=0 2>&1 || true

# Disable reverse-path filtering on all interfaces (IPsec tunnel decaps can trigger it)
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "$f" 2>/dev/null || true; done

# Baseline iptables: allow forwarding (Docker's FORWARD is DROP by default in some setups)
iptables -P FORWARD ACCEPT 2>&1 || true
ip6tables -P FORWARD ACCEPT 2>&1 || true
iptables -A FORWARD -j ACCEPT 2>&1 || true
ip6tables -A FORWARD -j ACCEPT 2>&1 || true

# Phase2/3 dummy IPs/routes for all 15 scenarios (idempotent)
# Gateway-a holds 10.77.11.10, .13.10, .15.10, .17.10, .19.10, .21.10, .23.10, .25.10, .8.10 and fd77:77:23::10
# Gateway-b holds 10.77.12.10, .14.10, .16.10, .18.10, .20.10, .22.10, .24.10, .26.10, .9.10 and fd77:77:24::10
if [ "$(hostname)" = "gateway-a" ]; then
    for ip in 10.77.11.10 10.77.13.10 10.77.15.10 10.77.17.10 10.77.19.10 10.77.21.10 10.77.23.10 10.77.25.10 10.77.8.10; do
        ip addr add ${ip}/24 dev lo 2>/dev/null || true
    done
    ip addr add fd77:77:23::10/64 dev lo 2>/dev/null || true
    for net in 10.77.12.0/24 10.77.14.0/24 10.77.16.0/24 10.77.18.0/24 10.77.20.0/24 10.77.22.0/24 10.77.24.0/24 10.77.26.0/24 10.77.9.0/24 fd77:77:24::/64; do
        ip route add ${net} via 10.77.0.20 2>/dev/null || true
        # IPv6 routes via IPv6 transit if needed
        if echo "$net" | grep -q ":"; then ip -6 route add ${net} via fd77:77:0::20 2>/dev/null || true; fi
    done
    echo "[entrypoint] gateway-a phase3 IPs: $(ip addr show lo | grep -o '10.77.[0-9]*\.[0-9]*' | tr '\n' ' ') $(ip -6 addr show lo | grep -o 'fd77:77:.*' | tr '\n' ' ')"
elif [ "$(hostname)" = "gateway-b" ]; then
    for ip in 10.77.12.10 10.77.14.10 10.77.16.10 10.77.18.10 10.77.20.10 10.77.22.10 10.77.24.10 10.77.26.10 10.77.9.10; do
        ip addr add ${ip}/24 dev lo 2>/dev/null || true
    done
    ip addr add fd77:77:24::10/64 dev lo 2>/dev/null || true
    for net in 10.77.11.0/24 10.77.13.0/24 10.77.15.0/24 10.77.17.0/24 10.77.19.0/24 10.77.21.0/24 10.77.23.0/24 10.77.25.0/24 10.77.8.0/24 fd77:77:23::/64; do
        ip route add ${net} via 10.77.0.10 2>/dev/null || true
        if echo "$net" | grep -q ":"; then ip -6 route add ${net} via fd77:77:0::10 2>/dev/null || true; fi
    done
    echo "[entrypoint] gateway-b phase3 IPs: $(ip addr show lo | grep -o '10.77.[0-9]*\.[0-9]*' | tr '\n' ' ') $(ip -6 addr show lo | grep -o 'fd77:77:.*' | tr '\n' ' ')"
fi
# Ensure all 10.77.x.0/24 via transit (for client subnets already handled, but add missing)
for net in 10.77.11.0/24 10.77.12.0/24 10.77.13.0/24 10.77.14.0/24 10.77.15.0/24 10.77.16.0/24 10.77.17.0/24 10.77.18.0/24 10.77.19.0/24 10.77.20.0/24 10.77.21.0/24 10.77.22.0/24 10.77.23.0/24 10.77.24.0/24 10.77.25.0/24 10.77.26.0/24 10.77.8.0/24 10.77.9.0/24; do
    # Add route via transit if not already via protected; keep existing if any
    ip route add ${net} via 10.77.0.20 2>/dev/null || true
    ip route add ${net} via 10.77.0.10 2>/dev/null || true
done 2>/dev/null || true

# Show interfaces / routing for debugging
echo "[entrypoint] interfaces:"
ip -4 addr show 2>&1 | sed 's/^/  /'
ip -6 addr show 2>&1 | sed 's/^/  /'
echo "[entrypoint] routes v4:"
ip -4 route show 2>&1 | sed 's/^/  /'
echo "[entrypoint] routes v6:"
ip -6 route show 2>&1 | sed 's/^/  /'

# Start strongSwan
echo "[entrypoint] starting charon (ipsec start) ..."
mkdir -p /var/run

# ipsec start uses starter; loads charon but NOT swanctl configs — we load them explicitly via vici.
ipsec start --nofork &
IPSEC_PID=$!

# Wait for vici socket
for i in $(seq 1 20); do
    if [ -S /var/run/charon.vici ]; then
        echo "[entrypoint] vici socket ready after ${i}s"
        break
    fi
    sleep 1
done

echo "[entrypoint] charon started (pid $IPSEC_PID), vici socket: $(ls -l /var/run/charon.vici 2>&1)"

# Load swanctl configs (connections + secrets) — retries until charon vici answers
for i in $(seq 1 10); do
    if swanctl --load-all 2>&1 | grep -qi "error"; then
        echo "[entrypoint] swanctl --load-all attempt $i had error, retrying..."
        sleep 1
    else
        swanctl --load-all 2>&1 | sed 's/^/  [load-all] /' || true
        break
    fi
done
# Ensure loaded even if previous filtered
swanctl --load-all 2>&1 | sed 's/^/  [load-all] /' || true

echo "[entrypoint] swanctl --list-conns:"
swanctl --list-conns 2>&1 | sed 's/^/  /' || true
echo "[entrypoint] ipsec status:"
ipsec status 2>&1 | sed 's/^/  /' || true

# Initiate CHILD_SA (start_action=start should auto-initiate, but trigger explicitly for reliability)
echo "[entrypoint] initiating SA (swanctl --initiate)..."
swanctl --initiate --child net-v4v6 2>&1 | sed 's/^/  [init] /' || true
sleep 2
swanctl --list-sas 2>&1 | sed 's/^/  [sas] /' || true

# If an explicit command was passed, exec it; otherwise keep alive and log
if [ $# -gt 0 ]; then
    exec "$@"
else
    echo "[entrypoint] gateway ready — tailing charon (ctrl-c to stop)"
    # Keep container alive; charon logs already to stderr
    wait $IPSEC_PID
fi
