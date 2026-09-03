#!/bin/bash
set -e
echo "[client] $(hostname) starting — $(date -u +%FT%TZ)"
ip -4 addr show 2>&1 | sed 's/^/  /'
ip -4 route show 2>&1 | sed 's/^/  /'
ip -6 addr show 2>&1 | sed 's/^/  /' || true
ip -6 route show 2>&1 | sed 's/^/  /' || true

if [ $# -gt 0 ]; then
    exec "$@"
else
    # Keep alive for exec-based testing
    echo "[client] ready — sleeping"
    exec sleep infinity
fi
