#!/usr/bin/env python3
"""Send one IPv6 UDP datagram and require an echo response."""
import argparse
import socket

parser = argparse.ArgumentParser()
parser.add_argument("peer")
parser.add_argument("port", type=int)
args = parser.parse_args()

sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.settimeout(2)
sock.sendto(b"t15-readiness", (args.peer, args.port, 0, 0))
payload, address = sock.recvfrom(128)
if payload != b"t15-readiness":
    raise SystemExit("unexpected UDP response")
print(f"READY {address[0]}:{address[1]}")
