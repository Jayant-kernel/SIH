#!/usr/bin/env python3
"""Minimal IPv6 UDP echo server used by the T15 readiness gate."""
import argparse
import socket

parser = argparse.ArgumentParser()
parser.add_argument("port", type=int)
args = parser.parse_args()

sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
sock.bind(("::", args.port))
while True:
    payload, address = sock.recvfrom(65535)
    sock.sendto(payload, address)
