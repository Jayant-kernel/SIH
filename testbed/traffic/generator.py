#!/usr/bin/env python3
"""
Controlled traffic generator - Phase 3.5 with variation
Handles profile ranges with seed-based reproducibility.
"""
import argparse, json, os, sys, time, random, subprocess, socket

PROFILES_PATH = os.path.join(os.path.dirname(__file__), "profiles.json")

def load_profiles():
    with open(PROFILES_PATH) as f:
        data = json.load(f)
        # Filter out non-profile keys like profile_version
        return {k: v for k, v in data.items() if k != "profile_version"}

def get_profile_version():
    with open(PROFILES_PATH) as f:
        data = json.load(f)
        return data.get("profile_version", "unknown")

def log(msg):
    print(f"[generator] {msg}", flush=True)

def run_cmd(cmd, timeout=None):
    try:
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return out.returncode, out.stdout, out.stderr
    except Exception as e:
        return 1, "", str(e)

def peer_endpoint(peer, port):
    return (peer, port, 0, 0) if ":" in peer else (peer, port)

def peer_socket(peer, sock_type):
    return socket.socket(socket.AF_INET6 if ":" in peer else socket.AF_INET, sock_type)

def pick_range(profile, key, seed, default):
    # If key_range exists, pick random within range using seed
    range_key = key + "_range"
    if range_key in profile:
        lo, hi = profile[range_key]
        # Use deterministic random based on seed and key
        r = random.Random(f"{seed}-{key}")
        if isinstance(lo, float) or isinstance(hi, float):
            return r.uniform(lo, hi)
        else:
            return r.randint(lo, hi)
    return profile.get(key, default)

def gen_icmp(peer, duration, seed, profile):
    packet_size = int(pick_range(profile, "packet_size", seed, 64))
    interval = pick_range(profile, "interval", seed, 0.5)
    count = max(1, int(duration / interval))
    cmd = f"ping -c {count} -i {interval:.3f} -s {packet_size-28} {peer} 2>&1"
    log(f"ICMP: {cmd} (size {packet_size}, interval {interval:.3f})")
    rc, out, err = run_cmd(cmd, timeout=duration+10)
    log(out[-400:] if len(out) > 400 else out)
    return {"packets": count, "bytes": count * packet_size, "protocol": "icmp", "packet_size": packet_size, "interval": interval, "count": count}

def gen_udp_small(peer, port, duration, seed, profile):
    packet_size = int(pick_range(profile, "packet_size", seed, 80))
    pps = int(pick_range(profile, "pps", seed, 50))
    jitter = pick_range(profile, "jitter_range", seed, 0.01) if "jitter_range" in profile else 0
    # Handle jitter_range as [lo,hi] for jitter
    if "jitter_range" in profile:
        lo, hi = profile["jitter_range"]
        jitter = random.Random(f"{seed}-jitter").uniform(lo, hi)
    else:
        jitter = 0.01
    log(f"UDP small: {pps} pps, size {packet_size}, jitter {jitter:.3f}, dur {duration}s to {peer}:{port}")
    sock = peer_socket(peer, socket.SOCK_DGRAM)
    interval = 1.0 / pps if pps > 0 else 0.02
    sent = 0
    start = time.time()
    payload = b"V" * packet_size
    while time.time() - start < duration:
        try:
            sock.sendto(payload, peer_endpoint(peer, port))
            sent += 1
        except:
            pass
        # Add jitter
        j = random.Random(f"{seed}-{sent}").uniform(-jitter, jitter) if jitter else 0
        time.sleep(max(0.001, interval + j))
    sock.close()
    log(f"UDP small sent {sent} packets")
    return {"packets": sent, "bytes": sent * packet_size, "protocol": "udp", "packet_size": packet_size, "pps": pps, "jitter": jitter}

def gen_udp_messaging(peer, port, duration, seed, profile):
    packet_size = int(pick_range(profile, "packet_size", seed, 120))
    interval_min = pick_range(profile, "interval_min", seed, 0.1)
    interval_max = pick_range(profile, "interval_max", seed, 0.6)
    # Handle interval_min_range etc.
    if "interval_min_range" in profile:
        lo, hi = profile["interval_min_range"]
        interval_min = random.Random(f"{seed}-imin").uniform(lo, hi)
    if "interval_max_range" in profile:
        lo, hi = profile["interval_max_range"]
        interval_max = random.Random(f"{seed}-imax").uniform(lo, hi)
    messages = int(pick_range(profile, "messages", seed, 40))
    log(f"Messaging: {messages} msgs, size {packet_size}, interval {interval_min:.3f}-{interval_max:.3f}s")
    sock = peer_socket(peer, socket.SOCK_DGRAM)
    sent = 0
    for i in range(messages):
        if time.time() > time.time() + 10:  # dummy
            pass
        payload = f"msg-{i}-{random.Random(f'{seed}-{i}').randint(1000,9999)}".encode() + b"X" * (packet_size - 20)
        payload = payload[:packet_size]
        try:
            sock.sendto(payload, peer_endpoint(peer, port))
            sent += 1
        except:
            pass
        time.sleep(random.Random(f"{seed}-msg-{i}").uniform(interval_min, interval_max))
        if sent * 0.3 > duration:
            # estimate
            pass
    sock.close()
    log(f"Messaging sent {sent}")
    return {"packets": sent, "bytes": sent * packet_size, "packet_size": packet_size, "interval_min": interval_min, "interval_max": interval_max, "messages": messages}

def gen_http(peer, duration, seed, profile):
    requests = int(pick_range(profile, "requests", seed, 15))
    interval = pick_range(profile, "interval", seed, 0.6)
    request_size = int(pick_range(profile, "request_size", seed, 350))
    response_size = int(pick_range(profile, "response_size", seed, 2048))
    host = f"[{peer}]" if ":" in peer else peer
    log(f"HTTP: {requests} requests to http://{host}:8000/ interval {interval:.3f} req {request_size} resp {response_size}")
    sent = 0
    for i in range(requests):
        rc, out, err = run_cmd(f"curl -g -s -o /dev/null -w '%{{http_code}}' http://{host}:8000/ 2>&1", timeout=5)
        sent += 1
        time.sleep(random.Random(f"{seed}-http-{i}").uniform(interval*0.7, interval*1.3))
    log(f"HTTP done {sent} requests")
    return {"packets": sent * 4, "bytes": sent * (request_size + response_size), "requests": requests, "interval": interval, "request_size": request_size, "response_size": response_size}

def gen_bulk(peer, duration, seed, profile):
    bytes_target = int(pick_range(profile, "bytes", seed, 5000000))
    if "bytes_range" in profile:
        lo, hi = profile["bytes_range"]
        bytes_target = random.Random(f"{seed}-bytes").randint(lo, hi)
    log(f"Bulk: iperf3 to {peer} dur {duration}s target {bytes_target} bytes")
    rc, out, err = run_cmd(f"iperf3 -c {peer} -t {duration} -p 5201 2>&1", timeout=duration+10)
    if rc != 0 or "error" in out.lower():
        log("iperf3 failed, fallback to nc bulk")
        try:
            s = peer_socket(peer, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect(peer_endpoint(peer, 5201))
            data = b"B" * 65536
            sent = 0
            start = time.time()
            while time.time() - start < duration and sent < bytes_target:
                s.send(data)
                sent += len(data)
            s.close()
            log(f"nc bulk sent {sent}")
            return {"packets": sent // 1400, "bytes": sent, "bytes_target": bytes_target}
        except Exception as e:
            log(f"bulk fallback failed {e}, using ping bulk")
            return gen_icmp(peer, duration, seed, profile)
    log(out[-400:])
    return {"packets": 0, "bytes": bytes_target, "bytes_target": bytes_target}

def start_background_servers():
    run_cmd("pkill -f 'http.server 8000' 2>/dev/null; nohup python3 -m http.server 8000 --bind 0.0.0.0 >/tmp/http.log 2>&1 & echo http:$!")
    run_cmd("nohup python3 -m http.server 8000 --bind fd77:77:24::10 >/tmp/http6.log 2>&1 & echo http6:$!")
    run_cmd("pkill iperf3 2>/dev/null; nohup iperf3 -s -p 5201 >/tmp/iperf.log 2>&1 & echo iperf:$!")
    udp_servers = [
        "nohup python3 -c \"import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',5001));\nwhile True:\n d,a=s.recvfrom(65535);s.sendto(d,a)\" >/tmp/udp5001.log 2>&1 &",
        "nohup python3 -c \"import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',5002));\nwhile True:\n d,a=s.recvfrom(65535);s.sendto(d,a)\" >/tmp/udp5002.log 2>&1 &",
        "nohup python3 -c \"import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('0.0.0.0',5003));\nwhile True:\n d,a=s.recvfrom(65535);s.sendto(d,a)\" >/tmp/udp5003.log 2>&1 &",
    ]
    for cmd in udp_servers:
        run_cmd(cmd)
    ipv6_udp_servers = [
        "nohup python3 -c \"import socket; s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1); s.bind(('::',5001));\\nwhile True:\\n d,a=s.recvfrom(65535);s.sendto(d,a)\" >/tmp/udp6-5001.log 2>&1 &",
        "nohup python3 -c \"import socket; s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1); s.bind(('::',5002));\\nwhile True:\\n d,a=s.recvfrom(65535);s.sendto(d,a)\" >/tmp/udp6-5002.log 2>&1 &",
        "nohup python3 -c \"import socket; s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1); s.bind(('::',5003));\\nwhile True:\\n d,a=s.recvfrom(65535);s.sendto(d,a)\" >/tmp/udp6-5003.log 2>&1 &",
    ]
    for cmd in ipv6_udp_servers:
        run_cmd(cmd)
    time.sleep(1)
    log("background servers started (http 8000, iperf 5201, udp 5001-5003)")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", required=True, help="traffic profile name")
    ap.add_argument("--duration", type=int, default=None)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--peer", default="10.77.2.10", help="peer IP")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--start-servers", action="store_true", help="start background servers and exit")
    args = ap.parse_args()
    if args.list:
        print(json.dumps(load_profiles(), indent=2))
        return
    if args.start_servers:
        start_background_servers()
        return
    profiles = load_profiles()
    if args.profile not in profiles:
        print(f"unknown profile {args.profile}, available {list(profiles.keys())}", file=sys.stderr)
        sys.exit(1)
    p = profiles[args.profile]
    # Duration handling: if args.duration is None, pick from duration_range
    if args.duration is not None:
        duration = args.duration
    elif "duration_range" in p:
        lo, hi = p["duration_range"]
        duration = random.Random(f"{args.seed}-duration").randint(lo, hi)
    else:
        duration = p.get("duration", 10)
    seed = args.seed
    peer = args.peer
    # Dispatch with variation
    result = {}
    if args.profile == "icmp":
        result = gen_icmp(peer, duration, seed, p)
    elif args.profile == "voip-like":
        result = gen_udp_small(peer, 5001, duration, seed, p)
    elif args.profile == "video-like":
        result = gen_udp_small(peer, 5002, duration, seed, p)
        # video uses same gen but with larger size/pps
        # Already handled via profile variation
    elif args.profile == "messaging-like":
        result = gen_udp_messaging(peer, 5003, duration, seed, p)
    elif args.profile == "web":
        result = gen_http(peer, duration, seed, p)
    elif args.profile == "bulk-transfer":
        result = gen_bulk(peer, duration, seed, p)
    elif args.profile == "dns":
        result = gen_udp_messaging(peer, 5300, duration, seed, p)
        result["protocol"] = "udp"
    elif args.profile == "email-like":
        result = gen_http(peer, duration, seed, p)
        result["protocol"] = "tcp"
    else:
        result = gen_icmp(peer, duration, seed, p)
    # Enrich result with actual generated params
    result["actual_duration"] = duration
    result["seed"] = seed
    result["profile_version"] = get_profile_version()
    out = {"profile": args.profile, "duration": duration, "seed": seed, "peer": peer, "result": result, "profile_version": get_profile_version()}
    print(json.dumps(out))

if __name__ == "__main__":
    main()
