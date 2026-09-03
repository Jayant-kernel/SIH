#!/usr/bin/env python3
"""
Deterministic PCAP feature extractor for IPsec dataset - Phase 3.5
Fixes:
- Rekey detection: 2 SPIs (bidirectional) does NOT imply rekey. Requires >2 unique ESP/AH SPIs or temporal transition evidence.
- Burstiness features: CV of IAT and size, burst count/size/duration, idle gaps, direction ratio.
- SPI misuse: raw SPIs kept for evidence but ML should use counts only.
- Empty pcap handling.

Usage: python pcap_features.py capture.pcap [--out features.json]
"""
import argparse, json, os, sys, statistics, re, subprocess

def try_scapy(pcap):
    try:
        from scapy.all import rdpcap
        pkts = rdpcap(pcap)
        return pkts, "scapy"
    except Exception as e:
        return None, str(e)

def parse_with_scapy(pkts):
    total = len(pkts)
    if total == 0:
        return _empty_features()

    times = []
    lens = []
    ipv4 = ipv6 = udp500 = udp4500 = esp = ah = ike = 0
    a2b = b2a = a2b_b = b2a_b = 0
    esp_spis = []
    ah_spis = []
    first_src = None
    # For rekey temporal: track SPI first seen time
    spi_first_seen = {}
    spi_last_seen = {}
    for p in pkts:
        try:
            t = float(p.time)
            times.append(t)
        except:
            pass
        l = len(p)
        lens.append(l)
        # Track SPI times
        # Extract SPI via ESP/AH layer if present, else via raw tcpdump fallback later
        spi_val = None
        if p.haslayer("IP"):
            ipv4 += 1
            ip = p["IP"]
            src = str(ip.src); dst = str(ip.dst)
            if first_src is None:
                first_src = src
            if src == first_src:
                a2b += 1; a2b_b += l
            else:
                b2a += 1; b2a_b += l
            try:
                proto = int(ip.proto)
                if proto == 50:
                    esp += 1
                elif proto == 51:
                    ah += 1
            except:
                pass
            if p.haslayer("UDP"):
                udp = p["UDP"]
                if udp.sport in (500, 4500) or udp.dport in (500, 4500):
                    ike += 1
                    if udp.sport == 500 or udp.dport == 500:
                        udp500 += 1
                    if udp.sport == 4500 or udp.dport == 4500:
                        udp4500 += 1
            if p.haslayer("ESP"):
                try:
                    spi = p["ESP"].spi
                    hv = hex(spi)
                    esp_spis.append(hv)
                    spi_val = hv
                except:
                    pass
            if p.haslayer("AH"):
                try:
                    spi = p["AH"].spi
                    hv = hex(spi)
                    ah_spis.append(hv)
                    if hv not in spi_first_seen:
                        spi_first_seen[hv] = t
                    spi_last_seen[hv] = t
                except:
                    pass
            if spi_val:
                if spi_val not in spi_first_seen:
                    spi_first_seen[spi_val] = t
                spi_last_seen[spi_val] = t
        elif p.haslayer("IPv6"):
            ipv6 += 1
            ip6 = p["IPv6"]
            src = str(ip6.src); dst = str(ip6.dst)
            if first_src is None:
                first_src = src
            if src == first_src:
                a2b += 1; a2b_b += l
            else:
                b2a += 1; b2a_b += l
            try:
                nh = int(ip6.nh)
                if nh == 50:
                    esp += 1
                elif nh == 51:
                    ah += 1
            except:
                pass
            if p.haslayer("UDP"):
                udp = p["UDP"]
                if udp.sport in (500, 4500) or udp.dport in (500, 4500):
                    ike += 1
                    if udp.sport == 500 or udp.dport == 500:
                        udp500 += 1
                    if udp.sport == 4500 or udp.dport == 4500:
                        udp4500 += 1
            if p.haslayer("ESP"):
                try:
                    hv = hex(p["ESP"].spi)
                    esp_spis.append(hv)
                    if hv not in spi_first_seen:
                        spi_first_seen[hv] = t
                    spi_last_seen[hv] = t
                except:
                    pass
            if p.haslayer("AH"):
                try:
                    hv = hex(p["AH"].spi)
                    ah_spis.append(hv)
                    if hv not in spi_first_seen:
                        spi_first_seen[hv] = t
                    spi_last_seen[hv] = t
                except:
                    pass
        else:
            pass

    # Timing and size
    times_sorted = sorted(times)
    duration = (max(times) - min(times)) if len(times) > 1 else 0
    pps = total / duration if duration > 0 else 0
    bps = sum(lens) / duration if duration > 0 else 0
    iats = [times_sorted[i] - times_sorted[i-1] for i in range(1, len(times_sorted))]
    mean_iat = statistics.mean(iats) if iats else 0
    median_iat = statistics.median(iats) if iats else 0
    std_iat = statistics.stdev(iats) if len(iats) > 1 else 0
    cv_iat = (std_iat / mean_iat) if mean_iat else 0

    mean_len = statistics.mean(lens) if lens else 0
    median_len = statistics.median(lens) if lens else 0
    min_len = min(lens) if lens else 0
    max_len = max(lens) if lens else 0
    std_len = statistics.stdev(lens) if len(lens) > 1 else 0
    cv_len = (std_len / mean_len) if mean_len else 0

    small = sum(1 for x in lens if x < 200)
    medium = sum(1 for x in lens if 200 <= x < 1000)
    large = sum(1 for x in lens if x >= 1000)

    uniq_esp = len(set(esp_spis))
    uniq_ah = len(set(ah_spis))

    # Burst definition: consecutive packets with IAT < 0.1s are in same burst; else gap
    # Burstiness features
    burst_threshold = 0.1  # seconds
    idle_threshold = 0.5   # seconds for idle gap
    bursts = []
    current_burst = []
    idle_gaps = 0
    for idx, t in enumerate(times_sorted):
        if idx == 0:
            current_burst = [t]
        else:
            iat = t - times_sorted[idx-1]
            if iat < burst_threshold:
                current_burst.append(t)
            else:
                if len(current_burst) > 1:
                    bursts.append(current_burst)
                elif len(current_burst) == 1:
                    bursts.append(current_burst)
                # idle gap if iat > idle_threshold
                if iat > idle_threshold:
                    idle_gaps += 1
                current_burst = [t]
    if current_burst:
        bursts.append(current_burst)
    burst_count = len(bursts)
    burst_sizes = [len(b) for b in bursts]
    avg_burst_size = statistics.mean(burst_sizes) if burst_sizes else 0
    burst_durations = [(b[-1]-b[0]) if len(b)>1 else 0 for b in bursts]
    avg_burst_duration = statistics.mean(burst_durations) if burst_durations else 0

    ratio = a2b / (b2a if b2a else 1)
    byte_ratio = a2b_b / (b2a_b if b2a_b else 1)

    # Two directional SPIs are normal. Multiple SPIs are only suggestive until
    # runtime lifecycle evidence corroborates the transition.
    rekey_observed = False
    rekey_status = "unknown"
    rekey_evidence = []
    # Count unique SPIs from scapy
    total_unique = uniq_esp + uniq_ah
    if uniq_esp > 2 or uniq_ah > 2:
        rekey_status = "possible_rekey"
        rekey_evidence.append(f"multiple SPIs: esp {uniq_esp} ah {uniq_ah}")
    elif total_unique > 2:
        rekey_status = "possible_rekey"
        rekey_evidence.append(f"total_unique {total_unique} >2")
    else:
        rekey_status = "no_rekey"
        rekey_evidence.append("<=2 directional SPIs and no lifecycle evidence")

    # If pcap has no SPI info but we have esp packets, we cannot determine rekey, set unknown
    if total_unique == 0 and (esp > 0 or ah > 0):
        rekey_status = "unknown"
        rekey_evidence = ["SPI not parseable from pcap, insufficient evidence"]

    return {
        "capture": {
            "total_packets": total,
            "duration": round(duration, 3),
            "total_bytes": sum(lens),
            "ipv4_count": ipv4,
            "ipv6_count": ipv6,
            "ike_packets": ike,
            "udp500": udp500,
            "udp4500": udp4500,
            "esp_packets": esp,
            "ah_packets": ah,
            "pps": round(pps, 2),
            "bps": round(bps, 2)
        },
        "size": {
            "mean": round(mean_len, 2),
            "median": median_len,
            "min": min_len,
            "max": max_len,
            "std": round(std_len, 2),
            "cv": round(cv_len, 4),
            "small_lt200": small,
            "medium_200_1000": medium,
            "large_ge1000": large
        },
        "direction": {
            "a_to_b_packets": a2b,
            "b_to_a_packets": b2a,
            "a_to_b_bytes": a2b_b,
            "b_to_a_bytes": b2a_b,
            "ratio_a2b_b2a": round(ratio, 3),
            "byte_ratio_a2b_b2a": round(byte_ratio, 3)
        },
        "timing": {
            "mean_iat": round(mean_iat, 5),
            "median_iat": round(median_iat, 5),
            "std_iat": round(std_iat, 5),
            "cv_iat": round(cv_iat, 4)
        },
        "burstiness": {
            "burst_threshold": burst_threshold,
            "idle_threshold": idle_threshold,
            "burst_count": burst_count,
            "avg_burst_size": round(avg_burst_size, 2),
            "avg_burst_duration": round(avg_burst_duration, 4),
            "burst_sizes": burst_sizes[:10],  # first 10 for debug, not for ML
            "idle_gap_count": idle_gaps
        },
        "esp_ah": {
            "esp_spis": sorted(set(esp_spis)),  # kept for evidence/debug, NOT for ML
            "esp_spi_count": uniq_esp,
            "ah_spis": sorted(set(ah_spis)),
            "ah_spi_count": uniq_ah,
            "unique_spi_total": total_unique
        },
        "rekey": {
            "unique_esp_spis": uniq_esp,
            "unique_ah_spis": uniq_ah,
            "rekey_observed": rekey_observed,
            "rekey_status": rekey_status,
            "rekey_evidence": rekey_evidence
        },
        "meta": {
            "parser": "scapy",
            "pcap": os.path.basename(pkts[0].name) if hasattr(pkts[0], "name") and pkts else "pcap"
        }
    }

def _empty_features():
    return {"capture":{"total_packets":0,"duration":0,"total_bytes":0,"ipv4_count":0,"ipv6_count":0,"ike_packets":0,"udp500":0,"udp4500":0,"esp_packets":0,"ah_packets":0,"pps":0,"bps":0},"size":{"mean":0,"median":0,"min":0,"max":0,"std":0,"cv":0,"small_lt200":0,"medium_200_1000":0,"large_ge1000":0},"direction":{"a_to_b_packets":0,"b_to_a_packets":0,"a_to_b_bytes":0,"b_to_a_bytes":0,"ratio_a2b_b2a":0,"byte_ratio_a2b_b2a":0},"timing":{"mean_iat":0,"median_iat":0,"std_iat":0,"cv_iat":0},"burstiness":{"burst_threshold":0.1,"idle_threshold":0.5,"burst_count":0,"avg_burst_size":0,"avg_burst_duration":0,"burst_sizes":[],"idle_gap_count":0},"esp_ah":{"esp_spis":[],"esp_spi_count":0,"ah_spis":[],"ah_spi_count":0,"unique_spi_total":0},"rekey":{"unique_esp_spis":0,"unique_ah_spis":0,"rekey_observed":False,"rekey_status":"no_rekey","rekey_evidence":["empty pcap"]},"meta":{"parser":"scapy","pcap":"empty"}}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", help="capture.pcap")
    ap.add_argument("--out", help="output json path")
    ap.add_argument("--lifecycle-evidence", help="runtime lifecycle evidence text file")
    args = ap.parse_args()
    if not os.path.exists(args.pcap):
        print(f"pcap not found {args.pcap}", file=sys.stderr); sys.exit(1)
    pkts, info = try_scapy(args.pcap)
    if pkts is not None:
        feat = parse_with_scapy(pkts)
    else:
        # fallback to tcpdump counting
        try:
            out = __import__("subprocess").run(["tcpdump","-r",args.pcap,"-n"], capture_output=True, text=True, timeout=10)
            txt = out.stdout+out.stderr
            total = txt.count("\n")
            esp = txt.count("ESP(")
            ah = txt.count("AH(")
            ike = txt.count("isakmp")
            feat = _empty_features()
            feat["capture"]["total_packets"] = total
            feat["capture"]["esp_packets"] = esp
            feat["capture"]["ah_packets"] = ah
            feat["capture"]["ike_packets"] = ike
            feat["meta"]["parser"] = "tcpdump"
        except Exception as e:
            feat = _empty_features()
            feat["meta"]["error"] = str(e)
    if "capture" not in feat:
        feat["capture"] = {"total_packets":0,"duration":0,"total_bytes":0,"ipv4_count":0,"ipv6_count":0,"ike_packets":0,"udp500":0,"udp4500":0,"esp_packets":0,"ah_packets":0,"pps":0,"bps":0}
    feat["capture"]["pcap"] = os.path.basename(args.pcap)
    # tcpdump fallback for SPI if scapy missed
    if feat.get("esp_ah",{}).get("esp_spi_count",0)==0 and feat["capture"].get("esp_packets",0)>0:
        try:
            out = __import__("subprocess").run(["tcpdump","-r",args.pcap,"-n"], capture_output=True, text=True, timeout=5)
            txt = out.stdout
            spis = re.findall(r"spi=0x[0-9a-fA-F]+", txt)
            uniq = len(set(spis))
            feat.setdefault("esp_ah",{})["esp_spis_tcpdump"] = sorted(set(spis))
            feat["esp_ah"]["esp_spi_count"] = uniq
            # Update rekey based on tcpdump SPIs
            if uniq > 2:
                feat["rekey"]["rekey_observed"] = False
                feat["rekey"]["rekey_status"] = "possible_rekey"
                feat["rekey"]["rekey_evidence"] = [f"tcpdump multiple spi {uniq}; lifecycle evidence required"]
            elif uniq <= 2 and uniq > 0:
                feat["rekey"]["rekey_observed"] = False
                feat["rekey"]["rekey_status"] = "no_rekey"
                feat["rekey"]["rekey_evidence"] = [f"tcpdump unique spi {uniq} <=2 normal"]
        except:
            pass
    # Packet text alone is not sufficient to claim a rekey.
    try:
        out = __import__("subprocess").run(["tcpdump","-r",args.pcap,"-n","-v"], capture_output=True, text=True, timeout=5)
        if "CREATE_CHILD_SA" in out.stdout or "child_sa" in out.stdout.lower():
            feat["rekey"]["rekey_evidence"].append("CREATE_CHILD_SA in pcap")
            if feat["rekey"].get("rekey_status") == "possible_rekey":
                feat["rekey"]["rekey_observed"] = True
                feat["rekey"]["rekey_status"] = "rekey_observed"
    except:
        pass

    if args.lifecycle_evidence and os.path.exists(args.lifecycle_evidence):
        try:
            with open(args.lifecycle_evidence, errors="replace") as f:
                lifecycle = f.read()
            if re.search(r"CREATE_CHILD_SA|REKEY|rekey|INSTALLED.*DELETED|DELETED.*INSTALLED", lifecycle, re.I | re.S) and feat["rekey"].get("rekey_status") == "possible_rekey":
                feat["rekey"]["rekey_observed"] = True
                feat["rekey"]["rekey_status"] = "rekey_observed"
                feat["rekey"]["rekey_evidence"].append("runtime lifecycle evidence")
        except:
            pass

    out_path = args.out or os.path.splitext(args.pcap)[0]+"_features.json"
    if os.path.isdir(out_path):
        out_path = os.path.join(out_path, os.path.splitext(os.path.basename(args.pcap))[0]+"_features.json")
    with open(out_path, "w") as f:
        import json as js
        js.dump(feat, f, indent=2)
    import json as js
    print(js.dumps(feat, indent=2))
    print(f"\n[features] wrote {out_path}", file=sys.stderr)

if __name__ == "__main__":
    main()
