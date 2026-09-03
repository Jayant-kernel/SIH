#!/usr/bin/env python3
"""Passive monitor CLI.

Three sources, ONE pipeline (monitor.Monitor.ingest):

  python -m monitor.run --pcap FILE        # deterministic replay
  python -m monitor.run --tail FILE        # follow a growing pcap (live sidecar)
  python -m monitor.run --interface eth0   # sniff locally (needs privileges)

The recommended live topology on this project keeps capture in the
gateway (tcpdump sidecar -> shared pcap) and runs the monitor with
--tail, so the monitor itself needs no network privileges.
"""
import argparse
import json
import signal
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from monitor.monitor import Monitor  # noqa: E402
from monitor.pcapio import PcapReader  # noqa: E402

DEFAULT_STATE = ROOT / "monitor" / "state"


def load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def build_monitor(args):
    policy = load_json(args.policy)
    schema = load_json(args.schema)
    return Monitor(state_dir=args.state, analyzer_path=args.analyzer,
                   cli_path=args.predict_cli, schema=schema, policy=policy,
                   window_sec=args.window, ml_interval=args.ml_interval,
                   do_ml=not args.no_ml, ring_mb=args.ring_mb,
                   linktype=args.linktype, threshold=args.threshold)


def run_file(mon, path, max_packets=None):
    reader = PcapReader(str(path))
    state = mon.process_stream(reader, max_packets=max_packets)
    mon.store.heartbeat({"status": "DONE", "profiles": len(mon.correlator.profiles),
                         "stats": dict(mon.stats)})
    return state


def run_tail(mon, path, stop):
    reader = PcapReader(str(path), follow=True, stop_event=stop)
    state = mon.process_stream(reader)
    mon.store.heartbeat({"status": "STOPPED", "profiles": len(mon.correlator.profiles),
                         "stats": dict(mon.stats)})
    return state


def run_interface(mon, iface, stop, snaplen=65535):
    try:
        from scapy.all import sniff  # lazy: only needed for local sniffing
    except ImportError:
        print("interface mode needs scapy + sniff privileges; use --tail with a "
              "tcpdump sidecar instead", file=sys.stderr)
        return None

    def cb(pkt):
        try:
            raw = bytes(pkt)
        except Exception:
            return
        mon.ingest(time.time(), raw)
    kwargs = {"iface": iface, "prn": cb, "store": False,
              "stop_filter": lambda _p: stop.is_set()}
    if snaplen:
        kwargs["snaplen"] = snaplen
    sniff(**kwargs)
    mon.maybe_ml(force=True)
    return mon.snapshot()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Continuous passive IPsec monitor")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="replay a static pcap through the live pipeline")
    src.add_argument("--tail", help="follow a growing pcap (live sidecar mode)")
    src.add_argument("--interface", help="sniff a local interface (needs privileges)")
    ap.add_argument("--state", default=str(DEFAULT_STATE))
    ap.add_argument("--window", type=float, default=10.0)
    ap.add_argument("--ml-interval", type=float, default=15.0)
    ap.add_argument("--no-ml", action="store_true")
    ap.add_argument("--ring-mb", type=float, default=0.0)
    ap.add_argument("--linktype", type=int, default=1)
    ap.add_argument("--threshold", type=float, default=0.60)
    ap.add_argument("--max-packets", type=int, default=0)
    ap.add_argument("--policy", default=str(ROOT / "security" / "policy" / "default_policy.json"))
    ap.add_argument("--schema", default=str(ROOT / "ml_v2" / "feature_schema.json"))
    ap.add_argument("--analyzer", default=str(ROOT / "analyzer" / "pcap_features.py"))
    ap.add_argument("--predict-cli", default=str(ROOT / "ml_v2" / "predict_traffic.py"))
    ap.add_argument("--summary", action="store_true")
    a = ap.parse_args(argv)
    mon = build_monitor(a)
    stop = threading.Event()

    def _stop(*_a):
        stop.set()

    signal.signal(signal.SIGTERM, _stop)
    try:
        signal.signal(signal.SIGINT, _stop)
    except ValueError:
        pass
    print("monitor: starting (state=%s)" % a.state, flush=True)
    if a.pcap:
        state = run_file(mon, a.pcap, max_packets=a.max_packets or None)
    elif a.tail:
        state = run_tail(mon, a.tail, stop)
    else:
        state = run_interface(mon, a.interface, stop)
    if state is None:
        return 2
    print("monitor: done profiles=%d packets=%d" %
          (len(mon.correlator.profiles), mon.stats["packets"]), flush=True)
    if a.summary:
        print(json.dumps({k: (len(v) if isinstance(v, dict) else v)
                          for k, v in state["sensor"].items()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
