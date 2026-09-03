#!/usr/bin/env python3
"""Live monitor orchestrator. Single convergence point: every packet,
whether sniffed live, tailed from a growing pcap, or replayed from a
static pcap, flows through ingest(). Raw packets are kept only in a
bounded in-memory ring (never written to long-term storage by default).
"""
import signal
import threading
import time
from collections import deque
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

from . import packets
from . import ike as ike_mod
from .flows import FlowTracker, spi_lifecycle
from .session import Correlator
from .store import Store
from . import ml_bridge
from . import security_bridge
from .changes import ChurnWatch, traffic_shift
from .pcapio import PcapReader

RAW_RING = 20000
RETIRE_AFTER = 30.0


class Monitor:
    def __init__(self, state_dir, analyzer_path, cli_path, schema, policy,
                 window_sec=10.0, ml_interval=15.0, do_ml=True, ring_mb=0,
                 linktype=1, threshold=0.60):
        self.store = Store(state_dir, ring_mb)
        self.correlator = Correlator()
        self.flows = FlowTracker()
        self.analyzer_path = analyzer_path
        self.cli_path = cli_path
        self.schema = schema
        self.policy = policy
        self.window_sec = window_sec
        self.ml_interval = ml_interval
        self.do_ml = do_ml
        self.linktype = linktype
        self.threshold = threshold
        self.raw = {}          # pid -> deque[(ts, raw)]
        self.ike_rekey = {}    # pid -> [ts of CREATE_CHILD_SA]
        self.churn = {}        # pid -> ChurnWatch
        self.last_ml = 0.0
        self.started_at = time.time()
        self.stats = {"packets": 0, "esp": 0, "ah": 0, "ike": 0,
                      "other": 0, "malformed": 0}
        self.linkname = "UNKNOWN"
        self.last_packet_ts = None
        self._state_lock = threading.RLock()

    # ---- ingest path (shared by live, tail, replay, sniff) ----
    def ingest(self, ts, raw):
        with self._state_lock:
            return self._ingest(ts, raw)

    def _ingest(self, ts, raw):
        self.stats["packets"] += 1
        self.last_packet_ts = ts
        ev = packets.parse_frame(raw, self.linktype, ts)
        if ev is None:
            self.stats["malformed"] += 1
            self.correlator.malformed += 1
            return None, []
        kind = ev["kind"]
        self.stats[kind] = self.stats.get(kind, 0) + 1
        if kind == "ike":
            parsed = ike_mod.parse_ike(
                _udp_payload(raw, self.linktype, ev),
                ev.get("sport"), ev.get("dport"))
            ev["ike"] = parsed
            if not parsed.get("ok"):
                self.stats["malformed"] += 1
                return None, []
        if kind in ("esp", "ah"):
            self.flows.update(ev)
        profile, changes = self.correlator.ingest(ev)
        pid = profile["profile_id"]
        ring = self.raw.setdefault(pid, deque(maxlen=RAW_RING))
        if kind in ("esp", "ah", "ike"):
            ring.append((ts, raw))
        if kind == "ike" and (ev.get("ike") or {}).get("exchange_name") == "CREATE_CHILD_SA":
            self.ike_rekey.setdefault(pid, []).append(ts)
        if any(c["type"] == "new_spi" for c in changes):
            watch = self.churn.setdefault(pid, ChurnWatch())
            hit = watch.note(ts)
            if hit:
                profile["change_history"].append(hit)
                changes.append(hit)
            self._refresh_rekey(profile, ts)
        try:
            self.store.log_event({k: v for k, v in ev.items() if k != "ike"}
                                 | ({"ike_summary": _ike_summary(ev.get("ike"))}
                                    if kind == "ike" else {}))
        except (TypeError, ValueError):
            pass
        if self.store.ring is not None:
            self.store.ring.write(ts, raw)
        return profile, changes

    def _refresh_rekey(self, profile, ts):
        spi_info = {}
        for sas in (profile.get("esp_sas", {}), profile.get("ah_sas", {})):
            for spi, s in sas.items():
                spi_info.setdefault(spi, {"first": s["first"], "last": s["last"]})
                spi_info[spi]["first"] = min(spi_info[spi]["first"], s["first"])
                spi_info[spi]["last"] = max(spi_info[spi]["last"], s["last"])
        status, evidence = spi_lifecycle(
            spi_info, ike_rekey_times=self.ike_rekey.get(profile["profile_id"], []))
        old = profile.get("rekey_status")
        profile["rekey_status"] = status
        profile["rekey_evidence"] = evidence
        if old != status and old is not None and status == "rekey_observed":
            profile["change_history"].append(
                {"ts": ts, "type": "rekey_lifecycle",
                 "detail": "temporal SPI transition consistent with rekey",
                 "previous": old, "new": status,
                 "provenance": "deterministically_derived", "source": "SPI timeline"})

    def sweep(self, now=None):
        """Retire stale SPIs; recompute lifecycle states."""
        now = now if now is not None else time.time()
        for pid, p in self.correlator.profiles.items():
            for sas in (p.get("esp_sas", {}), p.get("ah_sas", {})):
                for spi, s in sas.items():
                    if not s.get("retired") and now - s["last"] > RETIRE_AFTER:
                        s["retired"] = True
                        p["change_history"].append(
                            {"ts": now, "type": "spi_retired",
                             "detail": "SPI %s unseen for %.0fs" % (spi, RETIRE_AFTER),
                             "previous": spi, "new": None,
                             "provenance": "deterministically_derived",
                             "source": "SPI timeline"})
            self._refresh_rekey(p, now)

    def maybe_ml(self, now=None, force=False):
        with self._state_lock:
            return self._maybe_ml(now, force)

    def _maybe_ml(self, now=None, force=False):
        now = now if now is not None else time.time()
        if not self.do_ml:
            return
        if not force and now - self.last_ml < self.ml_interval:
            return
        self.last_ml = now
        for pid, p in self.correlator.profiles.items():
            ring = self.raw.get(pid, deque())
            window = [(t, r) for t, r in ring if now - t <= self.window_sec]
            if len(window) < ml_bridge.WINDOW_MIN_PACKETS:
                if p["traffic"]["reason"] == "no_prediction_yet":
                    p["traffic"] = {"label": "Unknown", "confidence": 0.0,
                                    "probabilities": {}, "reason": "insufficient_packets",
                                    "explanation": ml_bridge.REASON_TEXT["insufficient_packets"]
                                    + " Window holds %d packets." % len(window)}
                continue
            old_label = p["traffic"].get("label")
            res = ml_bridge.analyze_window(
                window, self.linktype, self.analyzer_path, self.cli_path,
                self.schema, ROOT, threshold=self.threshold)
            p["traffic"] = res
            shift = traffic_shift(now, old_label, res)
            if shift:
                p["change_history"].append(shift)
            p["security"] = security_bridge.assess_profile(p, self.policy)

    def snapshot(self):
        with self._state_lock:
            self.sweep()
            state = {"monitor": "monitor-v1",
                     "sensor": {"started_at": self.started_at,
                                 "status": "LIVE",
                                 "link": self.linkname,
                                 "last_packet_ts": self.last_packet_ts,
                                 "stats": dict(self.stats)},
                     "generated_at": time.time(),
                     "profiles": list(self.correlator.profiles.values())}
            self.store.save_snapshot(state)
            self.store.heartbeat({"status": "LIVE",
                                  "last_packet_ts": self.last_packet_ts,
                                  "profiles": len(self.correlator.profiles),
                                  "stats": dict(self.stats)})
            return state

    def process_stream(self, reader, max_packets=None):
        n = 0
        publish_stop = threading.Event()
        publisher = None
        if reader.follow:
            # Publish independently so idle live monitors still refresh their heartbeat.
            def publish():
                while not publish_stop.wait(1.0):
                    self.snapshot()
            publisher = threading.Thread(target=publish, name="monitor-publisher",
                                         daemon=True)
            publisher.start()
        try:
            for ts, raw in reader.packets():
                if reader.stop is not None and reader.stop.is_set():
                    break
                self.ingest(ts, raw)
                n += 1
                if n % 200 == 0:
                    self.maybe_ml()
                if max_packets and n >= max_packets:
                    break
            self.maybe_ml(force=True)
            return self.snapshot()
        finally:
            if publisher is not None:
                publish_stop.set()
                publisher.join(timeout=2.0)


def _udp_payload(raw, linktype, ev):
    try:
        if linktype == 1:
            off = 14
        elif linktype == 113:
            off = 16
        else:
            off = 0
        ver = ev["ip_version"]
        if ver == 4:
            ihl = (raw[off] & 0x0F) * 4
            return raw[off + ihl + 8:]
        if ver == 6:
            return raw[off + 40 + 8:]
    except IndexError:
        pass
    return b""


def _ike_summary(parsed):
    if not parsed:
        return {}
    return {k: parsed.get(k) for k in ("version", "exchange_name", "initiator",
                                       "response", "message_id", "truncated")
            if k in parsed}
