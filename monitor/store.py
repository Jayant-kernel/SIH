#!/usr/bin/env python3
"""Evidence store: append-only JSONL event log, atomic profile snapshots,
heartbeat, and an OPTIONAL short rolling pcap ring (default off).

Default long-term storage is metadata/evidence, never raw payloads.
Raw packets live only in memory (bounded ring) for rolling ML windows.
"""
import json
import os
import time

from .pcapio import PcapWriter


class Store:
    def __init__(self, state_dir, ring_mb=0):
        self.state_dir = state_dir
        os.makedirs(state_dir, exist_ok=True)
        self.events_path = os.path.join(state_dir, "events.jsonl")
        self.snapshot_path = os.path.join(state_dir, "live_profiles.json")
        self.heartbeat_path = os.path.join(state_dir, "heartbeat.json")
        self.ring = RollingPcap(state_dir, ring_mb) if ring_mb and ring_mb > 0 else None

    def log_event(self, ev):
        try:
            with open(self.events_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(ev, default=str) + "\n")
        except OSError:
            pass

    def save_snapshot(self, obj):
        tmp = self.snapshot_path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(obj, fh, indent=2, default=str)
            os.replace(tmp, self.snapshot_path)
        except OSError:
            pass

    def load_snapshot(self):
        try:
            with open(self.snapshot_path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    def heartbeat(self, info):
        info = dict(info)
        info["ts"] = time.time()
        try:
            with open(self.heartbeat_path, "w", encoding="utf-8") as fh:
                json.dump(info, fh, indent=2, default=str)
        except OSError:
            pass


class RollingPcap:
    """Tiny rotating raw ring for diagnostics. Disabled unless ring_mb > 0."""

    def __init__(self, state_dir, ring_mb, linktype=1):
        self.dir = os.path.join(state_dir, "ring")
        os.makedirs(self.dir, exist_ok=True)
        self.budget = int(ring_mb * 1024 * 1024)
        self.used = 0
        self.idx = 0
        self.w = None
        self.linktype = linktype

    def _rotate(self):
        if self.w is not None:
            self.w.close()
        path = os.path.join(self.dir, "ring-%d.pcap" % (self.idx % 2))
        try:
            if os.path.exists(path):
                self.used -= os.path.getsize(path)
        except OSError:
            pass
        self.w = PcapWriter(path, self.linktype)
        self.idx += 1

    def write(self, ts, raw):
        if self.w is None:
            self._rotate()
        if self.used + len(raw) + 16 > self.budget:
            self._rotate()
            self.used = 0
        try:
            self.w.write(ts, raw)
            self.used += len(raw) + 16
        except OSError:
            pass

    def close(self):
        if self.w is not None:
            self.w.close()
            self.w = None
