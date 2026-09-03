#!/usr/bin/env python3
"""Minimal pcap IO (stdlib only): static read, growing-file tail, writer.

One code path serves live-tail, static replay, and pipe streams, so live
and replayed traffic always feed the same event pipeline.
"""
import os
import struct
import time

GLOBAL_HDR = 24
REC_HDR = 16

# magic -> (byte_order, resolution_scale_to_seconds)
MAGICS = {
    0xA1B2C3D4: (">", 1e-6),
    0xD4C3B2A1: ("<", 1e-6),
    0xA1B23C4D: (">", 1e-9),
    0x4D3CB2A1: ("<", 1e-9),
}

# Common link types we accept (we only need IP/UDP bytes downstream).
LINKTYPE_NAMES = {1: "EN10MB", 101: "RAW", 113: "LINUX_SLL", 228: "IPV4", 229: "IPV6"}


class CorruptPcap(Exception):
    pass


class PcapReader:
    """Yields (timestamp_float, raw_bytes). follow=True tails a growing file."""

    def __init__(self, path=None, fh=None, follow=False, poll_interval=0.25,
                 stop_event=None, wait_timeout=30.0, max_frame=262144):
        self.path = path
        self.fh = fh
        self.own = False
        self.follow = follow
        self.poll = poll_interval
        self.stop = stop_event
        self.wait_timeout = wait_timeout
        self.max_frame = max_frame
        self.linktype = None
        self.linkname = "UNKNOWN"
        self.packets_read = 0
        self.bytes_read = 0

    def _stopped(self):
        return self.stop is not None and self.stop.is_set()

    def _read_exact(self, fh, n):
        """Read exactly n bytes; in follow mode wait for growth, else None on EOF."""
        buf = b""
        deadline = time.time() + self.wait_timeout if self.follow else None
        while len(buf) < n:
            chunk = fh.read(n - len(buf))
            if chunk:
                buf += chunk
                continue
            if not self.follow:
                return None if not buf else (_ for _ in ()).throw(
                    CorruptPcap("truncated record"))
            if self._stopped():
                return None
            if deadline is not None and time.time() > deadline:
                # Keep waiting while not stopped; deadline only bounds header wait.
                deadline = time.time() + self.wait_timeout
            time.sleep(self.poll)
        return buf

    def _open(self):
        if self.fh is not None:
            return self.fh
        deadline = time.time() + self.wait_timeout
        while True:
            try:
                fh = open(self.path, "rb")
                self.own = True
                return fh
            except OSError:
                if not self.follow or self._stopped() or time.time() > deadline:
                    raise
                time.sleep(self.poll)

    def packets(self):
        fh = self._open()
        try:
            gh = self._read_exact(fh, GLOBAL_HDR)
            if gh is None:
                return
            magic = struct.unpack(">I", gh[:4])[0]
            if magic not in MAGICS:
                raise CorruptPcap("bad pcap magic 0x%08x" % magic)
            order, scale = MAGICS[magic]
            self.linktype = struct.unpack(order + "I", gh[20:24])[0]
            self.linkname = LINKTYPE_NAMES.get(self.linktype, "TYPE-%d" % self.linktype)
            while not self._stopped():
                rh = self._read_exact(fh, REC_HDR)
                if rh is None:
                    return
                ts_s, ts_f, incl, _orig = struct.unpack(order + "IIII", rh)
                if incl > self.max_frame:
                    raise CorruptPcap("implausible frame length %d" % incl)
                data = self._read_exact(fh, incl)
                if data is None:
                    return
                self.packets_read += 1
                self.bytes_read += incl
                yield (ts_s + ts_f * scale, bytes(data))
        finally:
            if self.own:
                try:
                    fh.close()
                except OSError:
                    pass


class PcapWriter:
    """Write a standard microsecond pcap (little-endian, EN10MB default)."""

    def __init__(self, path, linktype=1):
        self.fh = open(path, "wb")
        self.fh.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))

    def write(self, ts, raw):
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        self.fh.write(struct.pack("<IIII", sec, usec, len(raw), len(raw)))
        self.fh.write(raw)

    def close(self):
        try:
            self.fh.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()
