#!/usr/bin/env python3
"""ESP/AH flow tracking with corrected rekey semantics.

Two directional SPIs are NORMAL and never imply rekey. A rekey is only
reported when a temporal SPI transition is observed (a new SPI appears
after previously seen SPIs stop), optionally corroborated by a
CREATE_CHILD_SA exchange nearby in time. Concurrent >2 SPIs without
temporal evidence is possible_rekey, never rekey_observed.
"""
import statistics

SIZE_CAP = 2048  # per-flow retained sizes (stats only, no payload)


class FlowTracker:
    def __init__(self):
        self.flows = {}  # (proto, src, dst, spi) -> stats dict
        self.malformed = 0

    def update(self, ev):
        """ev: packet event with kind esp/ah, ts, src, dst, spi, size."""
        if ev.get("kind") not in ("esp", "ah"):
            return None
        key = (ev["kind"], ev["src"], ev["dst"], ev.get("spi") or "?")
        f = self.flows.get(key)
        if f is None:
            f = {"proto": key[0], "src": key[1], "dst": key[2], "spi": key[3],
                 "first": ev["ts"], "last": ev["ts"], "packets": 0, "bytes": 0,
                 "sizes": []}
            self.flows[key] = f
        f["last"] = ev["ts"]
        f["packets"] += 1
        f["bytes"] += ev.get("size", 0)
        if len(f["sizes"]) < SIZE_CAP:
            f["sizes"].append(ev.get("size", 0))
        return f

    def relationships(self):
        """Group opposite directions of the same (proto, endpoint-pair)."""
        rels = {}
        for (proto, src, dst, spi), f in self.flows.items():
            pair = tuple(sorted((src, dst)))
            r = rels.setdefault((proto, pair),
                                {"proto": proto, "endpoints": pair, "spis": {}})
            s = r["spis"].setdefault(spi, {"first": f["first"], "last": f["last"],
                                           "packets": 0, "bytes": 0,
                                           "a_to_b": 0, "b_to_a": 0})
            s["first"] = min(s["first"], f["first"])
            s["last"] = max(s["last"], f["last"])
            s["packets"] += f["packets"]
            s["bytes"] += f["bytes"]
            if (src, dst) == pair:
                s["a_to_b"] += f["packets"]
            else:
                s["b_to_a"] += f["packets"]
        return rels


def spi_lifecycle(spi_info, ike_rekey_times=(), gap=0.5, window=10.0):
    """Classify SPI lifecycle. Returns (status, evidence_list).

    spi_info: {spi: {"first": t, "last": t}}. ike_rekey_times: timestamps of
    observed CREATE_CHILD_SA exchanges for corroboration.
    """
    spis = sorted(spi_info, key=lambda s: spi_info[s]["first"])
    if len(spis) <= 2:
        return ("no_rekey", ["<=2 directional SPIs (normal SA pair)"])
    # Temporal transition: a later SPI starts after earlier ones stopped.
    ordered = [(spi_info[s]["first"], spi_info[s]["last"], s) for s in spis]
    transition = None
    for i in range(1, len(ordered)):
        earlier_last = max(o[1] for o in ordered[:i])
        if ordered[i][0] > earlier_last + gap:
            transition = (ordered[i][2], ordered[i][0])
            break
    if transition:
        ev = ["SPI transition: %s first seen %.3f after predecessors stopped"
              % transition]
        for t in ike_rekey_times:
            if abs(t - transition[1]) <= window:
                ev.append("CREATE_CHILD_SA within %.0fs corroborates rekey" % window)
                break
        return ("rekey_observed", ev)
    # Concurrent overlap only: corroborating exchange upgrades to observed.
    if ike_rekey_times:
        return ("rekey_observed",
                ["%d concurrent SPIs with CREATE_CHILD_SA exchange observed" % len(spis)])
    return ("possible_rekey",
            ["%d concurrent SPIs without temporal transition; lifecycle evidence required"
             % len(spis)])


def iat_stats(times):
    if len(times) < 2:
        return {"mean": 0.0, "std": 0.0}
    iats = [b - a for a, b in zip(sorted(times), sorted(times)[1:])]
    mean = statistics.mean(iats)
    return {"mean": mean, "std": statistics.stdev(iats) if len(iats) > 1 else 0.0}
