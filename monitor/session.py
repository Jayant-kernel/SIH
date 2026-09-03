#!/usr/bin/env python3
"""VPN session correlation and knowledge accumulation.

One persistent VPNProfile per endpoint pair. New evidence ENRICHES the
same profile (history preserved, nothing silently overwritten). If two
observations cannot be safely correlated (different endpoint pair) a new
profile is created instead of forcing a merge.
"""
import time

EVIDENCE_CAP = 500
CHANGES_CAP = 200


def pair_id(a, b):
    x, y = sorted((a, b))
    return "%s<->%s" % (x, y)


def transform_summary(proposal):
    parts = []
    for t in proposal.get("transforms", []):
        keylen = t.get("attrs", {}).get("keylen")
        name = t["name"] + ("-%d" % keylen if keylen else "")
        parts.append("%s(%s)" % (t["type"], name))
    return "%s:%s" % (proposal.get("protocol", "?"), "/".join(parts))


def new_profile(a, b, ts):
    x, y = sorted((a, b))
    return {
        "profile_id": pair_id(a, b),
        "gateway_a": x, "gateway_b": y,
        "first_seen": ts, "last_seen": ts, "last_evidence_update": ts,
        "packets": 0, "observations": 0,
        "protocols": [], "ip_versions": [], "natt": None,
        "ike": {"version": None, "exchanges": [], "offered": [],
                "selected": None, "ke_groups": [], "sessions": {},
                "fingerprint_versions": []},
        "esp_sas": {}, "ah_sas": {},
        "rekey_status": "unknown", "rekey_evidence": [],
        "traffic": {"label": "Unknown", "confidence": 0.0, "probabilities": {},
                    "reason": "no_prediction_yet",
                    "explanation": "No rolling ML window has been evaluated yet."},
        "security": {},
        "evidence_history": [], "change_history": [],
    }


def _note(p, ts, field, value, provenance, source):
    p["last_evidence_update"] = ts
    p["observations"] += 1
    p["evidence_history"].append({"ts": ts, "field": field, "value": value,
                                  "provenance": provenance, "source": source})
    if len(p["evidence_history"]) > EVIDENCE_CAP:
        del p["evidence_history"][:len(p["evidence_history"]) - EVIDENCE_CAP]


def _change(p, ts, ctype, detail, previous, new, provenance, source):
    p["change_history"].append({"ts": ts, "type": ctype, "detail": detail,
                                "previous": previous, "new": new,
                                "provenance": provenance, "source": source})
    if len(p["change_history"]) > CHANGES_CAP:
        del p["change_history"][:len(p["change_history"]) - CHANGES_CAP]


class Correlator:
    """Conservative correlator: endpoint pair is the correlation key."""

    def __init__(self):
        self.profiles = {}
        self.malformed = 0

    def ingest(self, ev):
        """ev: packet event dict (kind esp/ah/ike/other) with ts/src/dst.
        Returns (profile, changes)."""
        ts = ev["ts"]
        pid = pair_id(ev["src"], ev["dst"])
        p = self.profiles.get(pid)
        changes = []
        if p is None:
            p = new_profile(ev["src"], ev["dst"], ts)
            self.profiles[pid] = p
            c = {"ts": ts, "type": "profile_created",
                 "detail": "new gateway pair %s" % pid,
                 "previous": None, "new": pid,
                 "provenance": "directly_observed", "source": "packet"}
            p["change_history"].append(c)
            changes.append(c)
        p["last_seen"] = ts
        p["packets"] += 1
        kind = ev.get("kind")
        if kind in ("esp", "ah") and kind.upper() not in p["protocols"]:
            p["protocols"].append(kind.upper())
            _note(p, ts, "protocol", kind.upper(), "directly_observed",
                  "%s packet" % kind.upper())
        if ev.get("ip_version") not in p["ip_versions"]:
            p["ip_versions"].append(ev["ip_version"])
            _note(p, ts, "outer_ip_version",
                  "IPv%d" % ev["ip_version"], "directly_observed", "IP header")
        if ev.get("natt") and p["natt"] is not True:
            prev = p["natt"]
            p["natt"] = True
            _note(p, ts, "natt", True, "directly_observed", "UDP 4500")
            c = {"ts": ts, "type": "natt_changed", "detail": "NAT-T observed",
                 "previous": prev, "new": True,
                 "provenance": "directly_observed", "source": "UDP 4500"}
            p["change_history"].append(c)
            changes.append(c)
        if kind in ("esp", "ah"):
            changes += self._track_sa(p, ev, ts)
        elif kind == "ike":
            changes += self._track_ike(p, ev, ts)
        return p, changes

    def _track_sa(self, p, ev, ts):
        changes = []
        sas = p["esp_sas"] if ev["kind"] == "esp" else p["ah_sas"]
        spi = ev.get("spi") or "?"
        s = sas.get(spi)
        if s is None:
            sas[spi] = {"first": ts, "last": ts, "packets": 1,
                        "bytes": ev.get("size", 0)}
            _note(p, ts, "spi", spi, "directly_observed",
                  "%s packet" % ev["kind"].upper())
            c = {"ts": ts, "type": "new_spi",
                 "detail": "new %s SPI %s on %s" % (ev["kind"].upper(), spi, p["profile_id"]),
                 "previous": None, "new": spi,
                 "provenance": "directly_observed",
                 "source": "%s packet" % ev["kind"].upper()}
            p["change_history"].append(c)
            changes.append(c)
        else:
            s["last"] = ts
            s["packets"] += 1
            s["bytes"] += ev.get("size", 0)
        return changes

    def _track_ike(self, p, ev, ts):
        changes = []
        ike = ev.get("ike") or {}
        if not ike.get("ok"):
            return changes
        ik = p["ike"]
        ver = ike.get("version")
        if ver and ver != ik["version"]:
            prev = ik["version"]
            ik["version"] = ver
            _note(p, ts, "ike_version", "IKEv%d" % ver, "directly_observed", "IKE packet")
            if prev is not None:
                c = {"ts": ts, "type": "ike_version_changed",
                     "detail": "IKE version changed", "previous": prev, "new": ver,
                     "provenance": "directly_observed", "source": "IKE packet"}
                p["change_history"].append(c)
                changes.append(c)
        exch = ike.get("exchange_name")
        if exch and exch not in ik["exchanges"]:
            ik["exchanges"].append(exch)
            _note(p, ts, "ike_exchange", exch, "directly_observed", "IKE packet")
        init = ike.get("init_spi", "")
        sess = ik["sessions"].setdefault(init, {"first": ts, "last": ts, "messages": 0})
        sess["last"] = ts
        sess["messages"] += 1
        for pr in ike.get("proposals", []):
            summ = transform_summary(pr)
            is_request = not ike.get("response")
            if is_request:
                if summ not in ik["offered"]:
                    prev = list(ik["offered"])
                    ik["offered"].append(summ)
                    _note(p, ts, "ike_offered_proposal", summ,
                          "directly_observed", "IKE_SA_INIT request")
                    if prev:
                        c = {"ts": ts, "type": "ike_proposal_changed",
                             "detail": "new offered IKE proposal",
                             "previous": prev, "new": list(ik["offered"]),
                             "provenance": "directly_observed",
                             "source": "IKE_SA_INIT request"}
                        p["change_history"].append(c)
                        changes.append(c)
            else:
                if len(ike.get("proposals", [])) == 1:
                    if ik["selected"] != summ:
                        prev = ik["selected"]
                        ik["selected"] = summ
                        _note(p, ts, "ike_selected_proposal", summ,
                              "directly_observed", "IKE_SA_INIT response")
                        if prev is not None:
                            c = {"ts": ts, "type": "ike_proposal_changed",
                                 "detail": "observed selected IKE proposal changed",
                                 "previous": prev, "new": summ,
                                 "provenance": "directly_observed",
                                 "source": "IKE_SA_INIT response"}
                            p["change_history"].append(c)
                            changes.append(c)
        for g in ike.get("ke_groups", []):
            from .ike import DH_IDS
            name = DH_IDS.get(g, "GROUP(%d)" % g)
            if name not in ik["ke_groups"]:
                prev = list(ik["ke_groups"])
                ik["ke_groups"].append(name)
                _note(p, ts, "ike_dh_group", name, "directly_observed", "KE payload")
                if prev:
                    c = {"ts": ts, "type": "dh_changed",
                         "detail": "new DH group in KE payload",
                         "previous": prev, "new": list(ik["ke_groups"]),
                         "provenance": "directly_observed", "source": "KE payload"}
                    p["change_history"].append(c)
                    changes.append(c)
        fp = {"version": ik["version"], "offered": list(ik["offered"]),
              "selected": ik["selected"], "ke": list(ik["ke_groups"])}
        if not ik["fingerprint_versions"] or ik["fingerprint_versions"][-1] != fp:
            ik["fingerprint_versions"].append(dict(fp, ts=ts))
            _note(p, ts, "ike_fingerprint", fp, "deterministically_derived",
                  "accumulated IKE observations")
        return changes

    def snapshot(self):
        return {"profiles": self.profiles, "malformed": self.malformed,
                "generated_at": time.time()}
