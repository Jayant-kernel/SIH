#!/usr/bin/env python3
"""Change detection. Every alert carries evidence and provenance; alerts
describe observed changes, never guessed causes.
"""
from collections import deque

CHANGE_TYPES = {
    "profile_created": "First observation of a gateway pair.",
    "new_spi": "A previously unseen SPI appeared.",
    "spi_retired": "An SPI stopped appearing (possible rotation).",
    "rekey_lifecycle": "Temporal SPI transition consistent with rekey.",
    "spi_churn": "Abnormal rate of new SPIs (possible instability or attack).",
    "ike_first_seen": "First IKE exchange observed for this profile.",
    "ike_version_changed": "Observed IKE version changed.",
    "ike_proposal_changed": "Externally visible IKE proposal changed.",
    "dh_changed": "DH group visible in KE payload changed.",
    "natt_changed": "NAT-T observation changed.",
    "traffic_shift": "ML traffic behavior label changed with confidence.",
}


def traffic_shift(ts, old_label, new):
    """new: ml_bridge result dict. Returns change dict or None."""
    label = new.get("label", "Unknown")
    if old_label in (None, "", "Unknown") or label in ("Unknown", ""):
        return None
    if label == old_label:
        return None
    return {"ts": ts, "type": "traffic_shift",
            "detail": "traffic behavior changed %s -> %s (confidence %.2f)"
                      % (old_label, label, new.get("confidence", 0.0)),
            "previous": old_label, "new": label,
            "provenance": "ml_inferred", "source": "rolling ML window"}


class ChurnWatch:
    """Flags abnormal SPI churn within a sliding window."""

    def __init__(self, threshold=5, window=60.0):
        self.threshold = threshold
        self.window = window
        self.events = deque()
        self.fired = False

    def note(self, ts):
        self.events.append(ts)
        while self.events and ts - self.events[0] > self.window:
            self.events.popleft()
        if len(self.events) >= self.threshold and not self.fired:
            self.fired = True
            return {"ts": ts, "type": "spi_churn",
                    "detail": "%d new SPIs within %.0fs"
                              % (len(self.events), self.window),
                    "previous": None, "new": len(self.events),
                    "provenance": "deterministically_derived",
                    "source": "SPI timeline"}
        if len(self.events) < self.threshold:
            self.fired = False
        return None
