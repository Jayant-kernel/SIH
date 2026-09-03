"""Short tests for live tail publication and the dashboard state contract."""
import json
import threading
import time
from pathlib import Path

from monitor.monitor import Monitor
from monitor.pcapio import PcapReader
from monitor.run import DEFAULT_STATE


class _SlowTail:
    follow = True

    def __init__(self):
        self.stop = threading.Event()

    def packets(self):
        yield time.time(), b""
        time.sleep(1.2)
        yield time.time(), b""


def test_tail_publishes_before_stream_ends(tmp_path):
    tail = _SlowTail()
    mon = Monitor(str(tmp_path), "x", "x", {"features": []}, {}, do_ml=False)
    thread = threading.Thread(target=mon.process_stream, args=(tail,))
    thread.start()
    time.sleep(1.05)
    snapshot = Path(mon.store.snapshot_path)
    heartbeat = Path(mon.store.heartbeat_path)
    assert snapshot.exists() and heartbeat.exists()
    live = json.loads(snapshot.read_text())
    beat = json.loads(heartbeat.read_text())
    assert live["sensor"]["stats"]["packets"] == 1
    assert live["sensor"]["status"] == "LIVE"
    assert beat["status"] == "LIVE"
    assert beat["last_packet_ts"] is not None
    tail.stop.set()
    thread.join(timeout=3)
    assert not thread.is_alive()


def test_default_monitor_state_matches_dashboard_path():
    dashboard_path = Path(__file__).resolve().parents[1] / "monitor" / "state"
    assert Path(DEFAULT_STATE).resolve() == dashboard_path.resolve()


def test_store_snapshot_is_valid_json_during_replacement(tmp_path):
    mon = Monitor(str(tmp_path), "x", "x", {"features": []}, {}, do_ml=False)
    for _ in range(10):
        mon.snapshot()
        json.loads(Path(mon.store.snapshot_path).read_text())
