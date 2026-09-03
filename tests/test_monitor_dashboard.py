"""Live dashboard data-contract test: real HTTP against app.py /live."""
import json
import threading
import urllib.request
from http.server import HTTPServer

from app.app import Handler
from tests.test_monitor_replay import synth_pcap, run_monitor


def test_live_route_contract(tmp_path):
    pcap = tmp_path / "s.pcap"
    synth_pcap(pcap)
    snap_path = run_monitor(pcap, tmp_path / "s1")
    import app.app as appmod
    appmod.LIVE_STATE = __import__("pathlib").Path(
        str(tmp_path / "s1" / "live_profiles.json"))
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05})
    th.daemon = True
    th.start()
    try:
        body = urllib.request.urlopen(
            "http://127.0.0.1:%d/live" % port, timeout=10).read().decode()
        assert "Live IPsec Monitor" in body
        assert "IKEv2" in body and "Unknown" in body
        home = urllib.request.urlopen(
            "http://127.0.0.1:%d/" % port, timeout=10).read().decode()
        assert "AI-Driven IPsec VPN Security Analyzer" in home  # offline intact
    finally:
        srv.shutdown()
        th.join(timeout=5)
