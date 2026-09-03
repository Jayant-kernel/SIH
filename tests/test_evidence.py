from security.evidence import parse_text

def test_passive_protocol_and_spi_only():
    e=parse_text("IP 1 > 2: ESP(spi=0xab12,seq=1), length 100", "tcpdump")
    assert any(x.field=="protocol" and x.value=="ESP" for x in e)
    assert any(x.field=="spi" for x in e)
    assert not any(x.field=="encryption_key_length" for x in e)

def test_two_spis_are_not_rekey():
    e=parse_text("xfrm", "proto esp spi 0x1 mode tunnel\nproto esp spi 0x2 mode tunnel")
    assert not any(x.field in ("rekey_observed","rekey_configured") for x in e)
