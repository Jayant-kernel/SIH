from security.rules import assess
from security.schema import Evidence

P={"allowed_encryption":["AES-GCM"],"allowed_key_sizes":[256],"min_dh_bits":2048,"require_pfs":True,"require_rekey":True}

def test_secure_facts_pass_rules():
    facts={"protocol":"ESP","ike_version":2,"mode":"tunnel","encryption_algorithm":"AES-GCM","encryption_key_length":256,"dh_strength_bits":3072,"pfs":True,"rekey_status":"rekey_observed"}
    selected={k: Evidence(k, v, "directly_observed", 1.0, "test") for k, v in facts.items()}
    fs=assess(facts, selected, P)
    assert not [x for x in fs if x.status=="fail"]

def test_pfs_uses_child_fact():
    facts={"protocol":"ESP","ike_version":2,"mode":"tunnel","encryption_algorithm":"AES-GCM","encryption_key_length":256,"dh_strength_bits":3072,"pfs":False}
    selected={k: Evidence(k, v, "directly_observed", 1.0, "test") for k, v in facts.items()}
    assert next(x for x in assess(facts, selected, P) if x.id=="IPSEC-PFS-001").status=="fail"
