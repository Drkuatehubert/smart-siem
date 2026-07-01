"""test_normalizer.py"""
from collectors.normalizer.tagger import tag_log
from collectors.normalizer.schema import build_normalized_doc

def test_tag_log_severity():
    log = {"raw_message": "Failed password for root", "host": "srv-01", "source_ip": "10.0.0.1"}
    result = tag_log(log)
    assert result["severity"] == "warning"

def test_tag_log_type_auth():
    log = {"raw_message": "sshd: Accepted publickey for admin", "host": "srv-01", "source_ip": "10.0.0.1"}
    result = tag_log(log)
    assert result["log_type"] == "auth"

def test_build_normalized_doc():
    data = {"host": "srv", "source_ip": "1.2.3.4", "raw_message": "test", "log_type": "auth", "severity": "info"}
    doc = build_normalized_doc(data)
    for field in ["log_id", "timestamp", "host", "source_ip", "log_type", "severity", "raw_message"]:
        assert field in doc

