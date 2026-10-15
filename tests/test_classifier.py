from scapy.layers.inet import IP, UDP, TCP

from core.ip_filter import load_networks
from core.classifier import classify
import pytest


@pytest.fixture(autouse=True)
def offline_enrichment(monkeypatch):
    monkeypatch.setattr("core.classifier.reverse_dns", lambda ip: "")
    monkeypatch.setattr("core.classifier.get_geo_info", lambda ip: {})


def setup_module(_):
    load_networks(["157.240.0.0/16"])


def test_meta_udp_flow_local_to_server():
    pkt = IP(src="192.168.1.20", dst="157.240.1.5") / UDP(sport=50000, dport=50001)
    rec = classify(pkt)
    assert rec is not None
    assert rec.remote == "157.240.1.5"
    assert rec.is_meta is True
    assert rec.candidate_peer is False


def test_candidate_peer_public_media():
    # Public, non-Meta remote on high UDP ports during media => flagged peer.
    pkt = IP(src="192.168.1.20", dst="45.55.100.10") / UDP(sport=50000, dport=50002)
    rec = classify(pkt)
    assert rec is not None
    assert rec.remote == "45.55.100.10"
    assert rec.is_meta is False
    assert rec.candidate_peer is True
    assert rec.score >= 90


def test_signaling_port_not_peer():
    pkt = IP(src="192.168.1.20", dst="157.240.1.5") / TCP(sport=50000, dport=443)
    rec = classify(pkt)
    assert rec.candidate_peer is False


def test_two_private_hosts_ignored():
    pkt = IP(src="192.168.1.20", dst="192.168.1.30") / UDP(sport=1, dport=2)
    assert classify(pkt) is None
