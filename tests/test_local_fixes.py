from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6

import core.classifier as classifier
import core.packet_sniffer as capture
from core.dns_resolver import is_meta_hostname
from core.ip_filter import load_networks


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    load_networks(["157.240.0.0/16", "2a03:2880::/32"])
    monkeypatch.setattr(classifier, "reverse_dns", lambda ip: "")
    monkeypatch.setattr(classifier, "get_geo_info", lambda ip: {})


@pytest.mark.parametrize("host", ["ams15.1e100.net", "fakefacebook.com", "facebook.com.evil.test"])
def test_non_meta_hostname(host):
    assert not is_meta_hostname(host)


def test_meta_domain_boundary():
    assert is_meta_hostname("EDGE.WhatsApp.NET.")
    assert is_meta_hostname("facebook.com")


@pytest.mark.parametrize("reverse", [False, True])
def test_meta_ipv6_endpoints(reverse):
    local = "2001:db8:1::10"
    remote = "2a03:2880::1234"
    src, dst = (remote, local) if reverse else (local, remote)
    packet = IPv6(src=src, dst=dst) / UDP(sport=50644, dport=443)
    record = classifier.classify(packet, local_ips={local})
    assert record.remote == remote
    assert record.is_meta and not record.candidate_peer


def test_non_meta_ipv6_remote_and_unrelated_traffic():
    local, remote = "2001:4860::10", "2606:4700::20"
    packet = IPv6(src=local, dst=remote) / UDP(sport=50000, dport=50001)
    assert classifier.classify(packet, local_ips={local}).remote == remote
    assert classifier.classify(packet, local_ips={"2001:4860::11"}) is None


@pytest.mark.parametrize("remote,port", [("239.255.255.250", 1900), ("224.0.0.251", 5353), ("255.255.255.255", 67)])
def test_discovery_not_remote_peer(remote, port):
    packet = IP(src="192.168.1.20", dst=remote) / UDP(sport=50000, dport=port)
    assert classifier.classify(packet) is None


def test_dns_kept_without_peer_flag():
    packet = IP(src="192.168.1.20", dst="1.0.0.1") / UDP(sport=50000, dport=53)
    record = classifier.classify(packet)
    assert record.remote == "1.0.0.1"
    assert not record.candidate_peer


def test_google_not_meta(monkeypatch):
    monkeypatch.setattr(classifier, "reverse_dns", lambda ip: "ams15.1e100.net")
    packet = IP(src="192.168.1.20", dst="172.217.20.78") / UDP(sport=50000, dport=443)
    record = classifier.classify(packet)
    assert not record.is_meta and not record.candidate_peer


def test_interface_uses_default_route(monkeypatch):
    monkeypatch.setattr(capture, "conf", SimpleNamespace(route=SimpleNamespace(route=lambda ip: ("en0", "192.168.1.20", "192.168.1.1"))))
    assert capture.pick_interface() == "en0"
    assert capture.pick_interface("en1") == "en1"


def test_dashboard_options_reach_capture(monkeypatch):
    from dashboard import server
    import uvicorn
    sniffer = Mock()
    monkeypatch.setattr(server, "PacketSniffer", lambda **kw: sniffer)
    monkeypatch.setattr(server, "refresh_ranges", Mock(side_effect=AssertionError("must be offline")))
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)
    monkeypatch.setattr(server, "_capture_options", {})
    monkeypatch.setattr(server, "_no_refresh", False)
    monkeypatch.setattr(server, "_sniffer", None)
    server.run(SimpleNamespace(iface="en0", count=10, timeout=5, no_refresh=True))
    server._run_sniffer()
    sniffer.start_sniffing.assert_called_once_with(iface="en0", count=10, timeout=5)
