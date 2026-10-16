import asyncio
import json
from contextlib import closing
from datetime import datetime, timedelta, timezone

import pytest
from scapy.all import AsyncSniffer, IP, UDP, wrpcap

from core.history import HistoryStore


def record(seconds=0, remote='203.0.113.10', proto='TCP', length=100):
    return {'ts': (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)).isoformat(),
            'remote': remote, 'proto': proto, 'length': length, 'host': '',
            'is_meta': False, 'candidate_peer': False}


def test_history_survives_restart_and_groups_at_exact_idle_boundary(tmp_path):
    path = tmp_path / 'history.sqlite3'
    with closing(HistoryStore(path)) as store:
        capture = store.start_capture('en0')
        for seconds in (0, 59, 119):
            store.record(capture, record(seconds))
        store.record(capture, record(120, proto='UDP'))
        store.finish_capture(capture)
    with closing(HistoryStore(path)) as store:
        sessions = store.detail(capture)['sessions']
        assert len(sessions) == 3  # 60-second gap splits; protocol splits too.
        assert sorted(s['packets'] for s in sessions) == [1, 1, 2]
        assert sum(m['packets'] for m in store.detail(capture)['minutes']) == 4
        endpoint = store.endpoints()[0]
        assert (endpoint['packets'], endpoint['bytes'], endpoint['sessions']) == (4, 400, 3)
        assert not any(s['active'] for s in sessions)
        assert store.captures()[0]['status'] == 'finished'


def test_compare_and_delete_preserve_running_capture(tmp_path):
    with closing(HistoryStore(tmp_path / 'h.sqlite3')) as store:
        a = store.start_capture('en0')
        store.record(a, record(remote='203.0.113.1'))
        store.record(a, record(remote='203.0.113.2'))
        store.finish_capture(a)
        b = store.start_capture('en0')
        store.record(b, record(remote='203.0.113.2'))
        store.record(b, record(remote='203.0.113.3'))
        assert store.compare(a, b) == {'added': ['203.0.113.3'], 'not_seen': ['203.0.113.1'], 'shared': ['203.0.113.2']}
        with pytest.raises(ValueError):
            store.delete(b)
        assert store.delete() == 1
        assert not store.exists(a) and store.exists(b)
        assert store.db.execute('SELECT COUNT(*) FROM buckets WHERE capture_id=?', (a,)).fetchone()[0] == 0
        assert len(store.endpoints()) == 2
        store.finish_capture(b)
        assert store.delete(b) == 1
        assert store.endpoints() == []


def test_crashed_capture_can_be_deleted(tmp_path, monkeypatch):
    with closing(HistoryStore(tmp_path / 'h.sqlite3')) as store:
        capture = store.start_capture('en0')
        monkeypatch.setattr('core.history.os.kill', lambda *a: (_ for _ in ()).throw(ProcessLookupError()))
        assert store.captures()[0]['status'] == 'interrupted'
        assert store.delete(capture) == 1


def test_reader_sees_live_committed_writes(tmp_path):
    path = tmp_path / 'h.sqlite3'
    with closing(HistoryStore(path)) as writer, closing(HistoryStore(path)) as reader:
        capture = writer.start_capture('en0')
        writer.record(capture, record())
        assert reader.captures()[0]['packets'] == 1
        writer.record(capture, record(1))
        assert reader.captures()[0]['packets'] == 2


def test_real_capture_thread_persists_and_finishes(tmp_path, monkeypatch):
    import core.packet_sniffer as sniffer
    from core.ip_filter import load_networks
    source = tmp_path / 'source.pcap'
    wrpcap(str(source), [IP(src='192.168.1.20', dst='1.0.0.1') / UDP(sport=51000, dport=53)])
    monkeypatch.setattr(sniffer, 'AsyncSniffer', lambda **kw: AsyncSniffer(offline=str(source), prn=kw['prn'], store=False))
    monkeypatch.setattr(sniffer, 'get_if_addr', lambda iface: '192.168.1.20')
    monkeypatch.setattr(sniffer, 'in6_getifaddr', lambda: [])
    monkeypatch.setattr('core.classifier.reverse_dns', lambda ip: '')
    monkeypatch.setattr('core.classifier.get_geo_info', lambda ip: {})
    path = tmp_path / 'history.sqlite3'
    monkeypatch.setattr(sniffer.config, 'HISTORY_DB', path)
    load_networks(['157.240.0.0/16'])
    capture = sniffer.PacketSniffer(log_file=tmp_path / 'saved.pcap')
    capture.start_sniffing(iface='test0')
    with closing(HistoryStore(path)) as store:
        assert store.captures()[0]['status'] == 'finished'
        assert store.captures()[0]['packets'] == 1
        assert store.endpoints()[0]['remote'] == '1.0.0.1'
    assert (tmp_path / 'saved.pcap').exists()
    path.unlink()
    disabled = sniffer.PacketSniffer(log_file=tmp_path / 'disabled.pcap', history_enabled=False)
    disabled.start_sniffing(iface='test0')
    assert not path.exists()


async def request(app, method, path, headers=(), query=b''):
    messages = []
    async def send(message):
        messages.append(message)
    async def receive():
        return {'type': 'http.request', 'body': b'', 'more_body': False}
    scope = {'type':'http','asgi':{'version':'3.0'},'http_version':'1.1','method':method,
             'scheme':'http','path':path,'raw_path':path.encode(),'query_string':query,
             'root_path':'','headers':[(b'host',b'testserver'), *headers],
             'server':('testserver',80),'client':('127.0.0.1',1)}
    await app(scope, receive, send)
    status = next(m['status'] for m in messages if m['type'] == 'http.response.start')
    body = b''.join(m.get('body', b'') for m in messages if m['type'] == 'http.response.body')
    return status, json.loads(body)


def test_history_api_reads_compares_and_protects_deletion(tmp_path, monkeypatch):
    from dashboard import server
    path = tmp_path / 'h.sqlite3'
    monkeypatch.setattr(server.config, 'HISTORY_DB', path)
    monkeypatch.setattr(server, '_sniffer', None)
    with closing(HistoryStore(path)) as store:
        a = store.start_capture('en0')
        store.record(a, record())
        store.finish_capture(a)
        b = store.start_capture('en0')
    def call(method, path, **kwargs):
        return asyncio.run(request(server.app, method, path, **kwargs))
    status, data = call('GET', '/api/history')
    assert status == 200 and len(data['captures']) == 2
    assert call('GET', '/api/history/' + a)[1]['sessions'][0]['packets'] == 1
    assert call('GET', '/api/history/missing')[0] == 404
    assert call('GET', '/api/history/compare', query=f'baseline={a}&current={b}'.encode())[1]['not_seen'] == ['203.0.113.10']
    assert call('GET', '/api/history/compare', query=f'baseline=missing&current={b}'.encode())[0] == 404
    header = [(b'x-history-action', b'delete')]
    assert call('DELETE', '/api/history/' + a)[0] == 403
    assert call('DELETE', '/api/history/' + a, headers=header + [(b'origin', b'https://other.test')])[0] == 403
    assert call('DELETE', '/api/history/' + b, headers=header)[0] == 409
    assert call('DELETE', '/api/history/' + a, headers=header) == (200, {'deleted': 1})
    assert call('DELETE', '/api/history', headers=header) == (200, {'deleted': 0})


def test_capture_error_is_saved_as_failed(tmp_path, monkeypatch):
    import core.packet_sniffer as sniffer
    monkeypatch.setattr(sniffer, 'AsyncSniffer', lambda **kw: AsyncSniffer(offline=str(tmp_path / 'missing.pcap'), store=False))
    monkeypatch.setattr(sniffer, 'get_if_addr', lambda iface: '192.168.1.20')
    monkeypatch.setattr(sniffer, 'in6_getifaddr', lambda: [])
    path = tmp_path / 'h.sqlite3'
    monkeypatch.setattr(sniffer.config, 'HISTORY_DB', path)
    capture = sniffer.PacketSniffer(log_file=tmp_path / 'saved.pcap')
    with pytest.raises(FileNotFoundError):
        capture.start_sniffing(iface='test0')
    with closing(HistoryStore(path)) as store:
        assert store.captures()[0]['status'] == 'failed'
        assert store.delete(capture.capture_id) == 1


def test_stop_ends_idle_capture_and_closes_history(tmp_path, monkeypatch):
    import threading
    import core.packet_sniffer as sniffer
    ready, release = threading.Event(), threading.Event()
    class IdleCapture:
        running = False
        def start(self):
            self.running = True
            self.stop_cb = True
            self.thread = threading.Thread(target=lambda: (ready.set(), release.wait(5)))
            self.thread.start()
        def join(self, timeout=None):
            self.thread.join(timeout)
        def stop(self):
            self.running = False
            release.set()
            self.thread.join()
    monkeypatch.setattr(sniffer, 'AsyncSniffer', lambda **kw: IdleCapture())
    monkeypatch.setattr(sniffer, 'get_if_addr', lambda iface: '192.168.1.20')
    monkeypatch.setattr(sniffer, 'in6_getifaddr', lambda: [])
    path = tmp_path / 'h.sqlite3'
    monkeypatch.setattr(sniffer.config, 'HISTORY_DB', path)
    capture = sniffer.PacketSniffer(log_file=tmp_path / 'saved.pcap')
    errors = []
    def run():
        try:
            capture.start_sniffing(iface='test0')
        except Exception as error:
            errors.append(error)
    worker = threading.Thread(target=run)
    worker.start()
    try:
        assert ready.wait(3)
        capture.stop()
        worker.join(3)
        assert not worker.is_alive() and not errors
        with closing(HistoryStore(path)) as store:
            assert store.captures()[0]['status'] == 'interrupted'
    finally:
        release.set()
        worker.join(3)
