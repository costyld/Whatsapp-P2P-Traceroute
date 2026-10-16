"""Local, aggregate-only capture history. No packet payloads are stored here."""
import sqlite3
import os
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


def utcnow():
    return datetime.now(timezone.utc).isoformat()


class HistoryStore:
    def __init__(self, path, idle_seconds=60):
        if idle_seconds <= 0:
            raise ValueError('Session idle timeout must be positive')
        self.idle_seconds = idle_seconds
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=10, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=NORMAL')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS captures (
                id TEXT PRIMARY KEY, started_at TEXT NOT NULL, ended_at TEXT,
                interface TEXT NOT NULL, status TEXT NOT NULL, idle_seconds INTEGER NOT NULL, process_id INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY, capture_id TEXT NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
                remote TEXT NOT NULL, protocol TEXT NOT NULL, first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL, packets INTEGER NOT NULL, bytes INTEGER NOT NULL,
                host TEXT NOT NULL, is_meta INTEGER NOT NULL, candidate_peer INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS session_endpoint ON sessions(capture_id, remote, protocol, last_seen);
            CREATE TABLE IF NOT EXISTS buckets (
                capture_id TEXT NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
                remote TEXT NOT NULL, protocol TEXT NOT NULL, minute TEXT NOT NULL,
                packets INTEGER NOT NULL, bytes INTEGER NOT NULL,
                PRIMARY KEY(capture_id, remote, protocol, minute));
        ''')

    def close(self):
        self.db.close()

    def start_capture(self, interface):
        capture_id = uuid4().hex
        with self.db:
            self.db.execute('INSERT INTO captures VALUES(?,?,NULL,?,?,?,?)',
                            (capture_id, utcnow(), interface, 'running', self.idle_seconds, os.getpid()))
        return capture_id

    def finish_capture(self, capture_id, status='finished'):
        with self.db:
            self.db.execute('UPDATE captures SET ended_at=?, status=? WHERE id=?',
                            (utcnow(), status, capture_id))

    def record(self, capture_id, record):
        ts = datetime.fromisoformat(record['ts']).astimezone(timezone.utc)
        timestamp = ts.isoformat()
        minute = ts.replace(second=0, microsecond=0).isoformat()
        remote, proto = record['remote'], record['proto']
        with self.db:
            last = self.db.execute('''SELECT id,last_seen FROM sessions
                WHERE capture_id=? AND remote=? AND protocol=? ORDER BY id DESC LIMIT 1''',
                (capture_id, remote, proto)).fetchone()
            gap = (ts - datetime.fromisoformat(last['last_seen'])).total_seconds() if last else None
            if last and 0 <= gap < self.idle_seconds:
                self.db.execute('''UPDATE sessions SET last_seen=?,packets=packets+1,bytes=bytes+?,
                    host=?,is_meta=MAX(is_meta,?),candidate_peer=MAX(candidate_peer,?) WHERE id=?''',
                    (timestamp, record['length'], record.get('host') or '', bool(record['is_meta']),
                     bool(record['candidate_peer']), last['id']))
            else:
                self.db.execute('''INSERT INTO sessions(capture_id,remote,protocol,first_seen,last_seen,
                    packets,bytes,host,is_meta,candidate_peer) VALUES(?,?,?,?,?,1,?,?,?,?)''',
                    (capture_id, remote, proto, timestamp, timestamp, record['length'],
                     record.get('host') or '', bool(record['is_meta']), bool(record['candidate_peer'])))
            self.db.execute('''INSERT INTO buckets VALUES(?,?,?,?,1,?)
                ON CONFLICT(capture_id,remote,protocol,minute) DO UPDATE SET
                packets=packets+1,bytes=bytes+excluded.bytes''',
                (capture_id, remote, proto, minute, record['length']))

    def recover_interrupted(self):
        # A process that exited without shutdown cannot keep history undeletable.
        for row in self.db.execute("SELECT id,process_id FROM captures WHERE status='running'").fetchall():
            try:
                os.kill(row['process_id'], 0)
            except ProcessLookupError:
                self.finish_capture(row['id'], 'interrupted')
            except PermissionError:
                pass  # Another user (e.g. root) may own a live capture.

    def captures(self):
        self.recover_interrupted()
        return [dict(r) for r in self.db.execute('''SELECT c.*,
            COALESCE(SUM(s.packets),0) AS packets, COALESCE(SUM(s.bytes),0) AS bytes,
            COUNT(DISTINCT s.remote) AS endpoints FROM captures c
            LEFT JOIN sessions s ON s.capture_id=c.id GROUP BY c.id ORDER BY c.started_at DESC LIMIT 200''')]

    def exists(self, capture_id):
        return self.db.execute('SELECT 1 FROM captures WHERE id=?', (capture_id,)).fetchone() is not None

    def detail(self, capture_id):
        sessions = [dict(r) for r in self.db.execute('''SELECT s.*,c.status AS capture_status,
            c.idle_seconds FROM sessions s JOIN captures c ON s.capture_id=c.id
            WHERE capture_id=? ORDER BY last_seen DESC LIMIT 200''', (capture_id,))]
        now = datetime.now(timezone.utc)
        for s in sessions:
            s['active'] = (s['capture_status'] == 'running' and
                           (now - datetime.fromisoformat(s['last_seen'])).total_seconds() < s['idle_seconds'])
        buckets = [dict(r) for r in self.db.execute('''SELECT minute,SUM(packets) AS packets,
            SUM(bytes) AS bytes FROM buckets WHERE capture_id=? GROUP BY minute
            ORDER BY minute DESC LIMIT 120''', (capture_id,))]
        return {'sessions': sessions, 'minutes': buckets}

    def endpoints(self):
        return [dict(r) for r in self.db.execute('''SELECT remote,MIN(first_seen) AS first_seen,
            MAX(last_seen) AS last_seen,SUM(packets) AS packets,SUM(bytes) AS bytes,
            COUNT(DISTINCT capture_id) AS captures,COUNT(*) AS sessions FROM sessions
            GROUP BY remote ORDER BY last_seen DESC LIMIT 200''')]

    def compare(self, baseline, current):
        def addresses(capture_id):
            return {r[0] for r in self.db.execute('SELECT DISTINCT remote FROM sessions WHERE capture_id=?', (capture_id,))}
        before, after = addresses(baseline), addresses(current)
        return {'added': sorted(after-before), 'not_seen': sorted(before-after), 'shared': sorted(before & after)}

    def delete(self, capture_id=None):
        """Never delete a running capture; foreign keys remove its aggregates."""
        self.recover_interrupted()
        with self.db:
            if capture_id:
                row = self.db.execute('SELECT status FROM captures WHERE id=?', (capture_id,)).fetchone()
                if row and row['status'] == 'running':
                    raise ValueError('Stop the capture before deleting its history.')
                return self.db.execute('DELETE FROM captures WHERE id=?', (capture_id,)).rowcount
            return self.db.execute("DELETE FROM captures WHERE status != 'running'").rowcount
