"""Run against exact SQL used by Rust, not the Rust or Win32 runtime."""
import hashlib
import sqlite3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if not (ROOT / 'dhcp6_history_schema.sql').is_file():
    ROOT = ROOT.parent / 'src/intelligence/sql'
NAMES = ['dhcp6_history_schema.sql', 'dhcp6_history_insert.sql', 'dhcp6_history_page.sql']
SCHEMA, INSERT, PAGE = [(ROOT / name).read_text(encoding='utf-8') for name in NAMES]


def add(db, router='r1:443', stamp=1, payload='{}'):
    return db.execute(INSERT, (router, stamp, payload)).rowcount


class HistoryContract(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        self.db.executescript(SCHEMA)

    def test_database_identity(self):
        self.assertEqual(self.db.execute('PRAGMA application_id').fetchone()[0], 1464742214)
        self.assertEqual(self.db.execute('PRAGMA user_version').fetchone()[0], 1)

    def test_duplicate_no_overwrite_and_router_isolation(self):
        self.assertEqual(add(self.db, payload='first'), 1)
        self.assertEqual(add(self.db, payload='conflict'), 0)
        self.assertEqual(add(self.db, router='r2:443', payload='other'), 1)
        self.assertEqual(self.db.execute(PAGE, ('r1:443',)).fetchall(), [(1, 'first')])
        self.assertEqual(self.db.execute(PAGE, ('r2:443',)).fetchall(), [(1, 'other')])

    def test_page_bounded_order(self):
        for stamp in range(30):
            self.assertEqual(add(self.db, stamp=stamp), 1)
        self.assertEqual([r[0] for r in self.db.execute(PAGE, ('r1:443',))], list(range(29, 9, -1)))

    def test_per_router_limit_retains_old_samples(self):
        for stamp in range(120):
            self.assertEqual(add(self.db, stamp=stamp), 1)
        self.assertEqual(add(self.db, stamp=120), 0)
        self.assertEqual(self.db.execute('SELECT count(*),min(stamp) FROM dhcp6_sample').fetchone(), (120, 0))
        self.assertEqual(add(self.db, router='r2:443'), 1)

    def test_distinct_router_limit(self):
        for i in range(32):
            self.assertEqual(add(self.db, router=f'r{i}:443'), 1)
        self.assertEqual(add(self.db, router='new:443'), 0)
        self.assertEqual(add(self.db, router='r1:443', stamp=2), 1)

    def test_payload_and_stamp_validation_rollback(self):
        add(self.db); self.db.commit()
        with self.assertRaises(sqlite3.IntegrityError):
            add(self.db, stamp=2, payload='x' * 262145)
        self.db.rollback()
        with self.assertRaises(sqlite3.IntegrityError):
            add(self.db, stamp=-1)
        self.db.rollback()
        self.assertEqual(self.db.execute(PAGE, ('r1:443',)).fetchall(), [(1, '{}')])

    def test_global_bytes_no_eviction(self):
        payload = 'x' * 262144
        self.db.executemany('INSERT INTO dhcp6_sample VALUES(?,?,?)',
                            ((f'r{i//100}:443', i, payload) for i in range(256)))
        self.assertEqual(add(self.db, router='other:443'), 0)
        self.assertEqual(self.db.execute('SELECT count(*) FROM dhcp6_sample').fetchone()[0], 256)


if __name__ == '__main__':
    print(f'Python {sys.version.split()[0]} / SQLite {sqlite3.sqlite_version}', flush=True)
    for name in NAMES + [Path(__file__).name]:
        path = ROOT / name if name in NAMES else Path(__file__)
        data = path.read_bytes()
        print(name, hashlib.sha1(f'blob {len(data)}\0'.encode() + data).hexdigest(), flush=True)
    unittest.main(verbosity=2)
