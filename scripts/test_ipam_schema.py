"""Tests exact SQL used by Rust IPAM metadata, not Rust or Windows."""
import sqlite3
import unittest
from pathlib import Path
from contextlib import closing

ROOT = Path(__file__).resolve().parents[1] / 'src/intelligence/sql'
SCHEMA = (ROOT / 'ipam_schema.sql').read_text(encoding='utf-8')
APPEND = (ROOT / 'ipam_append.sql').read_text(encoding='utf-8')
CURRENT = (ROOT / 'ipam_current.sql').read_text(encoding='utf-8')
EXACT = (ROOT / 'ipam_exact.sql').read_text(encoding='utf-8')


def add(db, scope='blue', cidr='192.0.2.0/24', expected=0, stamp=100,
        active=1, reserved=0, alias='lab', tags='', note=''):
    return db.execute(APPEND, (scope, cidr, expected, stamp, active,
                               reserved, alias, tags, note)).rowcount


class IpamContract(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        self.db.executescript(SCHEMA)

    def test_schema_identity(self):
        self.assertEqual(self.db.execute('PRAGMA application_id').fetchone()[0], 1464742221)
        self.assertEqual(self.db.execute('PRAGMA user_version').fetchone()[0], 1)

    def test_isolation_and_conflict(self):
        self.assertEqual(add(self.db), 1)
        self.assertEqual(add(self.db, scope='red'), 1)
        self.assertEqual(add(self.db, alias='conflict'), 0)
        self.assertEqual(add(self.db, expected=1, alias='edit'), 1)
        self.assertEqual(add(self.db, expected=1, alias='stale'), 0)
        rows = self.db.execute(CURRENT).fetchall()
        self.assertEqual([(r[0], r[2], r[6]) for r in rows],
                         [('blue', 2, 'edit'), ('red', 1, 'lab')])

    def test_append_undo_retains_history(self):
        add(self.db, alias='first', reserved=1)
        add(self.db, expected=1, alias='second')
        old = self.db.execute(EXACT, ('blue', '192.0.2.0/24', 1)).fetchone()
        self.assertEqual(add(self.db, expected=2, alias=old[6], reserved=old[5]), 1)
        self.assertEqual(self.db.execute('SELECT count(*) FROM ipam_revision').fetchone()[0], 3)
        self.assertEqual(self.db.execute(CURRENT).fetchone()[6], 'first')

    def test_tombstone_is_revision_not_delete(self):
        add(self.db)
        self.assertEqual(add(self.db, expected=1, active=0, alias=''), 1)
        self.assertEqual(self.db.execute(CURRENT).fetchone()[4], 0)
        self.assertEqual(self.db.execute('SELECT count(*) FROM ipam_revision').fetchone()[0], 2)

    def test_bound_and_rollback(self):
        add(self.db); self.db.commit()
        with self.assertRaises(sqlite3.IntegrityError):
            add(self.db, expected=1, alias='x' * 81)
        self.db.rollback()
        self.assertEqual(self.db.execute(CURRENT).fetchone()[2], 1)
        self.assertEqual(add(self.db, expected=5), 0)

    def test_parameterized_scope(self):
        self.assertEqual(add(self.db, scope="x' OR 1=1 --"), 1)
        self.assertEqual(add(self.db, scope='blue'), 1)
        self.assertEqual(len(self.db.execute(CURRENT).fetchall()), 2)

    def test_key_capacity_no_eviction(self):
        self.db.executemany(
            'INSERT INTO ipam_revision VALUES(?,?,1,1,1,0,?,?,?)',
            ((str(i), '192.0.2.0/24', '', '', '') for i in range(4096)),
        )
        self.assertEqual(add(self.db, scope='extra'), 0)
        self.assertEqual(len(self.db.execute(CURRENT).fetchall()), 4096)
        self.assertEqual(add(self.db, scope='0', expected=1, alias='edit'), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
