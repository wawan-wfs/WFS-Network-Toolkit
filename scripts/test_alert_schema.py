"""Offline tests of the exact SQL statements included by Rust; no network or live user DB."""
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1] / 'src/intelligence/sql'
def sql(name):
    return (ROOT / name).read_text(encoding='utf-8')

UPSERT = sql('alert_upsert.sql')
ACK = sql('alert_ack.sql')
PAGE = sql('alert_page.sql')
PRUNE = sql('alert_prune.sql')
CAP = sql('alert_cap.sql')


def migrate(db, start=0):
    scripts = {0: ['001.sql', '002.sql', '004.sql'],
               1: ['002.sql', '004.sql'], 2: ['004.sql']}
    db.executescript('BEGIN IMMEDIATE;'+''.join(sql(n) for n in scripts[start])+'COMMIT;')


def row(serial=1, scope='site/A', opened=100, seen=105, total=2, recovered=None, session='s1'):
    return (session, serial, scope, 'missing', opened, seen, total, recovered)


def acknowledge(db, identity, stamp=110):
    id_, session, serial, scope, signal, opened = identity[:6]
    return db.execute(ACK, (stamp, id_, session, serial, scope, signal, opened)).rowcount


class LedgerTest(unittest.TestCase):
    def test_v1_migrate_preserves_snapshot(self):
        with closing(sqlite3.connect(':memory:')) as db:
            db.executescript(sql('001.sql'))
            db.execute("INSERT INTO snapshots(fingerprint,source,observed,data) VALUES(X'11','fixture',123,'{}')")
            db.commit(); migrate(db, 1)
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],4)
            self.assertEqual(db.execute('SELECT count(*) FROM snapshots').fetchone()[0],1)

    def test_v2_migrate_preserves_router_sample(self):
        with closing(sqlite3.connect(':memory:')) as db:
            db.executescript(sql('001.sql')+sql('002.sql'))
            db.execute("INSERT INTO router_samples VALUES('lab',123,'{}')")
            db.commit(); migrate(db, 2)
            self.assertEqual(db.execute('PRAGMA application_id').fetchone()[0],1464226638)
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],4)
            self.assertEqual(db.execute('SELECT count(*) FROM router_samples').fetchone()[0],1)

    def test_atomic_migration_rollback(self):
        with closing(sqlite3.connect(':memory:')) as db:
            db.executescript(sql('001.sql')+sql('002.sql'))
            with self.assertRaises(sqlite3.OperationalError):
                db.executescript('BEGIN IMMEDIATE;'+sql('004.sql')+'SELECT * FROM missing_table; COMMIT;')
            db.rollback()
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],2)
            self.assertEqual(db.execute("SELECT count(*) FROM sqlite_master WHERE name='collector_alerts'").fetchone()[0],0)

    def test_exact_state_and_scoped_search(self):
        with closing(sqlite3.connect(':memory:')) as db:
            migrate(db)
            db.executemany(UPSERT,[row(),row(2,'site/B'),row(3,'site/A',seen=120,recovered=120)])
            a=db.execute(PAGE,('site/A','open',100)).fetchone()
            self.assertEqual(acknowledge(db,a),1)
            self.assertEqual(db.execute(PAGE,('site/A','open',100)).fetchall(),[])
            self.assertEqual(len(db.execute(PAGE,('site/A','ack',100)).fetchall()),1)
            self.assertEqual(len(db.execute(PAGE,('site/A','recovered',100)).fetchall()),1)
            self.assertEqual(len(db.execute(PAGE,('site/B','open',100)).fetchall()),1)
            self.assertEqual(db.execute(PAGE,("' OR 1=1 --",'all',100)).fetchall(),[])

    def test_ack_replay_and_identity_collision(self):
        with closing(sqlite3.connect(':memory:')) as db:
            migrate(db); db.execute(UPSERT,row())
            a=db.execute(PAGE,('','all',1)).fetchone()
            self.assertEqual(acknowledge(db,a,110),1)
            self.assertEqual(acknowledge(db,a,130),1)
            self.assertEqual(acknowledge(db,(*a[:3],'site/B',*a[4:])),0)
            self.assertEqual(db.execute(UPSERT,row(scope='site/B',seen=150)).rowcount,0)
            db.execute(UPSERT,row(seen=120,total=8,recovered=120))
            db.execute(UPSERT,row(seen=105,total=2))
            db.execute(UPSERT,row(seen=130,total=9,recovered=130))
            self.assertEqual(db.execute('SELECT scope,total,acknowledged,recovered,last_seen FROM collector_alerts').fetchone(),('site/A',8,110,120,120))

    def test_stale_recovery_and_clock_regression(self):
        with closing(sqlite3.connect(':memory:')) as db:
            migrate(db); db.execute(UPSERT,row(seen=120,total=10))
            db.execute(UPSERT,row(seen=110,total=3,recovered=110))
            self.assertEqual(db.execute('SELECT last_seen,total,recovered FROM collector_alerts').fetchone(),(120,10,None))
            a=db.execute(PAGE,('','all',1)).fetchone()
            self.assertEqual(acknowledge(db,a,80),1)
            self.assertEqual(db.execute('SELECT acknowledged FROM collector_alerts').fetchone()[0],100)

    def test_retention_cap_and_stable_pagination(self):
        with closing(sqlite3.connect(':memory:')) as db:
            migrate(db)
            db.executemany(UPSERT,(row(i,seen=100+i) for i in range(1,5001)))
            db.execute(PRUNE,(500,)); db.execute(CAP,(4096,))
            self.assertEqual(db.execute('SELECT count(*) FROM collector_alerts').fetchone()[0],4096)
            first=db.execute(PAGE,('','all',1000)).fetchall()
            self.assertEqual(len(first),1000)
            self.assertEqual(first[0][2],5000)
            self.assertEqual(first[-1][2],4001)
            self.assertEqual(db.execute('SELECT min(serial) FROM collector_alerts').fetchone()[0],905)

    def test_wal_backup_reopen_readonly_and_write_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'archive.sqlite'; copy=Path(tmp)/'backup.sqlite'
            with closing(sqlite3.connect(path)) as db:
                migrate(db); db.execute('PRAGMA journal_mode=WAL')
                db.execute(UPSERT,row()); a=db.execute(PAGE,('','all',1)).fetchone()
                acknowledge(db,a); db.commit()
                with closing(sqlite3.connect(copy)) as backup:
                    db.backup(backup)
                db.execute('BEGIN IMMEDIATE')
                with closing(sqlite3.connect(path,timeout=0.05)) as competing:
                    with self.assertRaises(sqlite3.OperationalError):
                        competing.execute(UPSERT,row(2))
                    competing.rollback()
                db.rollback()
            with closing(sqlite3.connect(copy.as_uri()+'?mode=ro',uri=True)) as read:
                self.assertEqual(read.execute(PAGE,('','ack',1)).fetchone()[8],110)
                with self.assertRaises(sqlite3.OperationalError):
                    acknowledge(read,a)
                self.assertEqual(read.execute('PRAGMA quick_check').fetchone()[0],'ok')
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute('SELECT count(*) FROM collector_alerts').fetchone()[0],1)

    def test_quota_full_rolls_back_without_deleting_existing_alert(self):
        with closing(sqlite3.connect(':memory:')) as db:
            migrate(db); db.execute(UPSERT,row()); db.commit()
            pages=db.execute('PRAGMA page_count').fetchone()[0]
            db.execute(f'PRAGMA max_page_count={pages}')
            with self.assertRaises(sqlite3.DatabaseError):
                db.execute('BEGIN IMMEDIATE')
                db.execute(UPSERT,row(2,scope='X'*1000000))
                db.commit()
            db.rollback()
            self.assertEqual(db.execute('SELECT count(*) FROM collector_alerts').fetchone()[0],1)
            self.assertEqual(db.execute('PRAGMA quick_check').fetchone()[0],'ok')

if __name__ == '__main__':
    unittest.main(verbosity=2)
