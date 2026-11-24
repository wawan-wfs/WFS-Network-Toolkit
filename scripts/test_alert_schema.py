"""Offline SQLite migration and ledger contract; not a Rust or Windows test."""
import sqlite3
from contextlib import closing
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1] / 'src/intelligence/sql'
UPSERT = '''INSERT INTO collector_alerts(session,serial,scope,signal,opened,last_seen,total,recovered)
VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(session,serial) DO UPDATE SET
last_seen=max(collector_alerts.last_seen,excluded.last_seen),
total=max(collector_alerts.total,excluded.total),
recovered=coalesce(collector_alerts.recovered,excluded.recovered)'''
ACK = '''UPDATE collector_alerts SET acknowledged=coalesce(acknowledged,max(opened,?1))
WHERE id=?2 AND session=?3 AND serial=?4'''

class LedgerTest(unittest.TestCase):
    def test_migrate_reopen_ack_replay_and_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'archive.sqlite'
            with closing(sqlite3.connect(path)) as db:
                db.executescript((ROOT/'001.sql').read_text())
                db.executescript((ROOT/'002.sql').read_text())
                db.execute("INSERT INTO router_samples VALUES ('lab',123,'{}')")
                db.commit()
                db.executescript('BEGIN IMMEDIATE;'+(ROOT/'004.sql').read_text()+'COMMIT;')
                self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 4)
                self.assertEqual(db.execute('PRAGMA application_id').fetchone()[0], 1464226638)
                for item in [('s1',1,'site/A','missing',100,105,2,None),('s1',2,'site/B','missing',100,105,4,None),('s2',1,'site/A','missing',100,105,1,None)]:
                    db.execute(UPSERT,item)
                row = db.execute("SELECT id FROM collector_alerts WHERE session='s1' AND serial=1").fetchone()[0]
                db.execute(ACK,(110,row,'s1',1)); db.execute(ACK,(120,row,'s1',1))
                db.execute(UPSERT,('s1',1,'site/A','missing',100,115,8,115))
                db.execute(UPSERT,('s1',1,'site/A','missing',100,105,2,None))
                db.commit()
                with closing(sqlite3.connect(Path(tmp)/'backup.sqlite')) as copy:
                    db.backup(copy)
                    self.assertEqual(copy.execute('SELECT count(*) FROM collector_alerts').fetchone()[0],3)
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute("SELECT total,acknowledged,recovered,last_seen FROM collector_alerts WHERE session='s1' AND serial=1").fetchone(),(8,110,115,115))
                self.assertEqual(db.execute('SELECT count(*) FROM router_samples').fetchone()[0],1)
                self.assertEqual(db.execute(ACK,(200,row,'wrong',1)).rowcount,0)
                self.assertEqual(db.execute('PRAGMA quick_check').fetchone()[0],'ok')
                db.execute('DELETE FROM collector_alerts WHERE last_seen < 110')
                self.assertEqual(db.execute('SELECT count(*) FROM collector_alerts').fetchone()[0],1)
    def test_v1_migrate_preserves_existing_flow_table(self):
        with closing(sqlite3.connect(':memory:')) as db:
            db.executescript((ROOT/'001.sql').read_text())
            db.execute("INSERT INTO snapshots(fingerprint,source,observed,data) VALUES (X'11','fixture',123,'{}')")
            db.commit()
            db.executescript('BEGIN IMMEDIATE;'+(ROOT/'002.sql').read_text()+(ROOT/'004.sql').read_text()+'COMMIT;')
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],4)
            self.assertEqual(db.execute('SELECT count(*) FROM snapshots').fetchone()[0],1)
            self.assertEqual(db.execute('SELECT count(*) FROM collector_alerts').fetchone()[0],0)
    def test_atomic_migration_rollback(self):
        db=sqlite3.connect(':memory:')
        db.executescript((ROOT/'001.sql').read_text()); db.executescript((ROOT/'002.sql').read_text())
        try:
            db.executescript('BEGIN IMMEDIATE;'+(ROOT/'004.sql').read_text()+'SELECT * FROM missing_table; COMMIT;')
        except sqlite3.OperationalError:
            db.rollback()
        else:
            self.fail('expected migration failure')
        self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],2)
        self.assertEqual(db.execute("SELECT count(*) FROM sqlite_master WHERE name='collector_alerts'").fetchone()[0],0)
        db.close()

if __name__ == '__main__':
    unittest.main(verbosity=2)
