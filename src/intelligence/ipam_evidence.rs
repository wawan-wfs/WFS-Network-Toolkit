//! Explicitly captured, aggregate subnet evidence. No allocation or scanning.
use crate::Result;
use rusqlite::{Connection,OpenFlags,OptionalExtension,TransactionBehavior,params};
use serde::{Deserialize,Serialize};
use std::{net::IpAddr,path::Path,time::Duration};
const SCHEMA:&str=include_str!("sql/ipam_evidence_schema.sql");

#[derive(Clone,Debug,Eq,PartialEq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    pub scope:String,
    pub cidr:String,
    pub observed_at:u64,
    pub recorded_at:u64,
    pub configured:usize,
    pub observed:usize,
    pub partial:bool,
}
fn key_valid(scope:&str,cidr:&str)->bool {
    let Some(hash)=scope.strip_prefix("scope:v1:") else {return false};
    if !super::secure_monitor::pin_valid(hash) {return false;}
    let Some((ip,bits))=cidr.split_once('/') else {return false};
    let (Ok(ip),Ok(bits))=(ip.parse::<IpAddr>(),bits.parse::<u8>()) else {return false};
    super::overview::Prefix::new(ip,bits).is_some_and(|p|p.to_string()==cidr)
}
impl Capture {
    pub fn from_row(row:&super::overview::SubnetRow,now:u64)->Option<Self> {
        let value=Self{scope:row.operator_scope.clone()?,cidr:row.prefix.to_string(),
            observed_at:row.observed_at,recorded_at:now,configured:row.configured,
            observed:row.observed,partial:row.partial};
        value.validate().ok()?;
        Some(value)
    }
    fn validate(&self)->Result<()> {
        if !key_valid(&self.scope,&self.cidr) || self.observed_at==0 || self.recorded_at<self.observed_at
            || self.recorded_at>i64::MAX as u64 || !(1..=1_000_000).contains(&self.configured)
            || self.observed>1_000_000 {
            return Err("Bukti subnet tidak valid atau scope tidak terverifikasi.".into());
        }
        Ok(())
    }
}
fn error(e:impl std::fmt::Display)->String {format!("Bukti IPAM: {e}")}
fn open(path:&Path,write:bool)->Result<Connection> {
    if write && let Some(parent)=path.parent().filter(|p|!p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(error)?;
    }
    let flags=if write {OpenFlags::SQLITE_OPEN_READ_WRITE|OpenFlags::SQLITE_OPEN_CREATE}
        else {OpenFlags::SQLITE_OPEN_READ_ONLY};
    let mut db=Connection::open_with_flags(path,flags).map_err(error)?;
    db.busy_timeout(Duration::from_millis(1500)).map_err(error)?;
    db.execute_batch("PRAGMA trusted_schema=OFF;").map_err(error)?;
    fn verify(db:&Connection)->Result<()> {
        let id:i64=db.pragma_query_value(None,"application_id",|r|r.get(0)).map_err(error)?;
        let version:i64=db.pragma_query_value(None,"user_version",|r|r.get(0)).map_err(error)?;
        if id!=1464742227 || version!=1 {return Err("Database bukti IPAM tidak kompatibel.".into());}
        Ok(())
    }
    if write {
        let tx=db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(error)?;
        let id:i64=tx.pragma_query_value(None,"application_id",|r|r.get(0)).map_err(error)?;
        let v:i64=tx.pragma_query_value(None,"user_version",|r|r.get(0)).map_err(error)?;
        let n:i64=tx.query_row("SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",[],|r|r.get(0)).map_err(error)?;
        if id==0 && v==0 && n==0 {tx.execute_batch(SCHEMA).map_err(error)?;}
        verify(&tx)?;
        tx.commit().map_err(error)?;
    } else {verify(&db)?;}
    Ok(db)
}
/// Same source snapshot is idempotent, even if captured again later.
/// Conflicting same-timestamp evidence is rejected rather than overwritten.
pub fn save(path:&Path,c:&Capture)->Result<bool> {
    c.validate()?;
    let mut db=open(path,true)?;
    let tx=db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(error)?;
    let old:Option<(i64,i64,bool)>=tx.query_row(
        "SELECT configured,observed,partial FROM ipam_evidence WHERE scope=?1 AND cidr=?2 AND observed_at=?3",
        params![c.scope,c.cidr,c.observed_at as i64],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))
        .optional().map_err(error)?;
    if let Some(old)=old {
        if old!=(c.configured as i64,c.observed as i64,c.partial) {return Err("Bukti timestamp sama bertentangan.".into());}
        return Ok(false);
    }
    tx.execute("INSERT INTO ipam_evidence VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![c.scope,c.cidr,c.observed_at as i64,c.recorded_at as i64,c.configured as i64,c.observed as i64,c.partial]).map_err(error)?;
    tx.execute("DELETE FROM ipam_evidence WHERE scope=?1 AND cidr=?2 AND observed_at IN (SELECT observed_at FROM ipam_evidence WHERE scope=?1 AND cidr=?2 ORDER BY observed_at DESC LIMIT -1 OFFSET 120)",params![c.scope,c.cidr]).map_err(error)?;
    tx.execute("DELETE FROM ipam_evidence WHERE (scope,cidr,observed_at) IN (SELECT scope,cidr,observed_at FROM ipam_evidence ORDER BY recorded_at DESC,scope DESC,cidr DESC,observed_at DESC LIMIT -1 OFFSET 4096)",[]).map_err(error)?;
    let retained:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM ipam_evidence WHERE scope=?1 AND cidr=?2 AND observed_at=?3)",params![c.scope,c.cidr,c.observed_at as i64],|r|r.get(0)).map_err(error)?;
    tx.commit().map_err(error)?;
    Ok(retained)
}
pub fn page(path:&Path,scope:&str,cidr:&str,before:Option<u64>)->Result<Vec<Capture>> {
    if !key_valid(scope,cidr) || before.is_some_and(|n|n==0||n>i64::MAX as u64) {return Err("Key/cursor bukti tidak valid.".into());}
    if !path.try_exists().map_err(error)? {return Ok(Vec::new());}
    let db=open(path,false)?;
    let mut stmt=db.prepare("SELECT scope,cidr,observed_at,recorded_at,configured,observed,partial FROM ipam_evidence WHERE scope=?1 AND cidr=?2 AND observed_at<?3 ORDER BY observed_at DESC LIMIT 25").map_err(error)?;
    let mut rows=stmt.query(params![scope,cidr,before.unwrap_or(i64::MAX as u64) as i64]).map_err(error)?;
    let mut out=Vec::new();
    while let Some(r)=rows.next().map_err(error)? {
        let c=Capture{scope:r.get(0).map_err(error)?,cidr:r.get(1).map_err(error)?,
            observed_at:r.get(2).map_err(error)?,recorded_at:r.get(3).map_err(error)?,
            configured:r.get(4).map_err(error)?,observed:r.get(5).map_err(error)?,partial:r.get(6).map_err(error)?};
        c.validate()?;
        if c.scope!=scope || c.cidr!=cidr {return Err("Identitas bukti IPAM tidak cocok.".into());}
        out.push(c);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn history_dedup_conflict_and_scope_isolation() {
        let dir=std::env::temp_dir().join(format!("wenet-ipam-evidence-{}-{}",std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let path=dir.join("evidence.sqlite3");
        let mut c=Capture{scope:format!("scope:v1:{}","a".repeat(64)),cidr:"192.0.2.0/24".into(),
            observed_at:1,recorded_at:1000,configured:1,observed:2,partial:true};
        for i in 1..=130 {c.observed_at=i;assert!(save(&path,&c).unwrap());}
        assert!(!save(&path,&c).unwrap());
        c.observed=3;
        assert!(save(&path,&c).is_err());
        let first=page(&path,&c.scope,&c.cidr,None).unwrap();
        assert_eq!(first.len(),25);
        assert_eq!(first[0].observed_at,130);
        assert_eq!(page(&path,&c.scope,&c.cidr,Some(first[24].observed_at)).unwrap()[0].observed_at,105);
        assert!(page(&path,&format!("scope:v1:{}","b".repeat(64)),&c.cidr,None).unwrap().is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
