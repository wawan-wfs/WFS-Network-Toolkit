//! Local archive policy and reviewed maintenance operations.
use super::store::Archive;
use crate::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    pub flow_days: u64,
    pub snapshot_days: u64,
    pub quota_mib: u64,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            flow_days: 30,
            snapshot_days: 7,
            quota_mib: 256,
        }
    }
}
impl Policy {
    pub fn new(flow_days: u64, snapshot_days: u64, quota_mib: u64) -> Result<Self> {
        if !(1..=365).contains(&flow_days)
            || !(1..=365).contains(&snapshot_days)
            || !(16..=1024).contains(&quota_mib)
        {
            return Err("Gunakan retensi 1–365 hari dan kuota 16–1.024 MiB.".into());
        }
        Ok(Self {
            flow_days,
            snapshot_days,
            quota_mib,
        })
    }
    pub fn parse(input: &str) -> Result<Self> {
        if input.len() > 128 {
            return Err("Masukan pengaturan terlalu panjang.".into());
        }
        let values: Vec<u64> = input
            .split_ascii_whitespace()
            .map(str::parse)
            .collect::<std::result::Result<_, _>>()
            .map_err(|_| "Gunakan tiga angka: hari flow, hari snapshot, kuota MiB.")?;
        let [flow, snapshots, quota] = values.as_slice() else {
            return Err("Gunakan tiga angka: hari flow, hari snapshot, kuota MiB.".into());
        };
        Self::new(*flow, *snapshots, *quota)
    }
    pub fn summary(self) -> String {
        format!(
            "Flow {} hari · Snapshot SQLite {} hari · DB {} MiB",
            self.flow_days, self.snapshot_days, self.quota_mib
        )
    }
    pub(crate) fn pages(self, page_size: i64) -> i64 {
        (self.quota_mib as i64 * 1024 * 1024) / page_size
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Flow,
    Snapshot,
}
impl Kind {
    pub fn parse(input: &str) -> Result<Self> {
        match input {
            "flow" => Ok(Self::Flow),
            "snapshot" => Ok(Self::Snapshot),
            _ => Err("Pilih flow atau snapshot.".into()),
        }
    }
    pub(crate) fn table(self) -> (&'static str, &'static str) {
        match self {
            Self::Flow => ("flow", "received"),
            Self::Snapshot => ("snapshots", "observed"),
        }
    }
}

pub const DELETE_LIMIT: usize = 10_000;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeletePreview {
    pub kind: Kind,
    pub start: u64,
    pub end: u64,
    pub count: usize,
    pub(crate) fingerprint: [u8; 32],
}
impl DeletePreview {
    pub fn binding(&self) -> String {
        self.fingerprint
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

/// A directory created exclusively beside the destination. Publication uses one
/// filesystem operation that refuses to replace any existing destination.
pub(crate) struct Stage {
    dir: PathBuf,
    pub file: PathBuf,
}
impl Stage {
    pub fn new(destination: &Path) -> Result<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        for _ in 0..32 {
            let dir = parent.join(format!(
                ".wfs-archive-{}-{}-{}",
                std::process::id(),
                super::now(),
                SERIAL.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&dir) {
                Ok(()) => {
                    return Ok(Self {
                        file: dir.join("archive.sqlite3"),
                        dir,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("Folder sementara tidak dapat dibuat: {e}")),
            }
        }
        Err("Folder sementara arsip tidak dapat dialokasikan.".into())
    }
    pub fn publish(&self, destination: &Path) -> Result<()> {
        require_no_sidecars(destination)?;
        fs::hard_link(&self.file, destination).map_err(|e| format!(
            "Salinan tidak dipublikasikan. Gunakan nama baru pada volume yang mendukung hard link (misalnya NTFS): {e}"
        ))
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.file);
        let _ = fs::remove_dir(&self.dir);
    }
}

fn require_no_sidecars(path: &Path) -> Result<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(suffix);
        if Path::new(&sidecar)
            .try_exists()
            .map_err(|e| e.to_string())?
        {
            return Err("Pemulihan hanya menerima backup mandiri tanpa sidecar SQLite.".into());
        }
    }
    Ok(())
}

pub fn check_recovery_destination(target: &Path, active: &Path) -> Result<()> {
    let parent = |p: &Path| {
        p.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .canonicalize()
            .map_err(|e| e.to_string())
    };
    if parent(active)
        .ok()
        .is_some_and(|a| parent(target).is_ok_and(|t| t == a))
        && let (Some(a), Some(t)) = (active.file_name(), target.file_name())
    {
        let a = a.to_string_lossy().to_lowercase();
        // Win32 can strip trailing periods/spaces from a component.
        let t = t
            .to_string_lossy()
            .trim_end_matches(['.', ' '])
            .to_lowercase();
        if t == a
            || ["-wal", "-shm", "-journal"]
                .iter()
                .any(|s| t == format!("{a}{s}"))
        {
            return Err("Pilih file selain arsip utama dan sidecar-nya.".into());
        }
    }
    Ok(())
}

fn hash_standalone(path: &Path) -> Result<[u8; 32]> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err("Pilih berkas salinan SQLite biasa.".into());
    }
    require_no_sidecars(path)?;
    const MAX: u64 = 1024 * 1024 * 1024;
    if meta.len() > MAX {
        return Err("Salinan melebihi batas pemulihan 1 GiB.".into());
    }
    let mut digest = Sha256::new();
    let f = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut f = f.take(MAX + 1);
    if std::io::copy(&mut f, &mut digest).map_err(|e| e.to_string())? > MAX {
        return Err("Salinan melebihi batas pemulihan 1 GiB.".into());
    }
    Ok(digest.finalize().into())
}
#[derive(Debug)]
pub struct RecoveryPlan {
    fingerprint: [u8; 32],
    pub flows: i64,
    pub snapshots: i64,
}
impl RecoveryPlan {
    pub fn inspect(source: &Path) -> Result<Self> {
        let fingerprint = hash_standalone(source)?;
        let src = Archive::reader(source)?;
        src.check_standalone()?;
        let (flows, snapshots) = src.counts()?;
        drop(src);
        if hash_standalone(source)? != fingerprint {
            return Err("Sumber berubah selama pratinjau. Pilih ulang.".into());
        }
        Ok(Self {
            fingerprint,
            flows,
            snapshots,
        })
    }
    pub fn recover(&self, source: &Path, destination: &Path) -> Result<()> {
        if hash_standalone(source)? != self.fingerprint {
            return Err(
                "Sumber berubah setelah pratinjau. Tidak ada salinan dipublikasikan.".into(),
            );
        }
        let stage = Stage::new(destination)?;
        fs::copy(source, &stage.file).map_err(|e| e.to_string())?;
        if hash_standalone(&stage.file)? != self.fingerprint
            || hash_standalone(source)? != self.fingerprint
        {
            return Err("Sumber berubah saat dipulihkan. Tidak ada salinan dipublikasikan.".into());
        }
        let restored = Archive::reader(&stage.file)?;
        restored.check_standalone()?;
        drop(restored);
        fs::OpenOptions::new()
            .write(true)
            .open(&stage.file)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        stage.publish(destination)
    }
}
