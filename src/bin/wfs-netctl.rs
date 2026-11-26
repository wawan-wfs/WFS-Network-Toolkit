#[cfg(not(windows))]
fn main() {
    eprintln!("wfs-netctl memerlukan Windows.");
}
#[cfg(windows)]
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
#[cfg(windows)]
fn run() -> wfs_network_toolkit::Result<()> {
    use std::{env, path::Path};
    use wfs_network_toolkit::intelligence::{self as ni, history, store, windows as nw};
    use wfs_network_toolkit::{MacRequest, read_backup, windows as w, write_new_json};
    let a: Vec<String> = env::args().skip(1).collect();
    match a.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["list"] => {
            for n in w::adapters()? {
                println!(
                    "{} | {} | {} | index {} | {} | antarmuka {} | aktif {} | permanen {}",
                    n.id,
                    n.name,
                    n.description,
                    n.index,
                    n.link_label(),
                    n.admin.label(),
                    n.active_mac.map_or_else(|| "-".into(), |m| m.to_string()),
                    n.permanent_mac
                        .map_or_else(|| "-".into(), |m| m.to_string())
                );
            }
        }
        ["inspect", id] => {
            let n = w::adapter(id)?;
            println!("{n:#?}");
            match w::driver_info(id) {
                Ok(x) => println!("{x}"),
                Err(e) => println!("Metadata driver tidak tersedia: {e}"),
            }
            println!("IPv4 konfigurasi: {:#?}", w::ipv4_config(&n));
            println!("Transaksi tertunda: {:?}", w::pending(id));
        }
        ["backup", id, path] | ["backup", id, path, "--include-mac"] => {
            let (b, warn) = w::backup(id, a.len() == 4)?;
            write_new_json(Path::new(path), &b)?;
            println!("Backup disimpan ke {path}");
            if let Some(w) = warn {
                println!("IPv4 tidak dicadangkan: {w}");
            }
        }
        ["check-backup", path] => {
            let (profile, legacy) = read_backup(Path::new(path))?;
            println!(
                "Profil valid · sumber: {} · format: {}",
                profile.source_name,
                if legacy { "IPv4 lama" } else { "WeNet Toolkit" }
            );
            println!(
                "IPv4/DNS: {}",
                if profile.ipv4.is_some() {
                    "ada"
                } else {
                    "tidak ada"
                }
            );
            println!(
                "MAC: {}",
                if profile.mac.is_some() {
                    "ada"
                } else {
                    "tidak ada"
                }
            );
        }
        ["snapshot-local", path] => {
            write_new_json(Path::new(path), &nw::local_snapshot())?;
            println!("Snapshot Windows disimpan. Berkas memuat alamat dan endpoint lokal.");
        }
        ["history-list"] => {
            let h = history::load(&history::default_dir()?, ni::now())?;
            for s in h.snapshots {
                println!(
                    "{} | UTC {} | {} bagian",
                    s.source,
                    s.observed_at,
                    s.sections.len()
                );
            }
            if h.unreadable > 0 {
                eprintln!("{} arsip tidak dapat dibaca.", h.unreadable);
            }
        }
        ["dhcp6-history", path, authority] => {
            let rows = ni::dhcp6_history::page(Path::new(path), authority)?;
            println!("{}", serde_json::to_string_pretty(&rows).map_err(|e| e.to_string())?);
        }
        ["dhcp6-history", path, authority, before] => {
            let stamp = before.parse::<u64>().map_err(|_| "Cursor UTC tidak valid.")?;
            let rows = ni::dhcp6_history::page_before(Path::new(path), authority, Some(stamp))?;
            println!("{}", serde_json::to_string_pretty(&rows).map_err(|e| e.to_string())?);
        }
        ["dhcp6-export-summary", path, authority, destination] => {
            ni::dhcp6_history::export_summary(Path::new(path), authority, Path::new(destination))?;
            println!("Ringkasan agregat DHCPv6 disimpan.");
        }
        ["ipam-overlap", path, input] => {
            let note = ni::ipam_notes::Note::parse(input)?;
            for row in ni::ipam_notes::overlaps(Path::new(path), &note)? {
                println!("{} | {} | revisi {}", row.scope, row.cidr, row.revision);
            }
        }
        ["ipam-recover", source, destination, "--confirm"] => {
            ni::ipam_notes::recover(Path::new(source), Path::new(destination))?;
            println!("Salinan IPAM dipulihkan ke berkas baru; sumber tidak diubah.");
        }
        ["archive-info"] => {
            let path = store::default_path()?;
            if !path.exists() {
                println!("Belum ada arsip SQLite.");
            } else {
                let (flow, snapshots) = store::Archive::reader(&path)?.counts()?;
                println!(
                    "{flow} flow · {snapshots} snapshot impor · {}",
                    path.display()
                );
            }
        }
        ["archive-health"] => {
            let path = store::default_path()?;
            if path.try_exists().map_err(|e| e.to_string())? {
                let stats = store::Archive::reader(&path)?.health(&path)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&stats).map_err(|e| e.to_string())?
                );
            } else {
                println!("Belum ada arsip SQLite.");
            }
        }
        ["archive-backup", path, "--confirm"] => {
            store::Archive::reader(&store::default_path()?)?.backup_to(Path::new(path))?;
            println!(
                "Backup konsisten disimpan. Berkas berisi metadata jaringan yang tidak disamarkan."
            );
        }
        ["archive-verify", path] => {
            let db = store::Archive::reader(Path::new(path))?;
            db.check()?;
            let (flows, snapshots) = db.counts()?;
            println!("Arsip valid · {flows} flow · {snapshots} snapshot.");
        }
        ["archive-list-snapshots"] => {
            let path = store::default_path()?;
            if path.exists() {
                for (source, observed) in store::Archive::reader(&path)?.snapshot_summaries()? {
                    println!("{source} · UTC {observed}");
                }
            } else {
                println!("Belum ada arsip SQLite.");
            }
        }
        ["archive-import-history", "--confirm"] => {
            let h = history::load(&history::default_dir()?, ni::now())?;
            if h.snapshots.is_empty() {
                println!(
                    "Tidak ada snapshot valid dalam jendela histori lama. Tidak terbaca: {}.",
                    h.unreadable
                );
            } else {
                let n = store::Archive::writer(&store::default_path()?)?.import(&h.snapshots)?;
                println!(
                    "{n} diimpor · {} sudah ada · {} tidak terbaca. Berkas sumber tidak diubah.",
                    h.snapshots.len() - n,
                    h.unreadable
                );
            }
        }
        ["history-clear", "--confirm"] => {
            let count = history::clear(&history::default_dir()?)?;
            println!("{count} snapshot dihapus.");
        }
        ["probe-https", "--confirm"] => {
            let p = nw::probe_https();
            println!(
                "{}",
                serde_json::to_string_pretty(&p).map_err(|e| e.to_string())?
            );
            if p.outcome != wfs_network_toolkit::intelligence::ProbeOutcome::Verified {
                return Err(
                    "Probe belum menghasilkan bukti yang bisa dikaitkan ke IP sumber.".into(),
                );
            }
        }
        ["set-mac", id, mac, "--confirm"] => {
            if w::remote_session() {
                return Err("Gunakan konsol lokal untuk mutasi CLI".into());
            }
            let target = mac.parse()?;
            let n = w::adapter(id)?;
            println!("{} {}: {:?} -> {target}", n.name, n.id, n.active_mac);
            println!("{}", w::apply(id, MacRequest::Set(target), None)?);
        }
        ["reset-mac", id, "--confirm"] => {
            if w::remote_session() {
                return Err("Gunakan konsol lokal untuk mutasi CLI".into());
            }
            println!("{}", w::apply(id, MacRequest::Factory, None)?);
        }
        ["recover", id, "--confirm"] => {
            if w::remote_session() {
                return Err("Gunakan konsol lokal untuk pemulihan CLI".into());
            }
            println!("{}", w::recover(id)?);
        }
        _ => println!(
            "WeNet Toolkit CLI\n  list\n  inspect <GUID>\n  backup <GUID> <file.json> [--include-mac]\n  check-backup <file.json>\n  snapshot-local <file.json>\n  probe-https --confirm\n  history-list\n  dhcp6-history <file.sqlite3> <authority> [before-utc]\n  dhcp6-export-summary <file.sqlite3> <authority> <new.json>\n  ipam-overlap <file.sqlite3> <scope|CIDR|label/reserved|alias|tag|note>\n  ipam-recover <backup.sqlite3> <new.sqlite3> --confirm\n  archive-info\n  archive-health\n  archive-backup <salinan.sqlite3> --confirm\n  archive-verify <salinan.sqlite3>\n  archive-list-snapshots\n  archive-import-history --confirm\n  history-clear --confirm\n  set-mac <GUID> <MAC> --confirm\n  reset-mac <GUID> --confirm\n  recover <GUID> --confirm\nPerintah mutasi memerlukan konsol Administrator lokal dan adaptor uji yang diizinkan."
        ),
    }
    Ok(())
}
