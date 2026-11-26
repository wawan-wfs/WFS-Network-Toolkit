//! Explicit, one-shot, native security transport candidate.
//! No service registration, persistent credential file, community fallback,
//! automatic router discovery, or automatic invocation by the desktop.
mod snmp;
mod tls_syslog;

use std::{env, process::ExitCode};
type Result<T> = std::result::Result<T, String>;

fn run(args: &[String]) -> Result<()> {
    let report = match args {
        [cmd, target, confirm] if cmd == "snmpv3-get" && confirm == "--confirm" => {
            snmp::get_once(target)?
        }
        [cmd, config, confirm] if cmd == "syslog-tls-once" && confirm == "--confirm" => {
            tls_syslog::receive_once(std::path::Path::new(config))?
        }
        _ => {
            return Err("WeNet Toolkit by WFS Project — secure transport candidate\n\
                snmpv3-get <IP:port> --confirm (credential JSON via non-terminal stdin)\n\
                syslog-tls-once <config.json> --confirm".into());
        }
    };
    let json = serde_json::to_string_pretty(&report).map_err(|_| "Serialisasi hasil gagal.")?;
    println!("{json}");
    Ok(())
}

fn main() -> ExitCode {
    match run(&env::args().skip(1).collect::<Vec<_>>()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
