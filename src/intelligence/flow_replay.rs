//! Offline deterministic replay of explicitly selected datagrams.
//! No socket, archive writes, credential handling, or traffic extrapolation.
use super::flow::Decoder;
use crate::Result;
use serde::{Deserialize, Serialize};
use std::{io::Read, net::SocketAddr, path::Path};

const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_PACKETS: usize = 4096;
const MAX_HEX: usize = 2 * 65535;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    exporter: SocketAddr,
    received_utc: u64,
    hex: String,
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub datagrams: usize,
    pub invalid: usize,
    pub duplicates: usize,
    pub decoded_records: usize,
    pub missing_templates: u64,
    pub skipped: u64,
    pub repeated_sequence: usize,
    pub reordered_sequence: usize,
    pub generation_restarts: usize,
    pub sampling_fields: usize,
    pub nat_fields: usize,
}

fn decode_hex(input: &str) -> Result<Vec<u8>> {
    if input.is_empty() || input.len() > MAX_HEX || !input.len().is_multiple_of(2) {
        return Err("Ukuran hex datagram tidak valid.".into());
    }
    fn digit(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    input.as_bytes().chunks_exact(2).map(|pair| {
        let a = digit(pair[0]).ok_or("Hex tidak valid.")?;
        let b = digit(pair[1]).ok_or("Hex tidak valid.")?;
        Ok((a << 4) | b)
    }).collect()
}

/// JSONL order is receive order; backward receive time is rejected to avoid
/// changing template expiry semantics. Exporter clock reorder is diagnosed by Decoder.
pub fn replay(bytes: &[u8]) -> Result<Report> {
    if bytes.len() > MAX_BYTES {
        return Err("Replay melebihi 8 MiB.".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "Replay harus UTF-8.")?;
    let mut report = Report::default();
    let mut decoder = Decoder::default();
    let mut previous = None;
    for line in text.lines() {
        if report.datagrams == MAX_PACKETS || line.len() > MAX_HEX + 256 {
            return Err("Replay melebihi batas frame.".into());
        }
        let frame: Frame = serde_json::from_str(line).map_err(|_| "Frame replay JSON tidak valid.")?;
        if frame.exporter.ip().is_unspecified() || frame.exporter.ip().is_multicast()
            || frame.exporter.port() == 0 || previous.is_some_and(|old| frame.received_utc < old)
        {
            return Err("Identitas atau waktu terima replay tidak valid.".into());
        }
        previous = Some(frame.received_utc);
        let packet = decode_hex(&frame.hex)?;
        report.datagrams += 1;
        match decoder.ingest(frame.exporter, &packet, frame.received_utc) {
            Ok(batch) => {
                report.duplicates += usize::from(batch.duplicate);
                report.decoded_records += batch.flows.len();
                report.missing_templates += u64::from(batch.missing);
                report.skipped += u64::from(batch.skipped);
                report.repeated_sequence += usize::from(batch.sequence_repeated);
                report.reordered_sequence += usize::from(batch.sequence_reordered);
                report.generation_restarts += usize::from(batch.generation_restart);
                report.sampling_fields += batch.provenance.iter().filter(|p| p.has_sampling()).count();
                report.nat_fields += batch.provenance.iter().filter(|p| p.has_nat()).count();
            }
            Err(_) => report.invalid += 1,
        }
    }
    Ok(report)
}

pub fn read(path: &Path) -> Result<Report> {
    let mut bytes = Vec::new();
    std::fs::File::open(path).map_err(|e| e.to_string())?
        .take(MAX_BYTES as u64 + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    replay(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deterministic_replay_and_rejections() {
        // IPFIX header-only packet, 16 bytes, sequence 1, observation domain 11.
        let line = r#"{"exporter":"192.0.2.1:4739","received_utc":100,"hex":"000a001000000064000000010000000b"}"#;
        let input = format!("{line}\n{line}\n");
        let report = replay(input.as_bytes()).unwrap();
        assert_eq!(report.datagrams, 2);
        assert_eq!(report.duplicates, 1);
        assert_eq!(report.invalid, 0);
        let backwards = format!("{line}\n{}", line.replace(":100", ":99"));
        assert!(replay(backwards.as_bytes()).is_err());
        assert!(replay(line.replace("000a", "zzzz").as_bytes()).is_err());
        assert!(replay(line.replace("192.0.2.1", "0.0.0.0").as_bytes()).is_err());
        assert!(replay(line.replace("\"hex\"", "\"unknown\"").as_bytes()).is_err());
        assert_eq!(replay(line.replace("000a0010", "000a0011").as_bytes()).unwrap().invalid, 1);
    }
}
