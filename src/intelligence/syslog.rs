//! Offline, explicitly selected syslog file. Never opens a listener or stores raw payload.
use crate::Result;
use std::{collections::BTreeMap, io::Read, path::Path};

pub const MAX_BYTES: usize = 1_048_576;
pub const MAX_LINES: usize = 10_000;
const MAX_LINE: usize = 8192;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Format {
    Rfc5424Header,
    LegacyPriority,
}
#[derive(Default, Debug)]
pub struct Summary {
    pub accepted: usize,
    pub rejected: usize,
    pub limited: bool,
    pub groups: BTreeMap<(Format, u8, u8), usize>,
}
fn priority(line: &str) -> Option<(Format, u8, u8)> {
    let (pri, rest) = line.strip_prefix('<')?.split_once('>')?;
    if pri.is_empty() || pri.len() > 3 || !pri.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let pri: u8 = pri.parse().ok()?;
    if pri > 191 || rest.is_empty() {
        return None;
    }
    let format = if let Some(header) = rest.strip_prefix("1 ") {
        // Validate presence of the five remaining HEADER fields. Do not
        // parse/persist message, hostname, timestamps or structured data.
        let fields: Vec<_> = header.splitn(6, ' ').collect();
        if fields.len() != 6
            || fields[..5]
                .iter()
                .any(|s| s.is_empty() || s.len() > 255 || !s.is_ascii())
            || !(fields[5].starts_with('[') || fields[5].starts_with('-'))
        {
            return None;
        }
        Format::Rfc5424Header
    } else if rest.bytes().next().is_some_and(|b| b.is_ascii_digit()) {
        // Unknown RFC5424 version or malformed header. No legacy fallback.
        return None;
    } else {
        Format::LegacyPriority
    };
    Some((format, pri / 8, pri % 8))
}
pub fn summarize(bytes: &[u8]) -> Result<Summary> {
    if bytes.len() > MAX_BYTES {
        return Err("File syslog melewati 1 MiB.".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "Syslog harus UTF-8 yang valid.")?;
    let mut out = Summary::default();
    for (i, line) in text.lines().enumerate() {
        if i >= MAX_LINES {
            out.limited = true;
            break;
        }
        if line.len() > MAX_LINE || line.chars().any(|c| c.is_control() && c != '\t') {
            out.rejected += 1;
            continue;
        }
        if let Some(group) = priority(line) {
            *out.groups.entry(group).or_default() += 1;
            out.accepted += 1;
        } else {
            out.rejected += 1;
        }
    }
    Ok(out)
}
/// RFC 5425 octet-counting frame parser. This function is transport-agnostic:
/// neither a successful parse nor the Syslog header proves sender authentication.
/// A future TLS receiver must verify the peer before invoking this routine.
pub fn summarize_octet_counted(mut input: &[u8]) -> Result<Summary> {
    if input.len() > MAX_BYTES {
        return Err("Stream Syslog melewati batas 1 MiB.".into());
    }
    let mut out = Summary::default();
    let mut frames = 0;
    while !input.is_empty() {
        frames += 1;
        if frames > MAX_LINES {
            return Err("Jumlah frame Syslog melewati batas.".into());
        }
        let separator = input.iter().take(6).position(|&b| b == b' ')
            .ok_or("Panjang frame Syslog tidak valid.")?;
        let prefix = &input[..separator];
        if prefix.is_empty() || prefix[0] == b'0' || !prefix.iter().all(u8::is_ascii_digit) {
            return Err("Prefix frame Syslog tidak kanonik.".into());
        }
        let len = std::str::from_utf8(prefix).map_err(|_| "Panjang frame tidak valid.")?
            .parse::<usize>().map_err(|_| "Panjang frame tidak valid.")?;
        input = &input[separator + 1..];
        if len == 0 || len > MAX_LINE || len > input.len() {
            return Err("Frame Syslog terlalu panjang atau terpotong.".into());
        }
        let (frame, rest) = input.split_at(len);
        input = rest;
        let group = std::str::from_utf8(frame).ok()
            .filter(|s| !s.chars().any(|c| c.is_control() && c != '\t'))
            .and_then(priority);
        if let Some(group) = group {
            *out.groups.entry(group).or_default() += 1;
            out.accepted += 1;
        } else {
            out.rejected += 1;
        }
    }
    Ok(out)
}
pub fn read_octet_counted(path: &Path) -> Result<Summary> {
    let mut bytes = Vec::new();
    std::fs::File::open(path).map_err(|e| e.to_string())?
        .take(MAX_BYTES as u64 + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    summarize_octet_counted(&bytes)
}

pub fn read(path: &Path) -> Result<Summary> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    summarize(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_isolated_from_untrusted_payload() {
        let sample = b"<34>1 2026-11-25T12:00:00Z host app 123 id - PRIVATE\n<13>Nov 25 00:00:00 host SECRET\n<192>bad\n<12>2 unknown\n<12>1 broken";
        let summary = summarize(sample).unwrap();
        assert_eq!(summary.accepted, 2);
        assert_eq!(summary.rejected, 3);
        assert_eq!(summary.groups[&(Format::Rfc5424Header, 4, 2)], 1);
        assert_eq!(summary.groups[&(Format::LegacyPriority, 1, 5)], 1);
        assert!(!format!("{summary:?}").contains("PRIVATE"));
    }

    #[test]
    fn octet_counting_never_treats_embedded_newline_as_another_frame() {
        let a = "<13>message";
        let b = "<14>second";
        let input = format!("{} {a}{} {b}", a.len(), b.len());
        let out = summarize_octet_counted(input.as_bytes()).unwrap();
        assert_eq!(out.accepted, 2);
        let bad = "<13>one\n<14>two";
        let framed = format!("{} {bad}", bad.len());
        assert_eq!(summarize_octet_counted(framed.as_bytes()).unwrap().rejected, 1);
        for invalid in ["0 ", "01 x", "99999 x", "4 abc", "+1 x", "2", "1 xtrailing"] {
            assert!(summarize_octet_counted(invalid.as_bytes()).is_err(), "{invalid}");
        }
    }

    #[test]
    fn bounds_lines_and_payload() {
        let lines = "<13>message\n".repeat(MAX_LINES + 1);
        let result = summarize(lines.as_bytes()).unwrap();
        assert_eq!(result.accepted, MAX_LINES);
        assert!(result.limited);
        assert!(summarize(&vec![0; MAX_BYTES + 1]).is_err());
        assert!(summarize(&[255]).is_err());
    }
}
