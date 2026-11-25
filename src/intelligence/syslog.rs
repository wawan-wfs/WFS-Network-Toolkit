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
            || fields[..5].iter().any(|s| s.is_empty() || s.len() > 255 || !s.is_ascii())
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
pub fn read(path: &Path) -> Result<Summary> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES as u64 + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
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
    fn bounds_lines_and_payload() {
        let lines = "<13>message\n".repeat(MAX_LINES + 1);
        let result = summarize(lines.as_bytes()).unwrap();
        assert_eq!(result.accepted, MAX_LINES);
        assert!(result.limited);
        assert!(summarize(&vec![0; MAX_BYTES + 1]).is_err());
        assert!(summarize(&[255]).is_err());
    }
}
