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
pub fn summarize_octet_counted(input: &[u8]) -> Result<Summary> {
    read_framed(input)
}

/// Incremental octet-counted reader. The caller supplies a bounded transport
/// and its own deadline; no assumption of TLS or authentication is made here.
/// One frame is buffered at a time, and truncation never publishes a summary.
pub fn read_framed(reader: impl Read) -> Result<Summary> {
    use std::io::{BufReader, ErrorKind};
    let mut reader = BufReader::new(reader.take(MAX_BYTES as u64 + 1));
    let mut out = Summary::default();
    let mut total = 0usize;
    let mut frame = Vec::with_capacity(MAX_LINE);
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("Baca framing Syslog: {e}")),
        }
        total += 1;
        if total > MAX_BYTES || !matches!(byte[0], b'1'..=b'9') {
            return Err("Prefix frame Syslog tidak kanonik atau batas byte tercapai.".into());
        }
        let mut len = usize::from(byte[0] - b'0');
        let mut digits = 1;
        loop {
            reader.read_exact(&mut byte).map_err(|_| "Prefix frame Syslog terpotong.")?;
            total += 1;
            if total > MAX_BYTES {
                return Err("Batas byte Syslog tercapai.".into());
            }
            if byte[0] == b' ' {
                break;
            }
            digits += 1;
            if digits > 4 || !byte[0].is_ascii_digit() {
                return Err("Panjang frame Syslog tidak valid.".into());
            }
            len = len * 10 + usize::from(byte[0] - b'0');
        }
        if len > MAX_LINE || total + len > MAX_BYTES || out.accepted + out.rejected >= MAX_LINES {
            return Err("Batas ukuran atau jumlah frame Syslog tercapai.".into());
        }
        frame.resize(len, 0);
        reader.read_exact(&mut frame).map_err(|_| "Frame Syslog terpotong.")?;
        total += len;
        let group = std::str::from_utf8(&frame).ok()
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
/// Incremental framing for an already authenticated, bounded transport.
/// Unlike the offline all-or-nothing parser, completed frames are independent
/// observations. A malformed suffix cannot retract an emitted batch.
#[derive(Default)]
pub struct FramedStream {
    prefix: usize,
    digits: usize,
    remaining: Option<usize>,
    frame: Vec<u8>,
    total_bytes: usize,
    total_frames: usize,
    pending: Summary,
    failed: bool,
}
impl FramedStream {
    pub const MAX_STREAM_BYTES: usize = 16 * 1024 * 1024;
    pub const MAX_STREAM_FRAMES: usize = 65_536;
    pub const BATCH_FRAMES: usize = 64;

    pub fn pending_frames(&self) -> usize { self.pending.accepted + self.pending.rejected }
    pub fn in_frame(&self) -> bool { self.digits != 0 || self.remaining.is_some() }
    pub fn take_summary(&mut self) -> Option<Summary> {
        (self.pending_frames() != 0).then(|| std::mem::take(&mut self.pending))
    }
    pub fn complete(&self) -> Result<()> {
        if self.failed || self.in_frame() { Err("Stream Syslog tidak lengkap.".into()) } else { Ok(()) }
    }
    pub fn feed(&mut self, bytes: &[u8], mut emit: impl FnMut(Summary) -> Result<()>) -> Result<()> {
        if self.failed { return Err("Framing stream sudah gagal.".into()); }
        let result = self.feed_inner(bytes,&mut emit);
        if result.is_err() {
            self.failed=true;
            self.frame.fill(0);
            self.frame.clear();
        }
        result
    }
    fn feed_inner(&mut self, bytes: &[u8], emit: &mut impl FnMut(Summary) -> Result<()>) -> Result<()> {
        for &byte in bytes {
            if self.total_bytes == Self::MAX_STREAM_BYTES { return Err("Batas byte stream tercapai.".into()); }
            self.total_bytes+=1;
            if let Some(remaining)=self.remaining {
                self.frame.push(byte);
                if remaining > 1 {
                    self.remaining=Some(remaining-1);
                    continue;
                }
                let group=std::str::from_utf8(&self.frame).ok()
                    .filter(|s| !s.chars().any(|c| c.is_control() && c!='\t')).and_then(priority);
                if let Some(group)=group {
                    *self.pending.groups.entry(group).or_default()+=1;
                    self.pending.accepted+=1;
                } else { self.pending.rejected+=1; }
                self.frame.fill(0);
                self.frame.clear();
                self.remaining=None;
                self.total_frames+=1;
                if self.pending_frames() == Self::BATCH_FRAMES {
                    if let Some(summary)=self.take_summary() { emit(summary)?; }
                }
            } else if byte == b' ' {
                if self.digits == 0 || self.prefix == 0 || self.prefix > MAX_LINE
                    || self.total_frames >= Self::MAX_STREAM_FRAMES {
                    return Err("Panjang atau jumlah frame stream tidak valid.".into());
                }
                self.remaining=Some(self.prefix);
                self.prefix=0;
                self.digits=0;
            } else {
                if !byte.is_ascii_digit() || (self.digits==0 && byte==b'0') || self.digits==4 {
                    return Err("Prefix stream Syslog tidak kanonik.".into());
                }
                self.digits+=1;
                self.prefix=self.prefix*10+usize::from(byte-b'0');
            }
        }
        Ok(())
    }
}

pub fn read_octet_counted(path: &Path) -> Result<Summary> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    read_framed(file)
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
    fn fragmented_stream_has_same_result_and_rejects_truncated_tail() {
        struct Fragmented<'a>(&'a [u8]);
        impl Read for Fragmented<'_> {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                if out.is_empty() || self.0.is_empty() { return Ok(0); }
                out[0] = self.0[0];
                self.0 = &self.0[1..];
                Ok(1)
            }
        }
        let a = "<13>message";
        let b = "<14>second";
        let bytes = format!("{} {a}{} {b}", a.len(), b.len());
        let normal = summarize_octet_counted(bytes.as_bytes()).unwrap();
        let split = read_framed(Fragmented(bytes.as_bytes())).unwrap();
        assert_eq!(normal.groups, split.groups);
        assert_eq!(normal.accepted, split.accepted);
        assert!(read_framed(Fragmented(&bytes.as_bytes()[..bytes.len() - 1])).is_err());
    }

    #[test]
    fn stream_emits_complete_batches_before_eof_and_preserves_valid_prefix() {
        let mut parser=FramedStream::default();
        let frame=b"5 <13>x";
        let mut batches=Vec::new();
        for _ in 0..65 {
            for byte in frame { parser.feed(&[*byte],|summary| { batches.push(summary); Ok(()) }).unwrap(); }
        }
        assert_eq!(batches.len(),1);
        assert_eq!(batches[0].accepted,64);
        assert_eq!(parser.pending_frames(),1);
        parser.feed(b"6 <14>",|_|Ok(())).unwrap();
        assert!(parser.in_frame());
        assert!(parser.complete().is_err());
        assert_eq!(parser.take_summary().unwrap().accepted,1);
        assert!(parser.take_summary().is_none());
    }
    #[test]
    fn stream_rejects_bad_prefix_and_never_reuses_poisoned_state() {
        for bad in [b"0 ".as_slice(),b"99999 x",b"8193 ",b"1x"] {
            let mut p=FramedStream::default();
            p.feed(b"5 <13>x",|_|Ok(())).unwrap();
            assert!(p.feed(bad,|_|Ok(())).is_err());
            assert_eq!(p.take_summary().unwrap().accepted,1);
            assert!(p.feed(b"5 <13>x",|_|Ok(())).is_err());
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
