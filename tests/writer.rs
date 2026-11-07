//! Dependency-free ZIP writer for test fixtures.
//!
//! The whole point of the crate is having no dependencies worth auditing, so
//! the test suite has none either -- `cargo audit` reads dev-dependencies as
//! well, and a ZIP writer pulled in just for fixtures would undo that.
//!
//! Writes only what the fixtures need: Stored and Deflate entries with chosen
//! DOS timestamps, directory entries, an archive comment, ZipCrypto and WinZip
//! AES-256 encryption, and ZIP64 end records ([`zip64`]).

#![allow(dead_code)]

/// Signatures, duplicated from the reader rather than imported: a writer
/// that shared the reader's constants could not catch the reader getting
/// them wrong, which is the one bug a round-trip test exists to find.
const LOCAL_HEADER_SIG: u32 = 0x0403_4b50;
const CENTRAL_HEADER_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;
const ZIP64_EOCD_SIG: u32 = 0x0606_4b50;
const ZIP64_LOCATOR_SIG: u32 = 0x0706_4b50;

/// How an entry should be stored.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Stored,
    Deflated,
}

impl Method {
    fn code(self) -> u16 {
        match self {
            Self::Stored => 0,
            Self::Deflated => 8,
        }
    }
}

/// How an entry is encrypted, with its password.
#[derive(Clone, Copy)]
pub enum Crypt<'a> {
    ZipCrypto(&'a str),
    Aes256(&'a str),
}

/// One entry to write.
pub struct Entry<'a> {
    pub name: &'a str,
    pub body: &'a [u8],
    pub method: Method,
    /// `(year, month, day, hour, minute, second)`. Seconds are rounded
    /// down to even, as DOS stores them in two-second units.
    pub modified: Option<(u16, u8, u8, u8, u8, u8)>,
    pub crypt: Option<Crypt<'a>>,
}

impl<'a> Entry<'a> {
    pub fn stored(name: &'a str, body: &'a [u8]) -> Self {
        Self {
            name,
            body,
            method: Method::Stored,
            modified: None,
            crypt: None,
        }
    }
    pub fn deflated(name: &'a str, body: &'a [u8]) -> Self {
        Self {
            name,
            body,
            method: Method::Deflated,
            modified: None,
            crypt: None,
        }
    }
    pub fn at(mut self, y: u16, mo: u8, d: u8, h: u8, mi: u8, s: u8) -> Self {
        self.modified = Some((y, mo, d, h, mi, s));
        self
    }
    pub fn encrypted(mut self, crypt: Crypt<'a>) -> Self {
        self.crypt = Some(crypt);
        self
    }
}

/// One byte of ZIP's CRC-32 without the inversions: ZipCrypto's key update.
fn crc_step(crc: u32, b: u8) -> u32 {
    let mut c = (crc ^ b as u32) & 0xff;
    for _ in 0..8 {
        c = if c & 1 != 0 {
            (c >> 1) ^ 0xEDB8_8320
        } else {
            c >> 1
        };
    }
    (crc >> 8) ^ c
}

/// ZipCrypto-encrypts a 12-byte header (random but for its last byte, the
/// CRC's top byte) and `payload`, written from the PKWARE note rather than
/// the reader's code.
fn zipcrypto(password: &str, crc: u32, payload: &[u8]) -> Vec<u8> {
    let mut keys = [0x1234_5678u32, 0x2345_6789, 0x3456_7890];
    let update = |keys: &mut [u32; 3], b: u8| {
        keys[0] = crc_step(keys[0], b);
        keys[1] = keys[1]
            .wrapping_add(keys[0] & 0xff)
            .wrapping_mul(134_775_813)
            .wrapping_add(1);
        keys[2] = crc_step(keys[2], (keys[1] >> 24) as u8);
    };
    for b in password.bytes() {
        update(&mut keys, b);
    }
    let mut header = [0u8; 12];
    for (i, b) in header.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37).wrapping_add(payload.len() as u8);
    }
    header[11] = (crc >> 24) as u8;
    header
        .iter()
        .chain(payload)
        .map(|&p| {
            let t = keys[2] | 2;
            let c = p ^ (t.wrapping_mul(t ^ 1) >> 8) as u8;
            update(&mut keys, p);
            c
        })
        .collect()
}

/// WinZip AES-256 (AE-2): salt, verifier, the CTR-encrypted payload and a
/// 10-byte authentication code, left zero since the reader doesn't check it.
/// Key derivation and CTR come from the crate: these fixtures test reading
/// through byte ranges, not the cipher.
fn aes256(password: &str, payload: &[u8]) -> Vec<u8> {
    let salt: Vec<u8> = (0..16u8).map(|i| i.wrapping_mul(29) ^ 0x5a).collect();
    let keys = zipview::aes_derive(password.as_bytes(), &salt, 32).expect("derive");
    let mut out = salt;
    out.extend_from_slice(&keys[64..66]);
    out.extend_from_slice(&zipview::decrypt_winzip_ctr(&keys[..32], payload).expect("ctr"));
    out.extend_from_slice(&[0u8; 10]);
    out
}

fn dos_datetime(modified: Option<(u16, u8, u8, u8, u8, u8)>) -> (u16, u16) {
    match modified {
        None => (0, 0),
        Some((y, mo, d, h, mi, s)) => {
            let date = (y.saturating_sub(1980) << 9) | ((mo as u16) << 5) | d as u16;
            let time = ((h as u16) << 11) | ((mi as u16) << 5) | (s as u16 / 2);
            (date, time)
        }
    }
}

/// CRC-32 (IEEE), computed directly so no crc crate is needed.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn deflate(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).expect("deflate write");
    e.finish().expect("deflate finish")
}

/// Builds an archive. `comment` becomes the EOCD comment; names ending in
/// `/` are written as directory entries with an empty payload.
pub fn build(entries: &[Entry<'_>], comment: &str) -> Vec<u8> {
    struct Central {
        name: Vec<u8>,
        extra: Vec<u8>,
        flags: u16,
        method: u16,
        crc: u32,
        comp_len: u32,
        uncomp_len: u32,
        date: u16,
        time: u16,
        offset: u32,
        is_dir: bool,
    }

    let mut out: Vec<u8> = Vec::new();
    let mut centrals: Vec<Central> = Vec::new();

    for e in entries {
        let is_dir = e.name.ends_with('/');
        let body: &[u8] = if is_dir { &[] } else { e.body };
        let compressed = match e.method {
            Method::Stored => body.to_vec(),
            Method::Deflated => deflate(body),
        };
        let (date, time) = dos_datetime(e.modified);
        let plain_crc = crc32(body);
        // Bit 11 declares the name is UTF-8, which it is here; bit 0 marks
        // encryption.
        let (payload, method, flags, crc, extra) = match e.crypt {
            None => (
                compressed,
                e.method.code(),
                0x0800u16,
                plain_crc,
                Vec::new(),
            ),
            Some(Crypt::ZipCrypto(pw)) => (
                zipcrypto(pw, plain_crc, &compressed),
                e.method.code(),
                0x0801,
                plain_crc,
                Vec::new(),
            ),
            Some(Crypt::Aes256(pw)) => {
                // 0x9901: AE-2, vendor "AE", strength 3, then the real method.
                let mut extra = vec![0x01, 0x99, 7, 0, 2, 0, b'A', b'E', 3];
                extra.extend_from_slice(&e.method.code().to_le_bytes());
                (aes256(pw, &compressed), 99, 0x0801, 0, extra)
            }
        };
        let name = e.name.as_bytes().to_vec();
        let offset = out.len() as u32;

        out.extend_from_slice(&LOCAL_HEADER_SIG.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&time.to_le_bytes());
        out.extend_from_slice(&date.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        out.extend_from_slice(&name);
        out.extend_from_slice(&extra);
        out.extend_from_slice(&payload);

        centrals.push(Central {
            name,
            extra,
            flags,
            method,
            crc,
            comp_len: payload.len() as u32,
            uncomp_len: body.len() as u32,
            date,
            time,
            offset,
            is_dir,
        });
    }

    let cd_offset = out.len() as u32;
    for c in &centrals {
        out.extend_from_slice(&CENTRAL_HEADER_SIG.to_le_bytes());
        // Host 3 (UNIX) so unix_mode() is meaningful, matching what the
        // zip crate produced on the platforms these tests ran on.
        out.extend_from_slice(&0x031eu16.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&c.flags.to_le_bytes());
        out.extend_from_slice(&c.method.to_le_bytes());
        out.extend_from_slice(&c.time.to_le_bytes());
        out.extend_from_slice(&c.date.to_le_bytes());
        out.extend_from_slice(&c.crc.to_le_bytes());
        out.extend_from_slice(&c.comp_len.to_le_bytes());
        out.extend_from_slice(&c.uncomp_len.to_le_bytes());
        out.extend_from_slice(&(c.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&(c.extra.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // comment
        out.extend_from_slice(&0u16.to_le_bytes()); // disk
        out.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        let mode: u32 = if c.is_dir { 0o040755 } else { 0o100644 };
        out.extend_from_slice(&(mode << 16).to_le_bytes());
        out.extend_from_slice(&c.offset.to_le_bytes());
        out.extend_from_slice(&c.name);
        out.extend_from_slice(&c.extra);
    }
    let cd_len = out.len() as u32 - cd_offset;

    let comment_bytes = comment.as_bytes();
    out.extend_from_slice(&EOCD_SIG.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // this disk
    out.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
    out.extend_from_slice(&(centrals.len() as u16).to_le_bytes());
    out.extend_from_slice(&(centrals.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_len.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&(comment_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(comment_bytes);
    out
}

/// Rewrites a [`build`] archive with ZIP64 end records: the classic end
/// record's counts, size and offset saturated, and the real values in a ZIP64
/// end record and locator just before it, as writers do past 65,535 entries
/// or 4 GiB.
pub fn zip64(archive: &[u8]) -> Vec<u8> {
    let eocd = (0..=archive.len() - 22)
        .rev()
        .find(|&i| archive[i..i + 4] == EOCD_SIG.to_le_bytes())
        .expect("end record");
    let field = |at: usize, n: usize| {
        archive[eocd + at..eocd + at + n]
            .iter()
            .rev()
            .fold(0u64, |v, &b| v << 8 | b as u64)
    };
    let (entries, cd_size, cd_offset) = (field(10, 2), field(12, 4), field(16, 4));
    let mut out = archive[..eocd].to_vec();
    let record = out.len() as u64;
    out.extend_from_slice(&ZIP64_EOCD_SIG.to_le_bytes());
    out.extend_from_slice(&44u64.to_le_bytes()); // size of the rest
    out.extend_from_slice(&45u16.to_le_bytes()); // made by
    out.extend_from_slice(&45u16.to_le_bytes()); // needed
    out.extend_from_slice(&0u32.to_le_bytes()); // this disk
    out.extend_from_slice(&0u32.to_le_bytes()); // directory's disk
    out.extend_from_slice(&entries.to_le_bytes()); // on this disk
    out.extend_from_slice(&entries.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&ZIP64_LOCATOR_SIG.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // record's disk
    out.extend_from_slice(&record.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes()); // disks
    out.extend_from_slice(&archive[eocd..eocd + 8]); // signature, disks
    out.extend_from_slice(&u16::MAX.to_le_bytes());
    out.extend_from_slice(&u16::MAX.to_le_bytes());
    out.extend_from_slice(&u32::MAX.to_le_bytes());
    out.extend_from_slice(&u32::MAX.to_le_bytes());
    out.extend_from_slice(&archive[eocd + 20..]); // comment length, comment
    out
}

// ---------------------------------------------------------------------------
// Round-trip tests: writer -> reader.
//
// These replace a differential test against the `zip` crate, which proved the
// reader correct before that dependency was dropped but could not be kept
// (it would have kept the advisories in `cargo audit`). The writer here is
// deliberately independent of the reader, duplicating the four signatures
// rather than importing them, so a round-trip cannot pass by sharing a wrong
// constant.
// ---------------------------------------------------------------------------

use zipview::{ZipReadError, ZipReader};

#[test]
fn round_trips_stored_and_deflated() {
    let body = "the quick brown fox ".repeat(500);
    let data = build(
        &[
            Entry::stored("stored.txt", b"hello world"),
            Entry::deflated("deflated.xml", body.as_bytes()),
        ],
        "",
    );
    let r = ZipReader::new(&data).expect("parse");
    assert_eq!(r.len(), 2);
    assert_eq!(r.read_to_string("stored.txt").expect("read"), "hello world");
    assert_eq!(r.read_to_string("deflated.xml").expect("read"), body);
}

#[test]
fn round_trips_an_empty_entry() {
    // A deflate stream for zero bytes is not zero bytes long, which is a
    // classic off-by-one in both directions.
    let data = build(
        &[
            Entry::stored("empty-stored", b""),
            Entry::deflated("empty-deflated", b""),
        ],
        "",
    );
    let r = ZipReader::new(&data).expect("parse");
    assert_eq!(r.read_by_name("empty-stored").expect("read"), b"");
    assert_eq!(r.read_by_name("empty-deflated").expect("read"), b"");
}

#[test]
fn round_trips_unicode_names() {
    let data = build(
        &[
            Entry::deflated("日本語.txt", b"nihongo"),
            Entry::stored("emoji-\u{1F600}.txt", b"grin"),
            Entry::stored("space in name.txt", b"sp"),
        ],
        "",
    );
    let r = ZipReader::new(&data).expect("parse");
    assert_eq!(r.read_to_string("日本語.txt").expect("read"), "nihongo");
    assert!(r.contains("emoji-\u{1F600}.txt"));
    assert!(r.contains("space in name.txt"));
}

#[test]
fn round_trips_timestamps() {
    let data = build(
        &[Entry::deflated("a.txt", b"x").at(2024, 3, 15, 14, 30, 44)],
        "",
    );
    let r = ZipReader::new(&data).expect("parse");
    let dt = r.by_index(0).expect("entry").last_modified().expect("dt");
    assert_eq!(
        (
            dt.year(),
            dt.month(),
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        ),
        (2024, 3, 15, 14, 30, 44)
    );
}

#[test]
fn reads_the_archive_comment() {
    // A comment shifts where the EOCD sits, so the backwards scan has to find
    // it rather than assume the last 22 bytes.
    let data = build(&[Entry::stored("a", b"x")], "a trailing comment");
    let r = ZipReader::new(&data).expect("parse");
    assert_eq!(r.comment(), "a trailing comment");
}

#[test]
fn handles_a_self_extracting_prefix() {
    // The bug a differential test caught: a stub before the first local header
    // shifts every offset the central directory records.
    let inner = build(&[Entry::deflated("a.txt", b"payload")], "");
    let mut data = b"#!/bin/sh\necho stub\nexit 0\n".to_vec();
    data.extend_from_slice(&inner);
    let r = ZipReader::new(&data).expect("parse a prefixed archive");
    assert_eq!(r.len(), 1, "a stub prefix must not hide the entries");
    assert_eq!(r.read_to_string("a.txt").expect("read"), "payload");
}

#[test]
fn directories_are_recognised() {
    let data = build(
        &[
            Entry::deflated("dir/", b""),
            Entry::deflated("dir/f.txt", b"c"),
        ],
        "",
    );
    let r = ZipReader::new(&data).expect("parse");
    assert!(r.by_name("dir/").expect("dir entry").is_dir());
    assert!(!r.by_name("dir/f.txt").expect("file entry").is_dir());
}

#[test]
fn many_entries_round_trip() {
    let bodies: Vec<(String, Vec<u8>)> = (0..200)
        .map(|i| {
            (
                format!("d{}/f{}.xml", i % 7, i),
                format!("<n>{i}</n>").into_bytes(),
            )
        })
        .collect();
    let entries: Vec<Entry<'_>> = bodies.iter().map(|(n, b)| Entry::deflated(n, b)).collect();
    let data = build(&entries, "");
    let r = ZipReader::new(&data).expect("parse");
    assert_eq!(r.len(), 200);
    for (n, b) in &bodies {
        assert_eq!(&r.read_by_name(n).expect("read"), b);
    }
}

#[test]
fn an_unsupported_method_still_enumerates() {
    let mut data = build(&[Entry::stored("a.txt", b"x")], "");
    let cd = data
        .windows(4)
        .position(|w| w == 0x0201_4b50u32.to_le_bytes())
        .expect("central header");
    data[cd + 10..cd + 12].copy_from_slice(&93u16.to_le_bytes()); // Zstd
    let r = ZipReader::new(&data).expect("parse");
    let e = r.by_index(0).expect("entry");
    assert_eq!(e.name(), "a.txt");
    assert_eq!(e.compression_name(), "Zstd");
    assert_eq!(
        r.read_entry(e),
        Err(ZipReadError::UnsupportedCompression(93))
    );
}

// ---------------------------------------------------------------------------
// Reading through byte ranges: `ZipIndex` against `ZipReader`.
//
// The ranged reader follows the in-memory one step by step, so on any input
// the two must agree: the same entries, comment and errors, the same bytes
// or error from every entry, the same password checks.
// ---------------------------------------------------------------------------

use std::cell::RefCell;
use zipview::{PasswordCheck, ZipIndex, ZipIndexOpener};

/// An archive served a range at a time, recording each read. A read past the
/// end panics, failing the test.
struct Source<'a> {
    data: &'a [u8],
    reads: RefCell<Vec<(u64, usize)>>,
}

impl<'a> Source<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            reads: RefCell::new(Vec::new()),
        }
    }

    fn read(&self) -> impl FnMut(u64, &mut [u8]) -> Result<(), ZipReadError> + '_ {
        |offset, buf| {
            self.reads.borrow_mut().push((offset, buf.len()));
            let start = usize::try_from(offset).expect("offset");
            buf.copy_from_slice(&self.data[start..start + buf.len()]);
            Ok(())
        }
    }

    fn read_count(&self) -> usize {
        self.reads.borrow().len()
    }
}

/// Opens `data` both ways and checks they agree, reading every entry with
/// each of `passwords`.
fn assert_same(data: &[u8], passwords: &[Option<&str>]) {
    let source = Source::new(data);
    let ranged = ZipIndex::open(data.len() as u64, source.read());
    match (ZipReader::new(data), ranged) {
        (Err(a), Err(b)) => assert_eq!(a, b, "open errors"),
        (Ok(memory), Ok(index)) => {
            assert_eq!(
                format!("{:?}", memory.entries()),
                format!("{:?}", index.entries())
            );
            assert_eq!(memory.comment(), index.comment());
            for entry in memory.entries() {
                for &password in passwords {
                    assert_eq!(
                        memory.read_entry_with_password(entry, password),
                        index.fetch_entry(entry, password, source.read()),
                        "{} with {password:?}",
                        entry.name()
                    );
                }
                let check: Option<PasswordCheck> = index
                    .fetch_password_check(entry, source.read())
                    .expect("in-memory reads don't fail");
                assert_eq!(memory.password_check(entry), check, "{}", entry.name());
            }
        }
        (memory, ranged) => panic!(
            "in memory {:?}, ranged {:?}",
            memory.map(|r| r.len()),
            ranged.map(|i| i.len())
        ),
    }
}

const PASSWORDS: [Option<&str>; 3] = [None, Some("secret"), Some("wrong")];

fn plain_archive() -> Vec<u8> {
    let text = "the quick brown fox ".repeat(300);
    build(
        &[
            Entry::stored("stored.txt", b"hello world"),
            Entry::deflated("deflated.xml", text.as_bytes()),
            Entry::deflated("dir/", b""),
            Entry::stored("empty", b""),
        ],
        "a comment",
    )
}

fn zipcrypto_archive() -> Vec<u8> {
    let text = "jumps over the lazy dog ".repeat(100);
    build(
        &[
            Entry::stored("zc-stored.txt", b"zipcrypto stored")
                .encrypted(Crypt::ZipCrypto("secret")),
            Entry::deflated("zc-deflated.xml", text.as_bytes())
                .encrypted(Crypt::ZipCrypto("secret")),
            Entry::stored("plain.txt", b"not encrypted"),
        ],
        "",
    )
}

fn aes_archive() -> Vec<u8> {
    let text = "winzip aes payload ".repeat(100);
    build(
        &[
            Entry::stored("aes-stored.txt", b"aes stored").encrypted(Crypt::Aes256("secret")),
            Entry::deflated("aes-deflated.xml", text.as_bytes()).encrypted(Crypt::Aes256("secret")),
        ],
        "",
    )
}

fn prefixed(archive: &[u8]) -> Vec<u8> {
    let mut data = b"#!/bin/sh\necho stub\nexit 0\n".to_vec();
    data.extend_from_slice(archive);
    data
}

#[test]
fn the_writer_encrypts_what_the_reader_decrypts() {
    for data in [zipcrypto_archive(), aes_archive()] {
        let r = ZipReader::new(&data).expect("parse");
        for e in r.entries() {
            let body = r
                .read_entry_with_password(e, Some("secret"))
                .expect("decrypt");
            assert!(!body.is_empty(), "{}", e.name());
            if e.is_encrypted() {
                assert_eq!(
                    r.read_entry_with_password(e, Some("wrong")),
                    Err(ZipReadError::BadPassword)
                );
            }
        }
    }
    let data = zip64(&plain_archive());
    let r = ZipReader::new(&data).expect("parse zip64");
    assert_eq!(r.len(), 4);
    assert_eq!(r.read_to_string("stored.txt").expect("read"), "hello world");
}

#[test]
fn ranged_reads_match_in_memory_on_every_fixture() {
    let plain = plain_archive();
    let zipcrypto = zipcrypto_archive();
    let aes = aes_archive();
    let fixtures = [
        build(&[], ""),
        build(&[Entry::stored("a", b"x")], &"c".repeat(65_000)),
        plain.clone(),
        zip64(&plain),
        prefixed(&plain),
        zip64(&prefixed(&plain)),
        zipcrypto.clone(),
        zip64(&zipcrypto),
        aes.clone(),
        prefixed(&aes),
    ];
    for data in &fixtures {
        assert_same(data, &PASSWORDS);
    }
}

#[test]
fn ranged_reads_match_in_memory_on_every_truncation_and_corruption() {
    let plain = plain_archive();
    for (data, passwords) in [
        (plain.clone(), &[None][..]),
        (zip64(&plain), &[None]),
        (prefixed(&plain), &[None]),
        (zipcrypto_archive(), &[Some("secret")]),
    ] {
        for n in 0..=data.len() {
            assert_same(&data[..n], passwords);
        }
        let mut corrupt = data.clone();
        for i in 0..data.len() {
            for x in [0xff, 0x01] {
                corrupt[i] ^= x;
                assert_same(&corrupt, passwords);
                corrupt[i] ^= x;
            }
        }
    }
}

#[test]
fn opening_takes_one_read_for_a_small_directory_and_two_for_a_big_one() {
    let small = plain_archive();
    let source = Source::new(&small);
    let index = ZipIndex::open(small.len() as u64, source.read()).expect("open");
    assert_eq!(source.read_count(), 1, "the tail holds the whole directory");
    let entry = index.by_name("deflated.xml").expect("entry");
    index.fetch_entry(entry, None, source.read()).expect("read");
    assert_eq!(source.read_count(), 3, "an entry takes two reads");

    // About 200 KB of directory: past the tail read.
    let names: Vec<String> = (0..3000)
        .map(|i| format!("dir{}/file-{i:05}.xml", i % 9))
        .collect();
    let entries: Vec<Entry<'_>> = names
        .iter()
        .map(|n| Entry::stored(n, n.as_bytes()))
        .collect();
    let big = build(&entries, "");
    let source = Source::new(&big);
    let index = ZipIndex::open(big.len() as u64, source.read()).expect("open");
    assert_eq!(source.read_count(), 2);
    assert_eq!(index.len(), 3000);
    assert_same(&big, &[None]);
}

#[test]
fn a_directory_bigger_than_one_read_is_read_in_pieces() {
    // 64,000 entries with 220-byte names: about 17 MB of directory, past
    // one 16 MiB read, and still under 65,535 entries.
    let names: Vec<String> = (0..64_000)
        .map(|i| format!("{}{i:06}", "d/".repeat(107)))
        .collect();
    let entries: Vec<Entry<'_>> = names.iter().map(|n| Entry::stored(n, b"")).collect();
    let data = build(&entries, "");
    let source = Source::new(&data);
    let index = ZipIndex::open(data.len() as u64, source.read()).expect("open");
    assert_eq!(index.len(), 64_000);
    let reads = source.reads.borrow().clone();
    assert!(reads.len() >= 3, "{reads:?}");
    assert!(reads.iter().all(|&(_, n)| n <= 16 << 20), "{reads:?}");
    let memory = ZipReader::new(&data).expect("parse");
    assert_eq!(
        format!("{:?}", memory.entries()),
        format!("{:?}", index.entries())
    );
}

#[test]
fn the_opener_asks_only_for_bytes_it_lacks() {
    let names: Vec<String> = (0..3000).map(|i| format!("f{i:05}")).collect();
    let entries: Vec<Entry<'_>> = names.iter().map(|n| Entry::stored(n, b"x")).collect();
    let data = build(&entries, "");
    let mut opener = ZipIndexOpener::new(data.len() as u64);
    let mut asked: Vec<std::ops::Range<u64>> = Vec::new();
    while let Some(range) = opener.next_read().expect("next read") {
        assert!(range.start < range.end && range.end <= data.len() as u64);
        assert!(!asked.contains(&range), "asked twice for {range:?}");
        let bytes = &data[range.start as usize..range.end as usize];
        opener.supply(range.start, bytes).expect("supply");
        asked.push(range);
    }
    assert_eq!(
        opener.supply(data.len() as u64 - 1, b"ab"),
        Err(ZipReadError::BadOffset)
    );
    assert_eq!(opener.finish().expect("finish").len(), 3000);
}

/// An archive mostly of zeros it never stores: `pieces` are its real bytes
/// at their offsets, and every read is recorded.
struct Sparse {
    len: u64,
    pieces: Vec<(u64, Vec<u8>)>,
    reads: RefCell<Vec<(u64, usize)>>,
}

impl Sparse {
    fn read(&self) -> impl FnMut(u64, &mut [u8]) -> Result<(), ZipReadError> + '_ {
        |offset, buf| {
            assert!(offset + buf.len() as u64 <= self.len, "read past the end");
            self.reads.borrow_mut().push((offset, buf.len()));
            buf.fill(0);
            for (start, piece) in &self.pieces {
                for (i, b) in buf.iter_mut().enumerate() {
                    let at = offset + i as u64;
                    if at >= *start && at < start + piece.len() as u64 {
                        *b = piece[(at - start) as usize];
                    }
                }
            }
            Ok(())
        }
    }

    fn bytes_read(&self) -> usize {
        self.reads.borrow().iter().map(|&(_, n)| n).sum()
    }
}

/// A 50 GiB archive: `big.bin` (50 GiB, stored), then `readme.txt`, then the
/// directory with ZIP64 sizes and offsets. Only the headers are real bytes.
fn fifty_gigabytes() -> Sparse {
    const BIG: u64 = 50 << 30;
    let le16 = |v: u16| v.to_le_bytes();
    let le32 = |v: u32| v.to_le_bytes();
    let le64 = |v: u64| v.to_le_bytes();

    // big.bin's local header, with its sizes in a ZIP64 extra field.
    let mut head = Vec::new();
    head.extend_from_slice(&le32(LOCAL_HEADER_SIG));
    head.extend_from_slice(&le16(45));
    head.extend_from_slice(&le16(0x0800));
    head.extend_from_slice(&le16(0)); // stored
    head.extend_from_slice(&[0; 8]); // time, date, crc
    head.extend_from_slice(&le32(u32::MAX));
    head.extend_from_slice(&le32(u32::MAX));
    head.extend_from_slice(&le16(7));
    head.extend_from_slice(&le16(20));
    head.extend_from_slice(b"big.bin");
    head.extend_from_slice(&le16(1));
    head.extend_from_slice(&le16(16));
    head.extend_from_slice(&le64(BIG));
    head.extend_from_slice(&le64(BIG));

    // readme.txt after the 50 GiB of data, then the directory.
    let readme_at = head.len() as u64 + BIG;
    let body = b"read me";
    let mut tail = Vec::new();
    tail.extend_from_slice(&le32(LOCAL_HEADER_SIG));
    tail.extend_from_slice(&le16(20));
    tail.extend_from_slice(&le16(0x0800));
    tail.extend_from_slice(&le16(0));
    tail.extend_from_slice(&[0; 4]);
    tail.extend_from_slice(&le32(crc32(body)));
    tail.extend_from_slice(&le32(body.len() as u32));
    tail.extend_from_slice(&le32(body.len() as u32));
    tail.extend_from_slice(&le16(10));
    tail.extend_from_slice(&le16(0));
    tail.extend_from_slice(b"readme.txt");
    tail.extend_from_slice(body);

    let cd_at = readme_at + tail.len() as u64;
    let central = |name: &[u8], crc: u32, size: u32, offset: u32, extra: &[u8]| {
        let mut c = Vec::new();
        c.extend_from_slice(&le32(CENTRAL_HEADER_SIG));
        c.extend_from_slice(&le16(0x032d));
        c.extend_from_slice(&le16(45));
        c.extend_from_slice(&le16(0x0800));
        c.extend_from_slice(&le16(0));
        c.extend_from_slice(&[0; 4]);
        c.extend_from_slice(&le32(crc));
        c.extend_from_slice(&le32(size));
        c.extend_from_slice(&le32(size));
        c.extend_from_slice(&le16(name.len() as u16));
        c.extend_from_slice(&le16(extra.len() as u16));
        c.extend_from_slice(&[0; 6]); // comment, disk, internal attributes
        c.extend_from_slice(&le32(0o100644 << 16));
        c.extend_from_slice(&le32(offset));
        c.extend_from_slice(name);
        c.extend_from_slice(extra);
        c
    };
    let mut big_extra = vec![1, 0, 16, 0];
    big_extra.extend_from_slice(&le64(BIG));
    big_extra.extend_from_slice(&le64(BIG));
    let mut readme_extra = vec![1, 0, 8, 0];
    readme_extra.extend_from_slice(&le64(readme_at));
    let mut cd = central(b"big.bin", 0, u32::MAX, 0, &big_extra);
    cd.extend_from_slice(&central(
        b"readme.txt",
        crc32(body),
        body.len() as u32,
        u32::MAX,
        &readme_extra,
    ));
    let record_at = cd_at + cd.len() as u64;
    tail.extend_from_slice(&cd);
    tail.extend_from_slice(&le32(ZIP64_EOCD_SIG));
    tail.extend_from_slice(&le64(44));
    tail.extend_from_slice(&le16(45));
    tail.extend_from_slice(&le16(45));
    tail.extend_from_slice(&[0; 8]);
    tail.extend_from_slice(&le64(2));
    tail.extend_from_slice(&le64(2));
    tail.extend_from_slice(&le64(cd.len() as u64));
    tail.extend_from_slice(&le64(cd_at));
    tail.extend_from_slice(&le32(ZIP64_LOCATOR_SIG));
    tail.extend_from_slice(&le32(0));
    tail.extend_from_slice(&le64(record_at));
    tail.extend_from_slice(&le32(1));
    tail.extend_from_slice(&le32(EOCD_SIG));
    tail.extend_from_slice(&[0; 4]);
    tail.extend_from_slice(&le16(u16::MAX));
    tail.extend_from_slice(&le16(u16::MAX));
    tail.extend_from_slice(&le32(u32::MAX));
    tail.extend_from_slice(&le32(u32::MAX));
    tail.extend_from_slice(&le16(0));

    Sparse {
        len: readme_at + tail.len() as u64,
        pieces: vec![(0, head), (readme_at, tail)],
        reads: RefCell::new(Vec::new()),
    }
}

#[test]
fn a_fifty_gigabyte_archive_opens_with_one_small_read() {
    let archive = fifty_gigabytes();
    let index = ZipIndex::open(archive.len, archive.read()).expect("open");
    assert_eq!(archive.reads.borrow().len(), 1);
    assert!(archive.bytes_read() < 70_000, "{}", archive.bytes_read());

    let big = index.by_name("big.bin").expect("big.bin");
    assert_eq!(big.size(), 50 << 30);
    let readme = index.by_name("readme.txt").expect("readme.txt");
    assert_eq!(
        index
            .fetch_entry(readme, None, archive.read())
            .expect("read"),
        b"read me"
    );
    // Too big to inflate: refused before any read.
    let reads = archive.reads.borrow().len();
    assert_eq!(
        index.fetch_entry(big, None, archive.read()),
        Err(ZipReadError::EntryTooLarge(50 << 30))
    );
    assert_eq!(archive.reads.borrow().len(), reads);
    assert!(archive.bytes_read() < 70_100, "{}", archive.bytes_read());
}

#[test]
fn a_lying_directory_size_is_read_at_most_sixteen_mebibytes_at_a_time() {
    // A 60 GB archive of zeros but for an end record claiming a 4 GiB
    // directory at offset 0, where no central header is.
    let len = 60_000_000_000u64;
    let mut eocd = Vec::new();
    eocd.extend_from_slice(&EOCD_SIG.to_le_bytes());
    eocd.extend_from_slice(&[0; 4]);
    eocd.extend_from_slice(&5u16.to_le_bytes());
    eocd.extend_from_slice(&5u16.to_le_bytes());
    eocd.extend_from_slice(&0xffff_fff0u32.to_le_bytes());
    eocd.extend_from_slice(&0u32.to_le_bytes());
    eocd.extend_from_slice(&0u16.to_le_bytes());
    let archive = Sparse {
        len,
        pieces: vec![(len - eocd.len() as u64, eocd)],
        reads: RefCell::new(Vec::new()),
    };
    let index = ZipIndex::open(len, archive.read()).expect("open");
    assert!(index.is_empty());
    let reads = archive.reads.borrow().clone();
    assert!(reads.len() <= 3, "{reads:?}");
    assert!(reads.iter().all(|&(_, n)| n <= 16 << 20), "{reads:?}");
}
