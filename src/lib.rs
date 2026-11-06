// zipview -- read-only ZIP container reader
// Copyright (C) 2026 zipview contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along
// with this program. If not, see <https://www.gnu.org/licenses/>.

//! Read-only ZIP container reader.
//!
//! Opens an in-memory archive, lists its entries, and inflates the ones you
//! ask for. That is all it does. It **cannot** write an archive, extract to
//! disk, decrypt, or touch the filesystem at all.
//!
//! # Why this exists
//!
//! It was written to replace the `zip` crate in a metadata tool that needed
//! about five percent of what that crate does -- open an archive, find an
//! entry by name, inflate a few small XML members -- and was inheriting its
//! whole dependency tree and advisory surface for the privilege. Removing it
//! dropped 27 crates from the lockfile, including an AES/cipher stack and
//! three `zstd` crates, none of which that tool ever used.
//!
//! Seven RUSTSEC advisories went with them. Three (RUSTSEC-2026-0367/0368/0369)
//! were extraction bugs: SUID/SGID preservation, symlink escape, and
//! permissions applied through symlinks, all in `ZipArchive::extract`. A reader
//! that cannot extract makes that class **inapplicable by construction** rather
//! than patched, which is a stronger property than being up to date. The other
//! four were `zstd` crates pulled in transitively so the dependency could
//! decompress Zstd entries that the tool only ever named in a report.
//!
//! So: use this if you read metadata out of ZIP containers -- OOXML, EPUB,
//! iWork, JAR, APK, ODF. Use [`zip`](https://crates.io/crates/zip) if you need
//! to write archives, extract files, decrypt, or decompress anything beyond
//! Stored and Deflate.
//!
//! # What it does not decompress
//!
//! Only Stored and Deflate. An entry in any other method is still **fully
//! enumerated** -- name, sizes, CRC, timestamp, mode, and method name -- and
//! only reading its bytes fails. That distinction matters: metadata about a
//! Zstd or LZMA entry is still correct and complete.
//!
//! # Hardening
//!
//! Every field is read through bounds-checked helpers, so a truncated or
//! hostile archive yields `Err`, never a panic or an out-of-bounds read.
//! Parsing has no `unsafe`. The only `unsafe` in the crate is in `accel`,
//! which runs the processor's own AES instructions where it has them, checked
//! for at run time, with the portable code as the fallback. Inflation is done
//! by `flate2` on its `zlib-rs` backend, which also uses `unsafe`, for speed.
//!
//! - The central directory is the single source of truth for sizes and
//!   offsets. Local headers are checked only for their signature; their size
//!   fields are ignored, because a streamed entry writes zeros there and
//!   defers the real values to a data descriptor after the payload.
//! - Inflation is capped at the declared uncompressed size, so a zip bomb that
//!   lies about its size produces an error rather than an unbounded
//!   allocation. A stream that inflates to a *different* size than declared is
//!   also an error: a silently short XML document parses into wrong values,
//!   which is worse than no values.
//! - The entry count from the end-of-central-directory record is a hint, not a
//!   promise. It is clamped against what the buffer could actually hold, since
//!   each central directory entry needs at least 46 bytes.
//! - Self-extracting archives are handled. A stub before the first local
//!   header shifts every offset the central directory records, and the shift
//!   is derived rather than assumed. Getting this wrong reads zero entries
//!   *silently*, which is how it was caught -- by differential testing against
//!   the `zip` crate, not by any amount of reading the code.
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), zipview::ZipReadError> {
//! # let bytes: &[u8] = &zipview_doctest_fixture();
//! let archive = zipview::ZipReader::new(bytes)?;
//!
//! for entry in archive.entries() {
//!     println!("{} ({} bytes, {})", entry.name(), entry.size(), entry.compression_name());
//! }
//!
//! if archive.contains("docProps/core.xml") {
//!     let xml = archive.read_to_string("docProps/core.xml")?;
//!     assert!(!xml.is_empty());
//! }
//! # Ok(())
//! # }
//! # fn zipview_doctest_fixture() -> Vec<u8> {
//! #     // A valid empty archive: the 22-byte end-of-central-directory
//! #     // record and nothing else.
//! #     let mut v = vec![0x50, 0x4b, 0x05, 0x06];
//! #     v.extend_from_slice(&[0u8; 18]);
//! #     v
//! # }
//! ```
//!
//! # Testing
//!
//! Fixtures are built byte by byte by `tests/writer.rs`, so the test suite has
//! no dependencies either. Beyond the usual cases the suite sweeps **every
//! truncation** of a valid archive and **flips every single byte**, asserting
//! only that nothing panics. `fuzz/fuzz_targets/fuzz_zip.rs` continues that
//! past what enumeration can reach: it both lists and *reads* every entry,
//! because a reader that parsed headers safely but trusted the payload offset
//! would pass an enumeration-only target.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs, clippy::undocumented_unsafe_blocks)]

mod accel;

use std::borrow::Cow;

/// Local file header signature, `PK\x03\x04`.
const LOCAL_HEADER_SIG: u32 = 0x0403_4b50;
/// Central directory file header signature, `PK\x01\x02`.
const CENTRAL_HEADER_SIG: u32 = 0x0201_4b50;
/// End of central directory signature, `PK\x05\x06`.
const EOCD_SIG: u32 = 0x0605_4b50;
/// ZIP64 end of central directory record signature, `PK\x06\x06`.
const ZIP64_EOCD_SIG: u32 = 0x0606_4b50;
/// ZIP64 end of central directory locator signature, `PK\x06\x07`.
const ZIP64_LOCATOR_SIG: u32 = 0x0706_4b50;

/// Fixed size of a central directory file header, before the variable-length
/// name, extra and comment fields.
const CENTRAL_HEADER_LEN: usize = 46;
/// Fixed size of a local file header, before name and extra.
const LOCAL_HEADER_LEN: usize = 30;
/// Fixed size of an end-of-central-directory record, before its comment.
const EOCD_LEN: usize = 22;

/// The EOCD comment field is a `u16` length, so the record can start at most
/// this far from the end of the file.
const MAX_EOCD_SEARCH: usize = EOCD_LEN + u16::MAX as usize;

/// Ceiling on a single entry's inflated size, independent of what the archive
/// claims. Callers here read small XML and plist members; anything larger is not
/// metadata and is not worth the allocation. A caller that hits this gets an
/// error rather than a truncated value, because a silently short XML document
/// would parse into wrong tags, which is worse than no tags at all.
const MAX_INFLATED_SIZE: u64 = 256 * 1024 * 1024;

/// Why an archive could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZipReadError {
    /// No end-of-central-directory record was found.
    NotAZip,
    /// A structure extended past the end of the buffer.
    Truncated,
    /// A signature was not what the format requires at that offset.
    BadSignature,
    /// An offset or length in the archive does not address the buffer.
    BadOffset,
    /// No entry with the requested name exists.
    EntryNotFound,
    /// The entry's compression method has no decompressor here.
    UnsupportedCompression(u16),
    /// Decompression failed, or produced a different size than declared.
    DecompressionFailed,
    /// The entry's declared size exceeds [`MAX_INFLATED_SIZE`].
    EntryTooLarge(u64),
    /// The entry is encrypted and no password was provided.
    Encrypted,
    /// The provided password was rejected by the entry's password verifier.
    BadPassword,
}

impl std::fmt::Display for ZipReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAZip => write!(f, "no ZIP end-of-central-directory record found"),
            Self::Truncated => write!(f, "ZIP structure extends past end of data"),
            Self::BadSignature => write!(f, "bad ZIP signature"),
            Self::BadOffset => write!(f, "ZIP offset does not address the archive"),
            Self::EntryNotFound => write!(f, "entry not found in archive"),
            Self::UnsupportedCompression(m) => {
                write!(f, "unsupported ZIP compression method {m}")
            }
            Self::DecompressionFailed => write!(f, "ZIP entry decompression failed"),
            Self::EntryTooLarge(n) => write!(f, "ZIP entry declares {n} bytes, over the limit"),
            Self::Encrypted => write!(f, "ZIP entry is encrypted"),
            Self::BadPassword => write!(f, "ZIP entry password is incorrect"),
        }
    }
}

impl std::error::Error for ZipReadError {}

type Result<T> = std::result::Result<T, ZipReadError>;

/// A DOS date/time, as stored in a ZIP header.
///
/// Kept as the raw packed fields rather than converted to a calendar type: the
/// values are frequently nonsense in real archives (zero, or a month of 0) and
/// callers render them as-is. Interpreting them further would invent data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DosDateTime {
    date: u16,
    time: u16,
}

impl DosDateTime {
    /// Returns `None` when both fields are zero, which is how archivers mark
    /// "no timestamp" -- distinct from a real timestamp that happens to be
    /// 1980-00-00, which this still reports.
    fn from_parts(date: u16, time: u16) -> Option<Self> {
        if date == 0 && time == 0 {
            None
        } else {
            Some(Self { date, time })
        }
    }

    /// Calendar year, 1980 plus the stored offset.
    pub fn year(&self) -> u16 {
        1980 + (self.date >> 9)
    }
    /// Month, 1-12 in a well-formed archive. Real archives store 0.
    pub fn month(&self) -> u8 {
        ((self.date >> 5) & 0x0f) as u8
    }
    /// Day of month, 1-31 in a well-formed archive. Real archives store 0.
    pub fn day(&self) -> u8 {
        (self.date & 0x1f) as u8
    }
    /// Hour, 0-23.
    pub fn hour(&self) -> u8 {
        (self.time >> 11) as u8
    }
    /// Minute, 0-59.
    pub fn minute(&self) -> u8 {
        ((self.time >> 5) & 0x3f) as u8
    }
    /// DOS stores seconds in two-second units, so odd seconds are not
    /// representable and this is always even.
    pub fn second(&self) -> u8 {
        ((self.time & 0x1f) * 2) as u8
    }
}

/// One entry, as described by its central directory header.
#[derive(Debug, Clone)]
pub struct ZipEntry {
    name: String,
    compression: u16,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    local_header_offset: u64,
    external_attributes: u32,
    version_made_by: u16,
    flags: u16,
    last_modified: Option<DosDateTime>,
    aes_info: Option<(u8, u16)>,
}

impl ZipEntry {
    /// The entry's path within the archive, as recorded.
    ///
    /// Never treat this as a filesystem path: it may be absolute, contain
    /// `..`, or be an arbitrary byte string. This crate only ever compares it.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Raw compression method code, e.g. 0 Stored, 8 Deflate, 93 Zstd, 99 AES.
    pub fn compression(&self) -> u16 {
        self.compression
    }
    /// Raw general-purpose bit flags from the header.
    pub fn flags(&self) -> u16 {
        self.flags
    }
    /// Local header offset as stored in the central directory.
    pub fn local_header_offset(&self) -> u64 {
        self.local_header_offset
    }
    /// WinZip AES extra field (`0x9901`) parameters `(strength, actual_method)`, if present.
    pub fn aes_info(&self) -> Option<(u8, u16)> {
        self.aes_info
    }
    /// Underlying compression method after unwrapping WinZip AES (method 99), if applicable.
    pub fn effective_compression(&self) -> u16 {
        match (self.compression, self.aes_info) {
            (99, Some((_, actual))) => actual,
            (m, _) => m,
        }
    }
    /// CRC-32 of the uncompressed data, as declared. Not verified on read.
    pub fn crc32(&self) -> u32 {
        self.crc32
    }
    /// Size of the stored payload, in bytes.
    pub fn compressed_size(&self) -> u64 {
        self.compressed_size
    }
    /// Uncompressed size, named `size` to match the call sites this replaced.
    pub fn size(&self) -> u64 {
        self.uncompressed_size
    }
    /// The DOS timestamp, or `None` when the entry records none.
    pub fn last_modified(&self) -> Option<DosDateTime> {
        self.last_modified
    }

    /// `(host system, zip specification version)`, as the central directory
    /// packs them into one `u16`.
    pub fn version_made_by(&self) -> (u8, u8) {
        (
            (self.version_made_by >> 8) as u8,
            (self.version_made_by & 0xff) as u8,
        )
    }

    /// Unix permission bits, present only when the archive was made on a Unix
    /// host. The high 16 bits of the external attributes carry `st_mode`.
    pub fn unix_mode(&self) -> Option<u32> {
        // Host 3 is UNIX; 19 is OS X. Other hosts put DOS attributes here, and
        // reporting those as a Unix mode would be a plausible wrong value.
        match self.version_made_by >> 8 {
            3 | 19 => Some(self.external_attributes >> 16),
            _ => None,
        }
    }

    /// True when general purpose encryption flags are set or compression method is 99 (WinZip AES).
    pub fn is_encrypted(&self) -> bool {
        self.flags & (0x0001 | 0x0040 | 0x2000) != 0 || self.compression == 99
    }

    /// Directory entries are conventionally marked by a trailing separator.
    pub fn is_dir(&self) -> bool {
        self.name.ends_with('/') || self.name.ends_with('\\')
    }

    /// Human-readable compression method, covering the methods APPNOTE assigns
    /// even where this reader cannot decompress them -- the name is a tag value
    /// and is reported regardless.
    pub fn compression_name(&self) -> &'static str {
        match self.compression {
            0 => "Stored",
            1 => "Shrunk",
            6 => "Imploded",
            8 => "Deflate",
            9 => "Deflate64",
            12 => "Bzip2",
            14 => "LZMA",
            93 => "Zstd",
            95 => "XZ",
            96 => "Jpeg",
            97 => "WavPack",
            98 => "PPMd",
            99 => "AES",
            _ => "Unknown",
        }
    }
}

/// A parsed, read-only view over an in-memory ZIP archive.
#[derive(Debug, Clone)]
pub struct ZipReader<'a> {
    data: &'a [u8],
    entries: Vec<ZipEntry>,
    comment: Vec<u8>,
    /// Bytes of non-ZIP prefix (a self-extracting stub) that every offset in
    /// the central directory is implicitly relative to. Zero for ordinary
    /// archives. See `locate_central_directory`.
    offset_shift: u64,
}

/// Reads a little-endian `u16` at `off`, or `Truncated`.
fn u16_at(data: &[u8], off: usize) -> Result<u16> {
    data.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or(ZipReadError::Truncated)
}

/// Reads a little-endian `u32` at `off`, or `Truncated`.
fn u32_at(data: &[u8], off: usize) -> Result<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or(ZipReadError::Truncated)
}

/// Reads a little-endian `u64` at `off`, or `Truncated`.
fn u64_at(data: &[u8], off: usize) -> Result<u64> {
    data.get(off..off + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
        .ok_or(ZipReadError::Truncated)
}

/// Converts a `u64` from the archive into a buffer index, rejecting anything
/// that cannot address `data`. This is the only place archive-supplied offsets
/// become indices, so every such conversion is checked.
fn offset_to_index(value: u64, data: &[u8]) -> Result<usize> {
    let idx = usize::try_from(value).map_err(|_| ZipReadError::BadOffset)?;
    if idx > data.len() {
        return Err(ZipReadError::BadOffset);
    }
    Ok(idx)
}

impl<'a> ZipReader<'a> {
    /// Parses the central directory of `data`.
    ///
    /// Reads no entry payloads, so the cost is proportional to the number of
    /// entries rather than the size of the archive.
    pub fn new(data: &'a [u8]) -> Result<Self> {
        let eocd = Self::find_eocd(data).ok_or(ZipReadError::NotAZip)?;

        let mut entry_count = u16_at(data, eocd + 10)? as u64;
        let mut cd_size = u32_at(data, eocd + 12)? as u64;
        let mut cd_offset = u32_at(data, eocd + 16)? as u64;

        let comment_len = u16_at(data, eocd + 20)? as usize;
        let comment_start = eocd + EOCD_LEN;
        // A comment length longer than the remaining bytes is a malformed
        // archive rather than a fatal one: take what is actually there.
        let comment_end = comment_start.saturating_add(comment_len).min(data.len());
        let comment = data
            .get(comment_start..comment_end)
            .unwrap_or_default()
            .to_vec();

        // ZIP64 only when the 32-bit fields are saturated, which is the signal
        // the format uses. Looking for the ZIP64 records unconditionally would
        // misread a plain archive whose bytes happen to contain the signature.
        if entry_count == u16::MAX as u64
            || cd_offset == u32::MAX as u64
            || cd_size == u32::MAX as u64
        {
            if let Some((z64_entries, z64_size, z64_offset)) = Self::read_zip64(data, eocd) {
                entry_count = z64_entries;
                cd_size = z64_size;
                cd_offset = z64_offset;
            }
        }

        // A self-extracting archive carries an executable stub before the first
        // local header, so every offset the central directory records is
        // relative to where the ZIP data starts rather than to the file. The
        // declared offset then points into the stub.
        //
        // The central directory always ends at the EOCD, so `eocd - cd_size`
        // is its true position; the difference from the declared offset is the
        // prefix length, and the same shift applies to every local header
        // offset. Trusting the declared offset instead reads zero entries,
        // which is how this was caught -- by the differential test against the
        // `zip` crate, on a stub-prefixed archive.
        let (cd_start, offset_shift) =
            Self::locate_central_directory(data, eocd, cd_size, cd_offset)?;

        let mut cursor = cd_start;

        // The declared count is a hint. Each central directory header occupies
        // at least CENTRAL_HEADER_LEN bytes, so an archive claiming more
        // entries than could fit is lying and would otherwise have us
        // preallocate on its word.
        let max_possible = data.len().saturating_sub(cursor) / CENTRAL_HEADER_LEN;
        let capacity = (entry_count as usize).min(max_possible);
        let mut entries = Vec::with_capacity(capacity);

        for _ in 0..entry_count {
            if u32_at(data, cursor)? != CENTRAL_HEADER_SIG {
                // A short central directory is common in damaged archives.
                // Stop and keep what parsed rather than discarding all of it;
                // the entries already read are individually well-formed.
                break;
            }
            let (entry, next) = Self::parse_central_entry(data, cursor)?;
            entries.push(entry);
            cursor = next;
        }

        Ok(Self {
            data,
            entries,
            comment,
            offset_shift,
        })
    }

    /// Scans backwards for the end-of-central-directory signature.
    ///
    /// Backwards because the record sits at the end, and an archive may carry a
    /// self-extracting stub or trailing junk; the *last* valid-looking record
    /// is the operative one.
    fn find_eocd(data: &[u8]) -> Option<usize> {
        if data.len() < EOCD_LEN {
            return None;
        }
        let search_start = data.len().saturating_sub(MAX_EOCD_SEARCH);
        let last_possible = data.len() - EOCD_LEN;
        for off in (search_start..=last_possible).rev() {
            if u32_at(data, off).ok()? == EOCD_SIG {
                return Some(off);
            }
        }
        None
    }

    /// Follows the ZIP64 locator that precedes the EOCD to the ZIP64 EOCD
    /// record. Returns `None` on any inconsistency, leaving the 32-bit values
    /// in force, since a partially-understood ZIP64 archive should degrade to
    /// what the classic record says rather than guess.
    fn read_zip64(data: &[u8], eocd: usize) -> Option<(u64, u64, u64)> {
        // The locator is a fixed 20 bytes immediately before the EOCD.
        let locator = eocd.checked_sub(20)?;
        if u32_at(data, locator).ok()? != ZIP64_LOCATOR_SIG {
            return None;
        }
        let z64_eocd = offset_to_index(u64_at(data, locator + 8).ok()?, data).ok()?;
        if u32_at(data, z64_eocd).ok()? != ZIP64_EOCD_SIG {
            return None;
        }
        let entries = u64_at(data, z64_eocd + 32).ok()?;
        let cd_size = u64_at(data, z64_eocd + 40).ok()?;
        let cd_offset = u64_at(data, z64_eocd + 48).ok()?;
        Some((entries, cd_size, cd_offset))
    }

    /// Resolves where the central directory really begins, and by how much
    /// the archive's internal offsets are shifted.
    ///
    /// Returns `(index of first central header, shift)`. The shift is added to
    /// each entry's local header offset when reading its payload.
    ///
    /// Order matters: the declared offset is tried first, so an ordinary
    /// archive is unaffected and cannot be mis-shifted by a coincidence. Only
    /// when that does not hold a central header is the `eocd - cd_size`
    /// position consulted.
    fn locate_central_directory(
        data: &[u8],
        eocd: usize,
        cd_size: u64,
        cd_offset: u64,
    ) -> Result<(usize, u64)> {
        // Ordinary archive: the declared offset addresses a central header.
        if let Ok(idx) = offset_to_index(cd_offset, data) {
            if u32_at(data, idx) == Ok(CENTRAL_HEADER_SIG) {
                return Ok((idx, 0));
            }
        }

        // Prefixed archive: the directory ends at the EOCD, so back up by its
        // size. The shift is how far the real position is past the declared.
        let computed = (eocd as u64).checked_sub(cd_size);
        if let Some(computed) = computed {
            if let Ok(idx) = offset_to_index(computed, data) {
                if u32_at(data, idx) == Ok(CENTRAL_HEADER_SIG) {
                    let shift = computed.saturating_sub(cd_offset);
                    return Ok((idx, shift));
                }
            }
        }

        // Neither position holds a central header. An archive with zero
        // entries legitimately has no central header at all, so accept the
        // declared offset and let the (empty) entry loop confirm it.
        Ok((offset_to_index(cd_offset, data)?, 0))
    }

    /// Parses one central directory header at `off`, returning it and the
    /// offset of the next header.
    fn parse_central_entry(data: &[u8], off: usize) -> Result<(ZipEntry, usize)> {
        let version_made_by = u16_at(data, off + 4)?;
        let flags = u16_at(data, off + 8)?;
        let compression = u16_at(data, off + 10)?;
        let mod_time = u16_at(data, off + 12)?;
        let mod_date = u16_at(data, off + 14)?;
        let crc32 = u32_at(data, off + 16)?;
        let mut compressed_size = u32_at(data, off + 20)? as u64;
        let mut uncompressed_size = u32_at(data, off + 24)? as u64;
        let name_len = u16_at(data, off + 28)? as usize;
        let extra_len = u16_at(data, off + 30)? as usize;
        let comment_len = u16_at(data, off + 32)? as usize;
        let external_attributes = u32_at(data, off + 38)?;
        let mut local_header_offset = u32_at(data, off + 42)? as u64;

        let name_start = off + CENTRAL_HEADER_LEN;
        let name_bytes = data
            .get(name_start..name_start + name_len)
            .ok_or(ZipReadError::Truncated)?;

        // Flag bit 11 promises UTF-8. Without it the name is officially CP437,
        // but in practice it is usually UTF-8 anyway, so decode as UTF-8 and
        // fall back to lossy rather than mis-transcoding. Entry names are used
        // for lookup and reporting, never as filesystem paths.
        let name = match std::str::from_utf8(name_bytes) {
            Ok(s) => s.to_string(),
            Err(_) => String::from_utf8_lossy(name_bytes).into_owned(),
        };

        let extra_start = name_start + name_len;
        let extra = data
            .get(extra_start..extra_start + extra_len)
            .ok_or(ZipReadError::Truncated)?;

        // ZIP64 extended information (header id 0x0001) replaces whichever
        // 32-bit fields are saturated, in a fixed order, each present only if
        // its 32-bit counterpart was 0xFFFFFFFF.
        if compressed_size == u32::MAX as u64
            || uncompressed_size == u32::MAX as u64
            || local_header_offset == u32::MAX as u64
        {
            if let Some(z64) = find_extra_field(extra, 0x0001) {
                let mut p = 0usize;
                if uncompressed_size == u32::MAX as u64 {
                    if let Ok(v) = u64_at(z64, p) {
                        uncompressed_size = v;
                        p += 8;
                    }
                }
                if compressed_size == u32::MAX as u64 {
                    if let Ok(v) = u64_at(z64, p) {
                        compressed_size = v;
                        p += 8;
                    }
                }
                if local_header_offset == u32::MAX as u64 {
                    if let Ok(v) = u64_at(z64, p) {
                        local_header_offset = v;
                    }
                }
            }
        }

        let aes_info = aes_extra(extra);

        let next = extra_start
            .checked_add(extra_len)
            .and_then(|v| v.checked_add(comment_len))
            .ok_or(ZipReadError::Truncated)?;

        Ok((
            ZipEntry {
                name,
                compression,
                crc32,
                compressed_size,
                uncompressed_size,
                local_header_offset,
                external_attributes,
                version_made_by,
                flags,
                last_modified: DosDateTime::from_parts(mod_date, mod_time),
                aes_info,
            },
            next,
        ))
    }

    /// Number of entries parsed. May be fewer than the archive declared when
    /// its central directory is damaged.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no entries parsed.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The archive comment, lossily decoded. Comments are free text with no
    /// declared encoding.
    pub fn comment(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.comment)
    }

    /// All parsed entries, in central-directory order.
    pub fn entries(&self) -> &[ZipEntry] {
        &self.entries
    }

    /// The entry at `index` in central-directory order.
    pub fn by_index(&self, index: usize) -> Option<&ZipEntry> {
        self.entries.get(index)
    }

    /// The first entry whose name matches exactly.
    ///
    /// Exact comparison, not path resolution: ZIP permits duplicate names,
    /// and resolving them would be a guess.
    pub fn by_name(&self, name: &str) -> Option<&ZipEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Whether an entry with this exact name exists.
    pub fn contains(&self, name: &str) -> bool {
        self.by_name(name).is_some()
    }

    /// Decompresses the entry named `name`.
    pub fn read_by_name(&self, name: &str) -> Result<Vec<u8>> {
        let entry = self.by_name(name).ok_or(ZipReadError::EntryNotFound)?;
        self.read_entry(entry)
    }

    /// Decompresses the entry named `name`, decrypting with `password` when encrypted.
    pub fn read_by_name_with_password(
        &self,
        name: &str,
        password: Option<&str>,
    ) -> Result<Vec<u8>> {
        let entry = self.by_name(name).ok_or(ZipReadError::EntryNotFound)?;
        self.read_entry_with_password(entry, password)
    }

    /// Decompresses `name` and decodes it as UTF-8, lossily.
    ///
    /// Lossy because the alternative is failing a whole document over one bad
    /// byte in an XML comment, and these inputs are metadata parts whose
    /// encoding declarations are not always honest.
    pub fn read_to_string(&self, name: &str) -> Result<String> {
        Ok(String::from_utf8_lossy(&self.read_by_name(name)?).into_owned())
    }

    /// Decompresses `name` (decrypting with `password` if encrypted) and decodes it as UTF-8, lossily.
    pub fn read_to_string_with_password(
        &self,
        name: &str,
        password: Option<&str>,
    ) -> Result<String> {
        Ok(String::from_utf8_lossy(&self.read_by_name_with_password(name, password)?).into_owned())
    }

    /// Extracts the [`PasswordCheck`] for `entry` from its local header and payload prefix, if encrypted.
    pub fn password_check(&self, entry: &ZipEntry) -> Option<PasswordCheck> {
        if !entry.is_encrypted() {
            return None;
        }
        let local = offset_to_index(
            entry.local_header_offset.saturating_add(self.offset_shift),
            self.data,
        )
        .ok()?;
        if u32_at(self.data, local).ok()? != LOCAL_HEADER_SIG {
            return None;
        }
        let local_name_len = u16_at(self.data, local + 26).ok()? as usize;
        let local_extra_len = u16_at(self.data, local + 28).ok()? as usize;
        let extra_start = local
            .checked_add(LOCAL_HEADER_LEN)?
            .checked_add(local_name_len)?;
        let data_start = extra_start.checked_add(local_extra_len)?;
        let local_extra = self.data.get(extra_start..data_start)?;
        let entry_slice = self.data.get(local..)?;
        password_check_at(
            entry_slice,
            usize::from(entry.flags),
            usize::from(entry.compression),
            local_extra,
            data_start - local,
        )
    }

    /// Decompresses one entry's payload.
    ///
    /// Sizes come from the central directory, never the local header: a
    /// streamed entry stores zeros there and writes the real values to a data
    /// descriptor after the payload.
    pub fn read_entry(&self, entry: &ZipEntry) -> Result<Vec<u8>> {
        self.read_entry_with_password(entry, None)
    }

    /// Decompresses one entry's payload, decrypting with `password` when encrypted.
    pub fn read_entry_with_password(
        &self,
        entry: &ZipEntry,
        password: Option<&str>,
    ) -> Result<Vec<u8>> {
        if entry.uncompressed_size > MAX_INFLATED_SIZE {
            return Err(ZipReadError::EntryTooLarge(entry.uncompressed_size));
        }

        let local = offset_to_index(
            entry.local_header_offset.saturating_add(self.offset_shift),
            self.data,
        )?;
        if u32_at(self.data, local)? != LOCAL_HEADER_SIG {
            return Err(ZipReadError::BadSignature);
        }
        // Only the variable-length counts are taken from the local header; the
        // payload begins after them.
        let local_name_len = u16_at(self.data, local + 26)? as usize;
        let local_extra_len = u16_at(self.data, local + 28)? as usize;

        let extra_start = local
            .checked_add(LOCAL_HEADER_LEN)
            .and_then(|v| v.checked_add(local_name_len))
            .ok_or(ZipReadError::BadOffset)?;
        let data_start = extra_start
            .checked_add(local_extra_len)
            .ok_or(ZipReadError::BadOffset)?;
        let local_extra = self
            .data
            .get(extra_start..data_start)
            .ok_or(ZipReadError::Truncated)?;

        let compressed_len =
            usize::try_from(entry.compressed_size).map_err(|_| ZipReadError::BadOffset)?;
        let data_end = data_start
            .checked_add(compressed_len)
            .ok_or(ZipReadError::BadOffset)?;
        let payload = self
            .data
            .get(data_start..data_end)
            .ok_or(ZipReadError::Truncated)?;

        let (decrypted_buf, method);
        let payload_bytes: &[u8] = if entry.is_encrypted() {
            let pw = password
                .filter(|s| !s.is_empty())
                .ok_or(ZipReadError::Encrypted)?;
            if entry.compression == 99 {
                let (strength, actual_method) = entry
                    .aes_info
                    .or_else(|| aes_extra(local_extra))
                    .ok_or(ZipReadError::UnsupportedCompression(99))?;
                decrypted_buf =
                    decrypt_winzip_aes(pw, strength, payload, Some(entry.compressed_size))
                        .ok_or(ZipReadError::BadPassword)?;
                method = actual_method;
            } else {
                let check = if entry.flags & 0x0008 != 0 {
                    *self.data.get(local + 11).ok_or(ZipReadError::Truncated)?
                } else {
                    (entry.crc32 >> 24) as u8
                };
                decrypted_buf =
                    decrypt_zipcrypto(pw, check, payload).ok_or(ZipReadError::BadPassword)?;
                method = entry.compression;
            }
            &decrypted_buf
        } else {
            method = entry.compression;
            payload
        };

        match method {
            0 => {
                if payload_bytes.len() as u64 != entry.uncompressed_size {
                    return Err(ZipReadError::DecompressionFailed);
                }
                Ok(payload_bytes.to_vec())
            }
            8 => inflate(payload_bytes, entry.uncompressed_size),
            other => Err(ZipReadError::UnsupportedCompression(other)),
        }
    }
}

/// What a ZIP keeps at the start of an encrypted file's data to test a password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordCheck {
    /// 12-byte ZipCrypto encryption header whose decrypted 12th byte must equal `check`.
    Crypto {
        /// The 12-byte encryption header preceding the compressed stream.
        header: [u8; 12],
        /// Expected 12th byte after decryption (high byte of CRC-32 or DOS mod time).
        check: u8,
    },
    /// WinZip AES (`0x9901`): `salt` is `strength * 4 + 4` bytes, followed by a 2-byte PBKDF2 verifier.
    Aes {
        /// Key strength: 1 (AES-128), 2 (AES-192), or 3 (AES-256).
        strength: u8,
        /// Up to 16 bytes of salt (`8`, `12`, or `16` bytes used according to `strength`).
        salt: [u8; 16],
        /// 2-byte password verification value from PBKDF2-HMAC-SHA1.
        verifier: [u8; 2],
    },
}

impl PasswordCheck {
    /// Serializes this password check to a compact byte representation.
    pub fn to_bytes(self) -> Vec<u8> {
        match self {
            Self::Crypto { header, check } => {
                let mut out = vec![0, check];
                out.extend_from_slice(&header);
                out
            }
            Self::Aes {
                strength,
                salt,
                verifier,
            } => {
                let mut out = vec![strength];
                out.extend_from_slice(&salt);
                out.extend_from_slice(&verifier);
                out
            }
        }
    }

    /// Deserializes a [`PasswordCheck`] produced by [`Self::to_bytes`].
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        match *b.first()? {
            0 => Some(Self::Crypto {
                check: *b.get(1)?,
                header: b.get(2..14)?.try_into().ok()?,
            }),
            strength if (1..=3).contains(&strength) => Some(Self::Aes {
                strength,
                salt: b.get(1..17)?.try_into().ok()?,
                verifier: b.get(17..19)?.try_into().ok()?,
            }),
            _ => None,
        }
    }

    /// True if `password` satisfies the encryption header check.
    pub fn accepts(&self, password: &str) -> bool {
        match self {
            Self::Crypto { header, check } => crypto_check(password.as_bytes(), header) == *check,
            Self::Aes {
                strength,
                salt,
                verifier,
            } => {
                let salt_len = usize::from(*strength) * 4 + 4;
                let key_len = (usize::from(*strength) + 1) * 8;
                salt.get(..salt_len)
                    .and_then(|s| aes_verifier(password.as_bytes(), s, key_len))
                    .is_some_and(|found| found == *verifier)
            }
        }
    }

    /// True when the check is at least 16 bits wide (WinZip AES) rather than ZipCrypto's 1-in-256 byte check.
    pub fn certain(&self) -> bool {
        matches!(self, Self::Aes { .. })
    }
}

/// Parses the ZIP64 extended information extra field (`0x0001`) for saturated 32-bit sizes.
/// Returns `(uncompressed_size, compressed_size)`.
pub fn zip64_sizes(extra: &[u8], uncompressed: u32, compressed: u32) -> (u64, u64) {
    let (mut unp, mut packed) = (u64::from(uncompressed), u64::from(compressed));
    if let Some(z64) = find_extra_field(extra, 0x0001) {
        let mut at = 0usize;
        if uncompressed == u32::MAX {
            if let Ok(v) = u64_at(z64, at) {
                unp = v;
            }
            at += 8;
        }
        if compressed == u32::MAX {
            if let Ok(v) = u64_at(z64, at) {
                packed = v;
            }
        }
    }
    (unp, packed)
}

/// Parses WinZip AES extra field `0x9901`, returning `(strength, actual_method)`.
pub fn aes_extra(extra: &[u8]) -> Option<(u8, u16)> {
    let body = find_extra_field(extra, 0x9901)?;
    if body.len() < 7 {
        return None;
    }
    let strength = body.get(4).copied().filter(|s| (1..=3).contains(s))?;
    let method = u16::from_le_bytes([*body.get(5)?, *body.get(6)?]);
    Some((strength, method))
}

/// Extracts a [`PasswordCheck`] from a local entry slice starting at its `PK\x03\x04` signature.
pub fn password_check_at(
    entry: &[u8],
    flags: usize,
    method: usize,
    extra: &[u8],
    data_at: usize,
) -> Option<PasswordCheck> {
    let data = entry.get(data_at..)?;
    if method == 99 {
        let (strength, _) = aes_extra(extra)?;
        let salt_len = usize::from(strength) * 4 + 4;
        let mut salt = [0u8; 16];
        salt.get_mut(..salt_len)?
            .copy_from_slice(data.get(..salt_len)?);
        Some(PasswordCheck::Aes {
            strength,
            salt,
            verifier: data.get(salt_len..salt_len + 2)?.try_into().ok()?,
        })
    } else {
        let check = if flags & 0x0008 != 0 {
            *entry.get(11)?
        } else {
            *entry.get(17)?
        };
        Some(PasswordCheck::Crypto {
            header: data.get(..12)?.try_into().ok()?,
            check,
        })
    }
}

fn crypto_check(password: &[u8], header: &[u8; 12]) -> u8 {
    let mut keys = crypto_keys(password);
    let mut last = 0;
    for cipher in header {
        last = crypto_step(&mut keys, *cipher);
    }
    last
}

fn crypto_keys(password: &[u8]) -> [u32; 3] {
    let mut keys = [0x1234_5678u32, 0x2345_6789, 0x3456_7890];
    for b in password {
        crypto_update(&mut keys, *b);
    }
    keys
}

fn crypto_update(keys: &mut [u32; 3], b: u8) {
    fn crc_byte(crc: u32, b: u8) -> u32 {
        let mut c = (crc ^ u32::from(b)) & 0xff;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xedb8_8320
            } else {
                c >> 1
            };
        }
        (crc >> 8) ^ c
    }
    keys[0] = crc_byte(keys[0], b);
    keys[1] = keys[1]
        .wrapping_add(keys[0] & 0xff)
        .wrapping_mul(134_775_813)
        .wrapping_add(1);
    keys[2] = crc_byte(keys[2], (keys[1] >> 24) as u8);
}

fn crypto_step(keys: &mut [u32; 3], cipher: u8) -> u8 {
    let t = keys[2] | 2;
    let plain = cipher ^ (t.wrapping_mul(t ^ 1) >> 8) as u8;
    crypto_update(keys, plain);
    plain
}

/// Decrypts a ZipCrypto entry starting at `data` (12-byte encryption header + payload) if `check` matches.
pub fn decrypt_zipcrypto(password: &str, check: u8, data: &[u8]) -> Option<Vec<u8>> {
    let header = data.get(..12)?;
    let payload = data.get(12..)?;
    let mut keys = crypto_keys(password.as_bytes());
    let mut last = 0u8;
    for b in header {
        last = crypto_step(&mut keys, *b);
    }
    if last != check {
        return None;
    }
    let mut out = Vec::with_capacity(payload.len());
    for b in payload {
        out.push(crypto_step(&mut keys, *b));
    }
    Some(out)
}

/// SHA-1's starting state.
const SHA1_INIT: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

/// SHA-1's compression function: `state` after one 64-byte block, given as
/// its sixteen big-endian words.
///
/// Always inlined: PBKDF2's blocks are mostly constant padding, and inlined
/// into [`HmacSha1::mac_digest`] the compiler folds those words and much of
/// the message schedule built from them. The rounds are spelled out with the five working variables renamed from
/// round to round instead of shifted, so nothing moves between registers but
/// the values each round actually changes.
#[inline(always)]
fn sha1_compress(state: [u32; 5], block: [u32; 16]) -> [u32; 5] {
    let mut w = [0u32; 80];
    w[..16].copy_from_slice(&block);
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = state;

    // One round: `e` takes the new value and `b` its rotation; the caller
    // passes the variables in the order this round sees them.
    macro_rules! round {
        ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:expr, $k:expr, $i:expr) => {
            $e = $e
                .wrapping_add($a.rotate_left(5))
                .wrapping_add($f)
                .wrapping_add($k)
                .wrapping_add(w[$i]);
            $b = $b.rotate_left(30);
        };
    }
    // Five rounds, after which the names are back where they started.
    macro_rules! five {
        ($i:expr, $f:ident, $k:expr) => {
            round!(a, b, c, d, e, $f(b, c, d), $k, $i);
            round!(e, a, b, c, d, $f(a, b, c), $k, $i + 1);
            round!(d, e, a, b, c, $f(e, a, b), $k, $i + 2);
            round!(c, d, e, a, b, $f(d, e, a), $k, $i + 3);
            round!(b, c, d, e, a, $f(c, d, e), $k, $i + 4);
        };
    }
    #[inline(always)]
    fn choose(b: u32, c: u32, d: u32) -> u32 {
        d ^ (b & (c ^ d))
    }
    #[inline(always)]
    fn parity(b: u32, c: u32, d: u32) -> u32 {
        b ^ c ^ d
    }
    #[inline(always)]
    fn majority(b: u32, c: u32, d: u32) -> u32 {
        (b & c) | (d & (b | c))
    }

    for i in (0..20).step_by(5) {
        five!(i, choose, 0x5a82_7999);
    }
    for i in (20..40).step_by(5) {
        five!(i, parity, 0x6ed9_eba1);
    }
    for i in (40..60).step_by(5) {
        five!(i, majority, 0x8f1b_bcdc);
    }
    for i in (60..80).step_by(5) {
        five!(i, parity, 0xca62_c1d6);
    }
    [
        state[0].wrapping_add(a),
        state[1].wrapping_add(b),
        state[2].wrapping_add(c),
        state[3].wrapping_add(d),
        state[4].wrapping_add(e),
    ]
}

/// [`sha1_compress`] as a call, for the paths that run once per message.
#[inline(never)]
fn sha1_compress_call(state: [u32; 5], block: [u32; 16]) -> [u32; 5] {
    sha1_compress(state, block)
}

/// The big-endian words of a 64-byte block.
fn sha1_words(block: &[u8]) -> [u32; 16] {
    let mut w = [0u32; 16];
    for (word, bytes) in w.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    w
}

/// Finishes a SHA-1 begun in `state`, after `prefix_len` bytes already
/// compressed into it (a multiple of 64), with `data` as the rest of the
/// message.
fn sha1_finish(mut state: [u32; 5], prefix_len: u64, data: &[u8]) -> [u32; 5] {
    let mut blocks = data.chunks_exact(64);
    for block in &mut blocks {
        state = sha1_compress_call(state, sha1_words(block));
    }
    let rest = blocks.remainder();
    let bit_len = (prefix_len + data.len() as u64) * 8;
    let mut tail = [0u8; 128];
    tail[..rest.len()].copy_from_slice(rest);
    tail[rest.len()] = 0x80;
    let end = if rest.len() < 56 { 64 } else { 128 };
    tail[end - 8..end].copy_from_slice(&bit_len.to_be_bytes());
    for block in tail[..end].chunks_exact(64) {
        state = sha1_compress_call(state, sha1_words(block));
    }
    state
}

/// HMAC-SHA1 under one key, with the key's two padded blocks compressed once
/// up front rather than on every message.
struct HmacSha1 {
    inner: [u32; 5],
    outer: [u32; 5],
}

impl HmacSha1 {
    fn new(key: &[u8]) -> Self {
        let mut k = [0u8; 64];
        if key.len() > 64 {
            for (slot, word) in k.chunks_exact_mut(4).zip(sha1_finish(SHA1_INIT, 0, key)) {
                slot.copy_from_slice(&word.to_be_bytes());
            }
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let ipad = k.map(|b| b ^ 0x36);
        let opad = k.map(|b| b ^ 0x5c);
        Self {
            inner: sha1_compress_call(SHA1_INIT, sha1_words(&ipad)),
            outer: sha1_compress_call(SHA1_INIT, sha1_words(&opad)),
        }
    }

    /// The MAC of any message, as words.
    fn mac(&self, message: &[u8]) -> [u32; 5] {
        let inner = sha1_finish(self.inner, 64, message);
        Self::mac_digest(inner, self.outer)
    }

    /// The MAC of a 20-byte message given as words, which is all PBKDF2's
    /// iterations hash: one block for the inner hash and one for the outer.
    fn mac20(&self, message: [u32; 5]) -> [u32; 5] {
        let inner = Self::mac_digest(message, self.inner);
        Self::mac_digest(inner, self.outer)
    }

    /// `state` finished over a 20-byte digest after one 64-byte key block:
    /// the digest, the padding byte, zeros and a length of 84 bytes.
    #[inline(always)]
    fn mac_digest(digest: [u32; 5], state: [u32; 5]) -> [u32; 5] {
        let mut block = [0u32; 16];
        block[..5].copy_from_slice(&digest);
        block[5] = 0x8000_0000;
        block[15] = (64 + 20) * 8;
        sha1_compress(state, block)
    }
}

/// PBKDF2's iteration count for WinZip AES.
const WINZIP_ITERATIONS: u32 = 1000;

/// Bytes `start..end` of PBKDF2-HMAC-SHA1's output, computing only the
/// 20-byte blocks that cover them: blocks are independent, so a password
/// check needs just the one holding the verifier.
fn pbkdf2_sha1(
    mac: &HmacSha1,
    salt: &[u8],
    iterations: u32,
    start: usize,
    end: usize,
) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(end.checked_sub(start)?);
    let mut message = Vec::with_capacity(salt.len() + 4);
    for index in start / 20..end.div_ceil(20) {
        message.clear();
        message.extend_from_slice(salt);
        message.extend_from_slice(&u32::try_from(index + 1).ok()?.to_be_bytes());
        let mut u = mac.mac(&message);
        let mut sum = u;
        for _ in 1..iterations {
            u = mac.mac20(u);
            for (s, x) in sum.iter_mut().zip(u) {
                *s ^= x;
            }
        }
        let mut block = [0u8; 20];
        for (bytes, word) in block.chunks_exact_mut(4).zip(sum) {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
        let from = start.saturating_sub(index * 20);
        let to = (end - index * 20).min(20);
        out.extend_from_slice(&block[from..to]);
    }
    Some(out)
}

/// PBKDF2-HMAC-SHA1 (1000 rounds) as specified by WinZip AES: derives `2 * key_len + 2` bytes.
pub fn aes_derive(password: &[u8], salt: &[u8], key_len: usize) -> Option<Vec<u8>> {
    let wanted = key_len.checked_mul(2)?.checked_add(2)?;
    pbkdf2_sha1(&HmacSha1::new(password), salt, WINZIP_ITERATIONS, 0, wanted)
}

/// The two verifier bytes WinZip AES derives after the key and MAC key.
fn aes_verifier_with(mac: &HmacSha1, salt: &[u8], key_len: usize) -> Option<[u8; 2]> {
    let at = key_len.checked_mul(2)?;
    pbkdf2_sha1(mac, salt, WINZIP_ITERATIONS, at, at.checked_add(2)?)?
        .try_into()
        .ok()
}

fn aes_verifier(password: &[u8], salt: &[u8], key_len: usize) -> Option<[u8; 2]> {
    aes_verifier_with(&HmacSha1::new(password), salt, key_len)
}

/// Decrypts a WinZip AES (method 99) entry starting at `data` (`salt + verifier + ciphertext [+ 10-byte auth]`).
pub fn decrypt_winzip_aes(
    password: &str,
    strength: u8,
    data: &[u8],
    full_packed: Option<u64>,
) -> Option<Vec<u8>> {
    if !(1..=3).contains(&strength) {
        return None;
    }
    let salt_len = usize::from(strength) * 4 + 4;
    let key_len = (usize::from(strength) + 1) * 8;
    let salt = data.get(..salt_len)?;
    let verifier = data.get(salt_len..salt_len + 2)?;
    // The verifier first: a wrong password costs one PBKDF2 block, and the
    // MAC key between the AES key and the verifier is never derived.
    let mac = HmacSha1::new(password.as_bytes());
    if aes_verifier_with(&mac, salt, key_len)?[..] != *verifier {
        return None;
    }
    let key = pbkdf2_sha1(&mac, salt, WINZIP_ITERATIONS, 0, key_len)?;
    let key = &key[..];
    let ct_end = match full_packed.and_then(|p| usize::try_from(p).ok()) {
        Some(p) if p >= salt_len + 12 => data.len().min(p - 10),
        _ => data.len(),
    };
    let ct = data.get(salt_len + 2..ct_end)?;
    decrypt_winzip_ctr(key, ct)
}

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const RCON: [u32; 10] = [
    0x0100_0000,
    0x0200_0000,
    0x0400_0000,
    0x0800_0000,
    0x1000_0000,
    0x2000_0000,
    0x4000_0000,
    0x8000_0000,
    0x1b00_0000,
    0x3600_0000,
];

fn sub_word(w: u32) -> u32 {
    let [b0, b1, b2, b3] = w.to_be_bytes();
    u32::from_be_bytes([
        SBOX[usize::from(b0)],
        SBOX[usize::from(b1)],
        SBOX[usize::from(b2)],
        SBOX[usize::from(b3)],
    ])
}

/// AES's MixColumns of a byte `s` in column position 0, `(2s, s, s, 3s)`
/// as a big-endian word; positions 1-3 are its rotations. One lookup per
/// state byte then does SubBytes, ShiftRows (by which byte is looked up) and
/// MixColumns at once.
const TE0: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let s = SBOX[i];
        let s2 = (s << 1) ^ if s & 0x80 != 0 { 0x1b } else { 0 };
        let s3 = s2 ^ s;
        table[i] = u32::from_be_bytes([s2, s, s, s3]);
        i += 1;
    }
    table
};
const TE1: [u32; 256] = rotated(8);
const TE2: [u32; 256] = rotated(16);
const TE3: [u32; 256] = rotated(24);

const fn rotated(bits: u32) -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = TE0[i].rotate_right(bits);
        i += 1;
    }
    table
}

/// The expanded key as big-endian words, and the number of rounds.
fn aes_expand_key(key: &[u8]) -> Option<([u32; 60], usize)> {
    let (nk, nr) = match key.len() {
        16 => (4usize, 10usize),
        24 => (6usize, 12usize),
        32 => (8usize, 14usize),
        _ => return None,
    };
    let total_words = 4 * (nr + 1);
    let mut w = [0u32; 60];
    for (i, chunk) in key.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for i in nk..total_words {
        let mut temp = w[i - 1];
        if i % nk == 0 {
            temp = sub_word(temp.rotate_left(8)) ^ RCON[i / nk - 1];
        } else if nk > 6 && i % nk == 4 {
            temp = sub_word(temp);
        }
        w[i] = w[i - nk] ^ temp;
    }
    Some((w, nr))
}

/// Byte `n` (0 = most significant) of `w`, as a table index.
#[inline(always)]
fn byte(w: u32, n: u32) -> usize {
    usize::from((w >> (24 - 8 * n)) as u8)
}

/// Encrypts `N` blocks (each four big-endian words) side by side under a key
/// of `NR` rounds. The blocks are independent, so their table lookups
/// overlap instead of each round waiting on the last.
#[inline(always)]
fn aes_encrypt<const NR: usize, const N: usize>(
    rk: &[u32; 60],
    mut s: [[u32; 4]; N],
) -> [[u32; 4]; N] {
    for b in &mut s {
        for (w, k) in b.iter_mut().zip(&rk[..4]) {
            *w ^= k;
        }
    }
    for round in 1..NR {
        let k = &rk[4 * round..4 * round + 4];
        for b in &mut s {
            let [s0, s1, s2, s3] = *b;
            *b = [
                TE0[byte(s0, 0)] ^ TE1[byte(s1, 1)] ^ TE2[byte(s2, 2)] ^ TE3[byte(s3, 3)] ^ k[0],
                TE0[byte(s1, 0)] ^ TE1[byte(s2, 1)] ^ TE2[byte(s3, 2)] ^ TE3[byte(s0, 3)] ^ k[1],
                TE0[byte(s2, 0)] ^ TE1[byte(s3, 1)] ^ TE2[byte(s0, 2)] ^ TE3[byte(s1, 3)] ^ k[2],
                TE0[byte(s3, 0)] ^ TE1[byte(s0, 1)] ^ TE2[byte(s1, 2)] ^ TE3[byte(s2, 3)] ^ k[3],
            ];
        }
    }
    let k = &rk[4 * NR..4 * NR + 4];
    for b in &mut s {
        let [s0, s1, s2, s3] = *b;
        let last = |a: u32, b: u32, c: u32, d: u32| {
            u32::from_be_bytes([
                SBOX[byte(a, 0)],
                SBOX[byte(b, 1)],
                SBOX[byte(c, 2)],
                SBOX[byte(d, 3)],
            ])
        };
        *b = [
            last(s0, s1, s2, s3) ^ k[0],
            last(s1, s2, s3, s0) ^ k[1],
            last(s2, s3, s0, s1) ^ k[2],
            last(s3, s0, s1, s2) ^ k[3],
        ];
    }
    s
}

/// Decrypts WinZip AES CTR-mode ciphertext (little-endian counter starting at 1).
pub fn decrypt_winzip_ctr(key: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let (rk, nr) = aes_expand_key(key)?;
    let mut out = ciphertext.to_vec();
    if !accel::aes_ctr_xor(&rk, nr, &mut out) {
        ctr_xor_portable(&rk, nr, &mut out);
    }
    Some(out)
}

/// [`ctr_xor`] for a key of `nr` rounds: the keystream from table lookups, for
/// processors without AES instructions.
fn ctr_xor_portable(rk: &[u32; 60], nr: usize, data: &mut [u8]) {
    match nr {
        10 => ctr_xor::<10>(rk, data),
        12 => ctr_xor::<12>(rk, data),
        _ => ctr_xor::<14>(rk, data),
    }
}

/// How many counter blocks CTR encrypts side by side. Two keep the 64-bit ARM
/// cores' load units busy (Apple M4/M5: two run 13% faster than four, 50%
/// faster than one). x86-64's sixteen registers can't hold more than one
/// block's state and temporaries without spilling, and one measured fastest.
const CTR_LANES: usize = if cfg!(target_arch = "x86_64") { 1 } else { 2 };

/// XORs `data` with the keystream: [`CTR_LANES`] counter blocks at a time,
/// then one at a time for the rest.
fn ctr_xor<const NR: usize>(rk: &[u32; 60], data: &mut [u8]) {
    /// The counter as a block of four big-endian words.
    fn block(counter: u128) -> [u32; 4] {
        let b = counter.to_le_bytes();
        [0, 4, 8, 12].map(|i| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]))
    }
    /// XORs one keystream block into up to 16 bytes.
    fn apply(chunk: &mut [u8], ks: [u32; 4]) {
        let mut bytes = [0u8; 16];
        for (dst, w) in bytes.chunks_exact_mut(4).zip(ks) {
            dst.copy_from_slice(&w.to_be_bytes());
        }
        if let Ok(whole) = <&mut [u8; 16]>::try_from(&mut *chunk) {
            *whole = (u128::from_ne_bytes(*whole) ^ u128::from_ne_bytes(bytes)).to_ne_bytes();
        } else {
            for (c, k) in chunk.iter_mut().zip(bytes) {
                *c ^= k;
            }
        }
    }
    let mut counter = 1u128;
    let mut groups = data.chunks_exact_mut(16 * CTR_LANES);
    for group in &mut groups {
        let blocks: [[u32; 4]; CTR_LANES] =
            std::array::from_fn(|i| block(counter.wrapping_add(i as u128)));
        counter = counter.wrapping_add(CTR_LANES as u128);
        for (chunk, ks) in group
            .chunks_exact_mut(16)
            .zip(aes_encrypt::<NR, CTR_LANES>(rk, blocks))
        {
            apply(chunk, ks);
        }
    }
    for chunk in groups.into_remainder().chunks_mut(16) {
        let [ks] = aes_encrypt::<NR, 1>(rk, [block(counter)]);
        counter = counter.wrapping_add(1);
        apply(chunk, ks);
    }
}

/// Finds an extra-field record by header id within an extra-field block.
///
/// The block is a sequence of `(u16 id, u16 len, len bytes)`. A malformed
/// length terminates the walk rather than running past the block.
fn find_extra_field(extra: &[u8], want_id: u16) -> Option<&[u8]> {
    let mut off = 0usize;
    while off + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[off], extra[off + 1]]);
        let len = u16::from_le_bytes([extra[off + 2], extra[off + 3]]) as usize;
        let body_start = off + 4;
        let body_end = body_start.checked_add(len)?;
        if body_end > extra.len() {
            return None;
        }
        if id == want_id {
            return Some(&extra[body_start..body_end]);
        }
        off = body_end;
    }
    None
}

/// Inflates a raw deflate stream, refusing to produce more than
/// `declared_size` bytes.
///
/// The cap is what makes a zip bomb harmless: an entry claiming a small
/// uncompressed size cannot expand past it, and one claiming a large size is
/// rejected earlier by [`MAX_INFLATED_SIZE`]. Producing fewer bytes than
/// declared is also an error -- a short XML document would parse into wrong
/// tags, and AGENTS.md is explicit that a plausible wrong value is worse than
/// an absent one.
fn inflate(payload: &[u8], declared_size: u64) -> Result<Vec<u8>> {
    use flate2::{Decompress, FlushDecompress, Status};

    // One byte of room past the declared size, so a stream that runs long
    // fills it and is caught rather than silently cut to the declared size.
    let room = usize::try_from(declared_size)
        .ok()
        .and_then(|n| n.checked_add(1))
        .ok_or(ZipReadError::BadOffset)?;
    let mut out = Vec::new();
    out.try_reserve_exact(room)
        .map_err(|_| ZipReadError::EntryTooLarge(declared_size))?;

    // The whole stream in one call with `Finish`: the inflater then writes
    // straight into `out`, using it as its history, instead of inflating
    // through its own 32 KiB window and copying each piece out, as a reader
    // does.
    let status = Decompress::new(false)
        .decompress_vec(payload, &mut out, FlushDecompress::Finish)
        .map_err(|_| ZipReadError::DecompressionFailed)?;

    if status != Status::StreamEnd || out.len() as u64 != declared_size {
        return Err(ZipReadError::DecompressionFailed);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a single-entry Stored archive by hand. The richer builder in
    /// `tests/writer.rs` covers Deflate and timestamps; this local one keeps
    /// the unit tests self-contained.
    fn stored_archive(name: &str, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        let crc = crc32(body);
        let n = name.as_bytes();

        let local_off = v.len() as u32;
        v.extend_from_slice(&LOCAL_HEADER_SIG.to_le_bytes());
        v.extend_from_slice(&10u16.to_le_bytes()); // version needed
        v.extend_from_slice(&0u16.to_le_bytes()); // flags
        v.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        v.extend_from_slice(&0u16.to_le_bytes()); // time
        v.extend_from_slice(&0x2821u16.to_le_bytes()); // date: 2000-01-01
        v.extend_from_slice(&crc.to_le_bytes());
        v.extend_from_slice(&(body.len() as u32).to_le_bytes());
        v.extend_from_slice(&(body.len() as u32).to_le_bytes());
        v.extend_from_slice(&(n.len() as u16).to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes()); // extra len
        v.extend_from_slice(n);
        v.extend_from_slice(body);

        let cd_off = v.len() as u32;
        v.extend_from_slice(&CENTRAL_HEADER_SIG.to_le_bytes());
        v.extend_from_slice(&0x031eu16.to_le_bytes()); // made by: unix
        v.extend_from_slice(&10u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes()); // flags
        v.extend_from_slice(&0u16.to_le_bytes()); // method
        v.extend_from_slice(&0u16.to_le_bytes()); // time
        v.extend_from_slice(&0x2821u16.to_le_bytes()); // date
        v.extend_from_slice(&crc.to_le_bytes());
        v.extend_from_slice(&(body.len() as u32).to_le_bytes());
        v.extend_from_slice(&(body.len() as u32).to_le_bytes());
        v.extend_from_slice(&(n.len() as u16).to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes()); // extra
        v.extend_from_slice(&0u16.to_le_bytes()); // comment
        v.extend_from_slice(&0u16.to_le_bytes()); // disk
        v.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        v.extend_from_slice(&0o100644u32.wrapping_shl(16).to_le_bytes()); // external
        v.extend_from_slice(&local_off.to_le_bytes());
        v.extend_from_slice(n);

        let cd_len = v.len() as u32 - cd_off;
        v.extend_from_slice(&EOCD_SIG.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes()); // disk
        v.extend_from_slice(&0u16.to_le_bytes()); // cd disk
        v.extend_from_slice(&1u16.to_le_bytes()); // entries this disk
        v.extend_from_slice(&1u16.to_le_bytes()); // entries total
        v.extend_from_slice(&cd_len.to_le_bytes());
        v.extend_from_slice(&cd_off.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes()); // comment len
        v
    }

    fn crc32(data: &[u8]) -> u32 {
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

    #[test]
    fn reads_a_stored_entry() {
        let zip = stored_archive("hello.txt", b"hello world");
        let r = ZipReader::new(&zip).expect("should parse");
        assert_eq!(r.len(), 1);
        let e = r.by_index(0).expect("entry 0");
        assert_eq!(e.name(), "hello.txt");
        assert_eq!(e.size(), 11);
        assert_eq!(e.compression(), 0);
        assert_eq!(e.compression_name(), "Stored");
        assert!(!e.is_dir());
        assert!(!e.is_encrypted());
        assert_eq!(r.read_to_string("hello.txt").expect("read"), "hello world");
    }

    #[test]
    fn reports_unix_mode_only_for_unix_hosts() {
        let zip = stored_archive("a.txt", b"x");
        let r = ZipReader::new(&zip).expect("parse");
        // The fixture declares host 3 (UNIX), so the mode is meaningful.
        assert_eq!(r.by_index(0).expect("entry").unix_mode(), Some(0o100644));
    }

    #[test]
    fn decodes_dos_datetime() {
        let zip = stored_archive("a.txt", b"x");
        let r = ZipReader::new(&zip).expect("parse");
        let dt = r.by_index(0).expect("entry").last_modified().expect("dt");
        assert_eq!(dt.year(), 2000);
        assert_eq!(dt.month(), 1);
        assert_eq!(dt.day(), 1);
    }

    #[test]
    fn missing_entry_is_an_error_not_a_panic() {
        let zip = stored_archive("a.txt", b"x");
        let r = ZipReader::new(&zip).expect("parse");
        assert_eq!(r.read_by_name("nope"), Err(ZipReadError::EntryNotFound));
        assert!(!r.contains("nope"));
    }

    #[test]
    fn rejects_non_zip_input() {
        assert_eq!(
            ZipReader::new(b"not a zip").unwrap_err(),
            ZipReadError::NotAZip
        );
        assert_eq!(ZipReader::new(b"").unwrap_err(), ZipReadError::NotAZip);
    }

    /// Every truncation of a valid archive must be an error, never a panic.
    /// This is the property the fuzz target explores more widely.
    #[test]
    fn every_truncation_fails_cleanly() {
        let zip = stored_archive("hello.txt", b"hello world");
        for n in 0..zip.len() {
            if let Ok(r) = ZipReader::new(&zip[..n]) {
                // Parsing a prefix may succeed when the EOCD survives; reading
                // must then still not panic.
                for i in 0..r.len() {
                    if let Some(e) = r.by_index(i) {
                        let _ = r.read_entry(e);
                    }
                }
            }
        }
    }

    /// A single flipped byte must not panic, at any position.
    #[test]
    fn single_byte_corruption_never_panics() {
        let zip = stored_archive("hello.txt", b"hello world");
        for i in 0..zip.len() {
            let mut c = zip.clone();
            c[i] ^= 0xff;
            if let Ok(r) = ZipReader::new(&c) {
                for idx in 0..r.len() {
                    if let Some(e) = r.by_index(idx) {
                        let _ = r.read_entry(e);
                    }
                }
                let _ = r.comment();
            }
        }
    }

    #[test]
    fn unsupported_method_still_enumerates() {
        let mut zip = stored_archive("a.txt", b"x");
        // Rewrite the central directory method to Zstd (93). The entry must
        // still be listed with its name and sizes; only reading it fails.
        let cd = zip
            .windows(4)
            .position(|w| w == CENTRAL_HEADER_SIG.to_le_bytes())
            .expect("central header");
        zip[cd + 10..cd + 12].copy_from_slice(&93u16.to_le_bytes());
        let r = ZipReader::new(&zip).expect("parse");
        let e = r.by_index(0).expect("entry");
        assert_eq!(e.compression_name(), "Zstd");
        assert_eq!(e.name(), "a.txt");
        assert_eq!(
            r.read_entry(e),
            Err(ZipReadError::UnsupportedCompression(93))
        );
    }

    #[test]
    fn absurd_entry_count_does_not_preallocate() {
        let mut zip = stored_archive("a.txt", b"x");
        let eocd = ZipReader::find_eocd(&zip).expect("eocd");
        // Claim 65534 entries in an archive that holds one.
        zip[eocd + 10..eocd + 12].copy_from_slice(&65534u16.to_le_bytes());
        // Must stop at the first non-signature rather than trusting the count.
        let r = ZipReader::new(&zip).expect("parse");
        assert_eq!(r.len(), 1);
    }

    /// PBKDF2-HMAC-SHA1 as first written, hashing every block in full: the
    /// reference the precomputed-pad version must match.
    /// Pure-Rust SHA-1 digest of two slices concatenated (`a || b`).
    fn sha1_reference(a: &[u8], b: &[u8]) -> [u8; 20] {
        let mut h0 = 0x6745_2301u32;
        let mut h1 = 0xefcd_ab89u32;
        let mut h2 = 0x98ba_dcfeu32;
        let mut h3 = 0x1032_5476u32;
        let mut h4 = 0xc3d2_e1f0u32;

        let total_len = a.len() + b.len();
        let bit_len = (total_len as u64) * 8;
        let mut msg = Vec::with_capacity((total_len + 9).div_ceil(64) * 64);
        msg.extend_from_slice(a);
        msg.extend_from_slice(b);
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());

        for chunk in msg.chunks_exact(64) {
            let mut w = [0u32; 80];
            for (i, word) in w.iter_mut().take(16).enumerate() {
                let off = i * 4;
                *word = u32::from_be_bytes([
                    chunk[off],
                    chunk[off + 1],
                    chunk[off + 2],
                    chunk[off + 3],
                ]);
            }
            for i in 16..80 {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            }
            let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
            for (i, &wi) in w.iter().enumerate() {
                let (f, k) = match i {
                    0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999u32),
                    20..=39 => (b ^ c ^ d, 0x6ed9_eba1u32),
                    40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc_u32),
                    _ => (b ^ c ^ d, 0xca62_c1d6u32),
                };
                let temp = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(wi);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }
            h0 = h0.wrapping_add(a);
            h1 = h1.wrapping_add(b);
            h2 = h2.wrapping_add(c);
            h3 = h3.wrapping_add(d);
            h4 = h4.wrapping_add(e);
        }

        let mut out = [0u8; 20];
        out[0..4].copy_from_slice(&h0.to_be_bytes());
        out[4..8].copy_from_slice(&h1.to_be_bytes());
        out[8..12].copy_from_slice(&h2.to_be_bytes());
        out[12..16].copy_from_slice(&h3.to_be_bytes());
        out[16..20].copy_from_slice(&h4.to_be_bytes());
        out
    }

    fn hmac_pads_reference(key: &[u8]) -> ([u8; 64], [u8; 64]) {
        let mut k = [0u8; 64];
        if key.len() > 64 {
            let digest = sha1_reference(key, &[]);
            k[..20].copy_from_slice(&digest);
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for i in 0..64 {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }
        (ipad, opad)
    }

    fn hmac_reference(ipad: &[u8; 64], opad: &[u8; 64], data: &[u8]) -> [u8; 20] {
        let inner = sha1_reference(ipad, data);
        sha1_reference(opad, &inner)
    }

    /// PBKDF2-HMAC-SHA1 (1000 rounds) as specified by WinZip AES: derives `2 * key_len + 2` bytes.
    fn aes_derive_reference(password: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
        let (ipad, opad) = hmac_pads_reference(password);
        let wanted = key_len * 2 + 2;
        let mut derived = Vec::with_capacity(wanted + 20);
        let mut block = 1u32;
        let mut salt_block = Vec::with_capacity(salt.len() + 4);
        while derived.len() < wanted {
            salt_block.clear();
            salt_block.extend_from_slice(salt);
            salt_block.extend_from_slice(&block.to_be_bytes());
            let mut u = hmac_reference(&ipad, &opad, &salt_block);
            let mut out = u;
            for _ in 1..1000 {
                u = hmac_reference(&ipad, &opad, &u);
                for (slot, b) in out.iter_mut().zip(u) {
                    *slot ^= b;
                }
            }
            derived.extend_from_slice(&out);
            block += 1;
        }
        derived.truncate(wanted);
        derived
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn sha1(data: &[u8]) -> Vec<u8> {
        sha1_finish(SHA1_INIT, 0, data)
            .iter()
            .flat_map(|w| w.to_be_bytes())
            .collect()
    }

    #[test]
    fn sha1_and_pbkdf2_match_published_vectors() {
        // FIPS 180-2 and the usual extra lengths around the padding boundary.
        assert_eq!(sha1(b""), hex("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
        assert_eq!(
            sha1(b"abc"),
            hex("a9993e364706816aba3e25717850c26c9cd0d89d")
        );
        assert_eq!(
            sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            hex("84983e441c3bd26ebaae4aa1f95129e5e54670f1")
        );
        assert_eq!(
            sha1(&[b'a'; 1_000_000]),
            hex("34aa973cd4c4daa4f61eeb2bdbad27316534016f")
        );
        for len in 0..200 {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            assert_eq!(sha1(&data), sha1_reference(&data, &[]), "length {len}");
        }
        // RFC 6070.
        let mac = HmacSha1::new(b"password");
        for (iterations, want) in [
            (1, "0c60c80f961f0e71f3a9b524af6012062fe037a6"),
            (2, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
            (4096, "4b007901b765489abead49d926f721d065a429c1"),
        ] {
            assert_eq!(
                pbkdf2_sha1(&mac, b"salt", iterations, 0, 20).unwrap(),
                hex(want)
            );
        }
        let mac = HmacSha1::new(b"passwordPASSWORDpassword");
        let salt = b"saltSALTsaltSALTsaltSALTsaltSALTsalt";
        let want = hex("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");
        assert_eq!(pbkdf2_sha1(&mac, salt, 4096, 0, 25).unwrap(), want);
        // Any window of the output is the same bytes as in the whole.
        for (start, end) in [(0, 1), (3, 21), (19, 20), (20, 25), (24, 25), (5, 5)] {
            assert_eq!(
                pbkdf2_sha1(&mac, salt, 4096, start, end).unwrap(),
                want[start..end],
                "{start}..{end}"
            );
        }
    }

    #[test]
    fn aes_key_derivation_matches_the_reference() {
        let long = "x".repeat(100);
        for password in [
            "",
            "secret",
            "exactly-sixty-four-bytes-long-password-for-the-hmac-key-block!!",
            &long,
        ] {
            for salt_len in [0, 8, 12, 16, 55, 56, 64, 70] {
                let salt: Vec<u8> = (0..salt_len).map(|i| (i * 13 + 1) as u8).collect();
                for key_len in [16, 24, 32] {
                    let want = aes_derive_reference(password.as_bytes(), &salt, key_len);
                    assert_eq!(
                        aes_derive(password.as_bytes(), &salt, key_len).unwrap(),
                        want,
                        "{password:?} salt {salt_len} key {key_len}"
                    );
                    assert_eq!(
                        aes_verifier(password.as_bytes(), &salt, key_len).unwrap(),
                        want[key_len * 2..]
                    );
                }
            }
        }
    }

    // AES as first written, a byte at a time: the reference the table-driven
    // version must match.
    #[inline]
    fn xtime(x: u8) -> u8 {
        (x << 1) ^ if x & 0x80 != 0 { 0x1b } else { 0 }
    }

    fn expand_reference(key: &[u8]) -> Option<([[u8; 16]; 15], usize)> {
        let (nk, nr) = match key.len() {
            16 => (4usize, 10usize),
            24 => (6usize, 12usize),
            32 => (8usize, 14usize),
            _ => return None,
        };
        let total_words = 4 * (nr + 1);
        let mut w = [0u32; 60];
        for (i, chunk) in key.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for i in nk..total_words {
            let mut temp = w[i - 1];
            if i % nk == 0 {
                temp = sub_word(temp.rotate_left(8)) ^ RCON[i / nk - 1];
            } else if nk > 6 && i % nk == 4 {
                temp = sub_word(temp);
            }
            w[i] = w[i - nk] ^ temp;
        }
        let mut rk = [[0u8; 16]; 15];
        for r in 0..=nr {
            for c in 0..4 {
                rk[r][c * 4..c * 4 + 4].copy_from_slice(&w[r * 4 + c].to_be_bytes());
            }
        }
        Some((rk, nr))
    }

    fn encrypt_reference(rk: &[[u8; 16]; 15], nr: usize, block: &[u8; 16]) -> [u8; 16] {
        let mut s = *block;
        for (b, &k) in s.iter_mut().zip(&rk[0]) {
            *b ^= k;
        }
        for round_key in rk.iter().take(nr).skip(1) {
            for b in &mut s {
                *b = SBOX[usize::from(*b)];
            }
            s = [
                s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3], s[8], s[13], s[2], s[7], s[12],
                s[1], s[6], s[11],
            ];
            for col in s.chunks_exact_mut(4) {
                let (s0, s1, s2, s3) = (col[0], col[1], col[2], col[3]);
                let t = s0 ^ s1 ^ s2 ^ s3;
                col[0] ^= t ^ xtime(s0 ^ s1);
                col[1] ^= t ^ xtime(s1 ^ s2);
                col[2] ^= t ^ xtime(s2 ^ s3);
                col[3] ^= t ^ xtime(s3 ^ s0);
            }
            for (b, &k) in s.iter_mut().zip(round_key) {
                *b ^= k;
            }
        }
        for b in &mut s {
            *b = SBOX[usize::from(*b)];
        }
        s = [
            s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3], s[8], s[13], s[2], s[7], s[12],
            s[1], s[6], s[11],
        ];
        for (b, &k) in s.iter_mut().zip(&rk[nr]) {
            *b ^= k;
        }
        s
    }

    fn ctr_reference(key: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let (rk, nr) = expand_reference(key)?;
        let mut out = Vec::with_capacity(ciphertext.len());
        let mut counter = [0u8; 16];
        for chunk in ciphertext.chunks(16) {
            for b in &mut counter {
                *b = b.wrapping_add(1);
                if *b != 0 {
                    break;
                }
            }
            let ks = encrypt_reference(&rk, nr, &counter);
            for (&c, &k) in chunk.iter().zip(&ks) {
                out.push(c ^ k);
            }
        }
        Some(out)
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn aes_matches_fips_197_and_the_bytewise_reference() {
        let plain: [u8; 16] = unhex("00112233445566778899aabbccddeeff")
            .try_into()
            .unwrap();
        for (len, want) in [
            (16, "69c4e0d86a7b0430d8cdb78070b4c55a"),
            (24, "dda97ca4864cdfe06eaf70a0ec0d7191"),
            (32, "8ea2b7ca516745bfeafc49904b496089"),
        ] {
            let key: Vec<u8> = (0..len as u8).collect();
            let (rk, nr) = aes_expand_key(&key).unwrap();
            let words =
                [0, 4, 8, 12].map(|i| u32::from_be_bytes(plain[i..i + 4].try_into().unwrap()));
            let out = match nr {
                10 => aes_encrypt::<10, 1>(&rk, [words]),
                12 => aes_encrypt::<12, 1>(&rk, [words]),
                _ => aes_encrypt::<14, 1>(&rk, [words]),
            };
            let got: Vec<u8> = out[0].iter().flat_map(|w| w.to_be_bytes()).collect();
            assert_eq!(got, unhex(want), "AES-{}", len * 8);
            let (old_rk, old_nr) = expand_reference(&key).unwrap();
            assert_eq!(
                encrypt_reference(&old_rk, old_nr, &plain).to_vec(),
                unhex(want)
            );
        }
    }

    #[test]
    fn ctr_matches_the_bytewise_reference() {
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let data: Vec<u8> = (0..(1 << 20) + 4133)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect();
        for key_len in [16, 24, 32] {
            let key: Vec<u8> = data[..key_len].iter().map(|b| b ^ 0x5a).collect();
            // The whole buffer crosses the counter's carries into its second
            // and third bytes; the short ones every tail length.
            let want = ctr_reference(&key, &data).unwrap();
            assert_eq!(
                decrypt_winzip_ctr(&key, &data).unwrap(),
                want,
                "key {key_len}"
            );
            // The table-driven keystream too, which processors with AES
            // instructions never run through the public function.
            let (rk, nr) = aes_expand_key(&key).unwrap();
            let mut portable = data.clone();
            ctr_xor_portable(&rk, nr, &mut portable);
            assert_eq!(portable, want, "portable, key {key_len}");
            for len in (0..200).chain([4095, 4096, 4097, 65_535, 65_536, 65_537]) {
                assert_eq!(
                    decrypt_winzip_ctr(&key, &data[..len]).unwrap(),
                    want[..len],
                    "key {key_len} len {len}"
                );
            }
        }
        assert!(decrypt_winzip_ctr(&[0; 20], b"x").is_none());
    }

    #[test]
    fn inflate_holds_streams_to_their_declared_size() {
        use std::io::Write;
        fn deflate(body: &[u8]) -> Vec<u8> {
            let mut e =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(body).unwrap();
            e.finish().unwrap()
        }
        let failed = |r: Result<Vec<u8>>| matches!(r, Err(ZipReadError::DecompressionFailed));
        for body in [
            Vec::new(),
            b"x".to_vec(),
            b"metadata ".repeat(10_000),
            (0..300_000u32)
                .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
                .collect(),
        ] {
            let stream = deflate(&body);
            let n = body.len() as u64;
            assert_eq!(inflate(&stream, n).unwrap(), body);
            // Bytes after the end of the stream are not the stream's business.
            let mut trailing = stream.clone();
            trailing.extend_from_slice(b"junk");
            assert_eq!(inflate(&trailing, n).unwrap(), body);
            // A stream longer or shorter than declared, or cut short, is an error.
            if n > 0 {
                assert!(failed(inflate(&stream, n - 1)));
            }
            assert!(failed(inflate(&stream, n + 1)));
            for cut in [1, 2, stream.len() / 2] {
                assert!(
                    failed(inflate(&stream[..stream.len() - cut], n)),
                    "cut {cut}"
                );
            }
        }
        assert!(failed(inflate(b"\xff\xff\xff\xff", 10)));
    }

    #[test]
    fn zipcrypto_and_winzip_aes_password_check_and_decryption() {
        let hex = "504b03040a00090000005385615d8088f9e51d0000001100000005001c00612e74787455540900035dc0e76a5dc0e76a75780b000104f50100000400000000f7ab9852cf9d136c418bc8d76355e788c188185d9bab38a1e11ee61944";
        let data: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let check = password_check_at(&data, 9, 0, &data[35..63], 63).expect("password check");
        assert!(check.accepts("secret"));
        assert!(!check.accepts("wrong"));
        assert!(!check.certain());
        assert_eq!(PasswordCheck::from_bytes(&check.to_bytes()), Some(check));
        let plain = decrypt_zipcrypto("secret", 0x85, &data[63..]).expect("decrypt zipcrypto");
        assert_eq!(plain, b"hello hello hello");

        let mut salt = [0u8; 16];
        for (i, b) in salt.iter_mut().enumerate() {
            *b = i as u8;
        }
        let aes_check = PasswordCheck::Aes {
            strength: 3,
            salt,
            verifier: [0xa3, 0x36],
        };
        assert!(aes_check.accepts("secret"));
        assert!(!aes_check.accepts("wrong"));
        assert!(aes_check.certain());
        assert_eq!(
            PasswordCheck::from_bytes(&aes_check.to_bytes()),
            Some(aes_check)
        );

        let derived = aes_derive(b"secret", &salt, 32).expect("derive");
        let ct = decrypt_winzip_ctr(&derived[..32], b"winzip aes payload").expect("ctr encrypt");
        let mut aes_payload = Vec::new();
        aes_payload.extend_from_slice(&salt);
        aes_payload.extend_from_slice(&[0xa3, 0x36]);
        aes_payload.extend_from_slice(&ct);
        aes_payload.extend_from_slice(&[0u8; 10]);
        let dec = decrypt_winzip_aes("secret", 3, &aes_payload, Some(aes_payload.len() as u64))
            .expect("decrypt winzip aes");
        assert_eq!(dec, b"winzip aes payload");
    }
}
