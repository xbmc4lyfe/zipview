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

//! Archives that are not in memory, read a byte range at a time.
//!
//! [`ZipIndexOpener`] follows the same steps as [`ZipReader::new`], but asks
//! for each piece of the archive it needs instead of indexing a slice. The
//! tests hold the two to the same entries, comment and errors on every
//! fixture, every truncation of one and every single-byte corruption.

use super::{
    CENTRAL_HEADER_LEN, CENTRAL_HEADER_SIG, EOCD_LEN, EOCD_SIG, LOCAL_HEADER_LEN, LOCAL_HEADER_SIG,
    MAX_EOCD_SEARCH, MAX_INFLATED_SIZE, PasswordCheck, Result, ZIP64_EOCD_SIG, ZIP64_LOCATOR_SIG,
    ZipEntry, ZipReadError, ZipReader, local_password_check, read_local_entry, u16_at, u32_at,
    u64_at,
};
use std::borrow::Cow;
use std::ops::Range;

/// The ZIP64 end record (56 bytes) and its locator (20) sit just before the
/// end record, so the first read takes them along with the longest comment.
const TAIL_LEN: u64 = MAX_EOCD_SEARCH as u64 + 56 + 20;

/// The most of the central directory asked for in one read. A bigger
/// directory (roughly 150,000 entries and up) takes more reads, and a size
/// field that lies can't make a caller allocate more than this at once.
const DIRECTORY_READ: u64 = 16 * 1024 * 1024;

/// The longest span [`ZipIndex::entry_range`] asks for: the largest entry
/// [`MAX_INFLATED_SIZE`] lets through, stored or deflated, with its headers.
const MAX_ENTRY_SPAN: u64 = MAX_INFLATED_SIZE + MAX_INFLATED_SIZE / 1024 + 128 * 1024;

/// The bytes a password check reads after the local header: an AES-256 salt
/// and verifier (18), which covers ZipCrypto's 12-byte header too.
const PASSWORD_CHECK_LEN: u64 = 16 + 2;

/// The directory of a ZIP archive that isn't in memory: a file too big to
/// load, or one read over a network a range at a time.
///
/// Opening reads the end of the archive and its central directory (two reads
/// for most archives, one when the directory is small), and reading an entry
/// fetches only that entry's bytes. Nothing else of the archive is read or
/// held. [`ZipIndex::open`] and [`ZipIndex::fetch_entry`] take a blocking
/// `read(offset, buf)`; [`ZipIndexOpener`], [`ZipIndex::entry_range`] and
/// [`ZipIndex::read_entry`] do the same work one read at a time, for callers
/// whose reads are asynchronous or need checking first.
///
/// ```
/// # fn main() -> std::io::Result<()> {
/// # let archive: Vec<u8> = vec![0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
/// // Any source of byte ranges: a file read by offset, HTTP range requests...
/// let read = |offset: u64, buf: &mut [u8]| -> std::io::Result<()> {
///     let start = offset as usize;
///     buf.copy_from_slice(&archive[start..start + buf.len()]);
///     Ok(())
/// };
/// let index = zipview::ZipIndex::open(archive.len() as u64, read)?;
/// for entry in index.entries() {
///     println!("{} ({} bytes)", entry.name(), entry.size());
/// }
/// if let Some(entry) = index.by_name("readme.txt") {
///     let bytes = index.fetch_entry(entry, None, read)?;
/// #   let _ = bytes;
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct ZipIndex {
    len: u64,
    entries: Vec<ZipEntry>,
    comment: Vec<u8>,
    offset_shift: u64,
}

/// Opens a [`ZipIndex`] one read at a time.
///
/// While [`next_read`](Self::next_read) names a range, read those bytes of
/// the archive however suits (asynchronously, say) and hand them to
/// [`supply`](Self::supply); then [`finish`](Self::finish) gives the index.
/// Each read asks for bytes not yet supplied. The central directory is parsed
/// once, as its pieces arrive, and bytes already parsed are dropped, so a big
/// directory isn't held twice.
///
/// ```
/// use zipview::ZipIndexOpener;
/// # fn main() -> Result<(), zipview::ZipReadError> {
/// # let archive: Vec<u8> = vec![0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
/// let mut opener = ZipIndexOpener::new(archive.len() as u64);
/// while let Some(range) = opener.next_read()? {
///     let bytes = &archive[range.start as usize..range.end as usize]; // or fetch(range).await
///     opener.supply(range.start, bytes)?;
/// }
/// let index = opener.finish()?;
/// # let _ = index;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct ZipIndexOpener {
    len: u64,
    /// Supplied pieces of the archive, at their offsets.
    held: Vec<(u64, Vec<u8>)>,
    /// The walk over the central directory, once its start is known.
    walk: Option<Walk>,
}

/// Where the walk over the central directory has got to, kept between reads
/// so each header is parsed once.
#[derive(Debug, Clone)]
struct Walk {
    comment: Vec<u8>,
    offset_shift: u64,
    eocd: u64,
    /// Headers still to read, as the end record counts them.
    remaining: u64,
    cursor: u64,
    entries: Vec<ZipEntry>,
}

/// Why a step stopped: bytes it needs, or a reason the archive can't open.
enum Halt {
    Read(Range<u64>),
    Fail(ZipReadError),
}

impl From<ZipReadError> for Halt {
    fn from(e: ZipReadError) -> Self {
        Self::Fail(e)
    }
}

type Step<T> = std::result::Result<T, Halt>;

impl ZipIndexOpener {
    /// Starts opening an archive of `archive_len` bytes.
    pub fn new(archive_len: u64) -> Self {
        Self {
            len: archive_len,
            held: Vec::new(),
            walk: None,
        }
    }

    /// The bytes to read next, or `None` once everything is in. `Err` when
    /// the archive can't be opened, with the error [`ZipReader::new`] gives
    /// for it.
    pub fn next_read(&mut self) -> Result<Option<Range<u64>>> {
        let mut walk = match self.walk.take() {
            Some(walk) => walk,
            None => match self.locate() {
                Ok(walk) => walk,
                Err(Halt::Read(range)) => return Ok(Some(range)),
                Err(Halt::Fail(e)) => return Err(e),
            },
        };
        let step = self.walk(&mut walk);
        let cursor = walk.cursor;
        self.walk = Some(walk);
        match step {
            Ok(()) => {
                self.held = Vec::new();
                Ok(None)
            }
            Err(Halt::Read(range)) => {
                self.forget_before(cursor);
                Ok(Some(range))
            }
            Err(Halt::Fail(e)) => Err(e),
        }
    }

    /// Hands over `bytes`, read from the archive at `offset`. `BadOffset`
    /// when they would run past its end.
    pub fn supply(&mut self, offset: u64, bytes: &[u8]) -> Result<()> {
        if offset
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > self.len)
        {
            return Err(ZipReadError::BadOffset);
        }
        if bytes.is_empty() {
            return Ok(());
        }
        // A read that continues a piece extends it, so the directory stays
        // one slice however many reads it takes.
        match self
            .held
            .iter_mut()
            .find(|(start, piece)| start + piece.len() as u64 == offset)
        {
            Some((_, piece)) => piece.extend_from_slice(bytes),
            None => self.held.push((offset, bytes.to_vec())),
        }
        Ok(())
    }

    /// The index, once [`next_read`](Self::next_read) has nothing more to
    /// ask for. `Truncated` if it still needs bytes.
    pub fn finish(mut self) -> Result<ZipIndex> {
        if self.next_read()?.is_some() {
            return Err(ZipReadError::Truncated);
        }
        let walk = self.walk.ok_or(ZipReadError::Truncated)?;
        Ok(ZipIndex {
            len: self.len,
            entries: walk.entries,
            comment: walk.comment,
            offset_shift: walk.offset_shift,
        })
    }

    /// Drops supplied bytes before `cursor`: the walk never reads behind it.
    fn forget_before(&mut self, cursor: u64) {
        self.held.retain_mut(|(start, piece)| {
            let end = *start + piece.len() as u64;
            if end <= cursor {
                return false;
            }
            if *start < cursor {
                piece.drain(..(cursor - *start) as usize);
                *start = cursor;
            }
            true
        });
    }

    /// `n` bytes at `at`, if one supplied piece holds them all.
    fn held(&self, at: u64, n: u64) -> Option<&[u8]> {
        let end = at.checked_add(n)?;
        self.held.iter().find_map(|(start, piece)| {
            let from = usize::try_from(at.checked_sub(*start)?).ok()?;
            let to = usize::try_from(end - start).ok()?;
            piece.get(from..to)
        })
    }

    /// `n` bytes at `at`, or a read of those not yet supplied.
    fn need(&self, at: u64, n: u64) -> Step<&[u8]> {
        self.held(at, n)
            .ok_or_else(|| Halt::Read(self.unheld(at, at + n)..at + n))
    }

    /// Where a read for `at..end` starts: past the end of a supplied piece
    /// that covers its beginning, so a caller who supplied part of a read is
    /// asked for the rest rather than all of it again.
    fn unheld(&self, at: u64, end: u64) -> u64 {
        self.held
            .iter()
            .filter(|(start, _)| *start <= at)
            .map(|(start, piece)| start + piece.len() as u64)
            .filter(|&piece_end| piece_end > at && piece_end < end)
            .max()
            .unwrap_or(at)
    }

    /// Follows [`ZipReader::new`] over the supplied pieces as far as where
    /// the central directory starts.
    fn locate(&self) -> Step<Walk> {
        let len = self.len;
        if len < EOCD_LEN as u64 {
            return Err(ZipReadError::NotAZip.into());
        }
        let tail_start = len.saturating_sub(TAIL_LEN);
        let tail = self.need(tail_start, len - tail_start)?;
        let at = |off: u64| (off - tail_start) as usize;

        // The last end record within reach of the end, as `find_eocd`.
        let search_start = len.saturating_sub(MAX_EOCD_SEARCH as u64);
        let eocd = (search_start..=len - EOCD_LEN as u64)
            .rev()
            .find(|&off| u32_at(tail, at(off)) == Ok(EOCD_SIG))
            .ok_or(ZipReadError::NotAZip)?;

        let mut entry_count = u64::from(u16_at(tail, at(eocd) + 10)?);
        let mut cd_size = u64::from(u32_at(tail, at(eocd) + 12)?);
        let mut cd_offset = u64::from(u32_at(tail, at(eocd) + 16)?);
        let comment_len = u64::from(u16_at(tail, at(eocd) + 20)?);
        let comment_start = eocd + EOCD_LEN as u64;
        let comment_end = (comment_start + comment_len).min(len);
        let comment = tail[at(comment_start)..at(comment_end)].to_vec();

        if entry_count == u64::from(u16::MAX)
            || cd_offset == u64::from(u32::MAX)
            || cd_size == u64::from(u32::MAX)
        {
            if let Some((z64_entries, z64_size, z64_offset)) = self.zip64(eocd, tail, tail_start)? {
                entry_count = z64_entries;
                cd_size = z64_size;
                cd_offset = z64_offset;
            }
        }

        let (cd_start, offset_shift) = self.locate_central_directory(eocd, cd_size, cd_offset)?;
        Ok(Walk {
            comment,
            offset_shift,
            eocd,
            remaining: entry_count,
            cursor: cd_start,
            entries: Vec::new(),
        })
    }

    /// Parses central headers from where `walk` left off, as
    /// [`ZipReader::new`]'s loop does, until the count runs out, a header
    /// signature is missing, or the next header isn't supplied yet.
    fn walk(&self, walk: &mut Walk) -> Step<()> {
        let eocd = walk.eocd;
        while walk.remaining > 0 {
            if u32_at(self.need_directory(walk.cursor, 4, eocd)?, 0)? != CENTRAL_HEADER_SIG {
                walk.remaining = 0;
                break;
            }
            let fixed = self.need_directory(walk.cursor, CENTRAL_HEADER_LEN as u64, eocd)?;
            let name_len = u64::from(u16_at(fixed, 28)?);
            let extra_len = u64::from(u16_at(fixed, 30)?);
            let header = CENTRAL_HEADER_LEN as u64 + name_len + extra_len;
            let bytes = self.need_directory(walk.cursor, header, eocd)?;
            let (entry, next) = ZipReader::parse_central_entry(bytes, 0)?;
            walk.entries.push(entry);
            walk.cursor = walk
                .cursor
                .checked_add(next as u64)
                .ok_or(ZipReadError::Truncated)?;
            walk.remaining -= 1;
        }
        Ok(())
    }

    /// As `ZipReader::read_zip64`: the ZIP64 counts, or `None` on any
    /// inconsistency.
    fn zip64(&self, eocd: u64, tail: &[u8], tail_start: u64) -> Step<Option<(u64, u64, u64)>> {
        // The locator's 20 bytes end at the end record, inside the tail.
        let Some(locator) = eocd.checked_sub(20) else {
            return Ok(None);
        };
        let at = (locator - tail_start) as usize;
        if u32_at(tail, at) != Ok(ZIP64_LOCATOR_SIG) {
            return Ok(None);
        }
        let Ok(record) = u64_at(tail, at + 8) else {
            return Ok(None);
        };
        if record.checked_add(56).is_none_or(|end| end > self.len) {
            return Ok(None);
        }
        let bytes = self.need(record, 56)?;
        if u32_at(bytes, 0)? != ZIP64_EOCD_SIG {
            return Ok(None);
        }
        Ok(Some((
            u64_at(bytes, 32)?,
            u64_at(bytes, 40)?,
            u64_at(bytes, 48)?,
        )))
    }

    /// As `ZipReader::locate_central_directory`: where the directory starts
    /// and how far a self-extracting stub shifts the archive's offsets.
    fn locate_central_directory(
        &self,
        eocd: u64,
        cd_size: u64,
        cd_offset: u64,
    ) -> Step<(u64, u64)> {
        if cd_offset <= self.len
            && self.signature_at(cd_offset, cd_size, eocd)? == Some(CENTRAL_HEADER_SIG)
        {
            return Ok((cd_offset, 0));
        }
        if let Some(computed) = eocd.checked_sub(cd_size) {
            if computed <= self.len
                && self.signature_at(computed, cd_size, eocd)? == Some(CENTRAL_HEADER_SIG)
            {
                return Ok((computed, computed.saturating_sub(cd_offset)));
            }
        }
        if cd_offset > self.len {
            return Err(ZipReadError::BadOffset.into());
        }
        Ok((cd_offset, 0))
    }

    /// The four bytes at `at`, `None` past the end. When they aren't held,
    /// asks for the directory that would start there, which is what the
    /// next steps read if they turn out to be a central header.
    fn signature_at(&self, at: u64, cd_size: u64, eocd: u64) -> Step<Option<u32>> {
        if at.checked_add(4).is_none_or(|end| end > self.len) {
            return Ok(None);
        }
        match self.held(at, 4) {
            Some(bytes) => Ok(Some(u32_at(bytes, 0)?)),
            None => {
                // The declared size, though not past the end record the
                // directory comes before, nor more than one read's worth.
                let want = cd_size
                    .min(eocd.saturating_sub(at))
                    .max(CENTRAL_HEADER_LEN as u64)
                    .min(DIRECTORY_READ);
                let end = at.saturating_add(want).min(self.len);
                Err(Halt::Read(self.unheld(at, end)..end))
            }
        }
    }

    /// `n` bytes of the central directory at `at`. `Truncated` past the end
    /// of the archive, as in memory; otherwise, when they aren't held, a read
    /// that continues the piece `at` is in.
    fn need_directory(&self, at: u64, n: u64, eocd: u64) -> Step<&[u8]> {
        let end = at
            .checked_add(n)
            .filter(|&end| end <= self.len)
            .ok_or(ZipReadError::Truncated)?;
        if let Some(bytes) = self.held(at, n) {
            return Ok(bytes);
        }
        let from = self.unheld(at, end);
        // Up to the end record in reads of at most DIRECTORY_READ, or a
        // little past it for a directory whose size field undersells it.
        let chunk = eocd.saturating_sub(from).clamp(64 * 1024, DIRECTORY_READ);
        Err(Halt::Read(
            from..end.max(from.saturating_add(chunk)).min(self.len),
        ))
    }
}

impl ZipIndex {
    /// Opens an archive of `archive_len` bytes with a blocking
    /// `read(offset, buf)`, which must fill `buf` from the archive at
    /// `offset`. Each read is at most 16 MiB.
    ///
    /// Errors come back as `E`: whatever `read` returns, or the archive's
    /// [`ZipReadError`] converted (`std::io::Error` converts).
    pub fn open<E: From<ZipReadError>>(
        archive_len: u64,
        mut read: impl FnMut(u64, &mut [u8]) -> std::result::Result<(), E>,
    ) -> std::result::Result<Self, E> {
        let mut opener = ZipIndexOpener::new(archive_len);
        while let Some(range) = opener.next_read()? {
            let mut buf = vec![0; (range.end - range.start) as usize];
            read(range.start, &mut buf)?;
            opener.supply(range.start, &buf)?;
        }
        Ok(opener.finish()?)
    }

    /// The archive's length, as given when opening.
    pub fn archive_len(&self) -> u64 {
        self.len
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

    /// The archive comment, lossily decoded.
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
    pub fn by_name(&self, name: &str) -> Option<&ZipEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Whether an entry with this exact name exists.
    pub fn contains(&self, name: &str) -> bool {
        self.by_name(name).is_some()
    }

    /// The first read toward `entry`'s data: its fixed 30-byte local header
    /// (shorter only where the archive ends). Its bytes go to
    /// [`entry_range`](Self::entry_range) or
    /// [`password_check_range`](Self::password_check_range).
    pub fn header_range(&self, entry: &ZipEntry) -> Result<Range<u64>> {
        let start = entry.local_header_offset.saturating_add(self.offset_shift);
        if start > self.len {
            return Err(ZipReadError::BadOffset);
        }
        Ok(start..start.saturating_add(LOCAL_HEADER_LEN as u64).min(self.len))
    }

    /// The bytes of `entry` from its local header to the end of its data,
    /// given `header` (the bytes at [`header_range`](Self::header_range)).
    /// Read them and pass them to [`read_entry`](Self::read_entry).
    ///
    /// `EntryTooLarge` for an entry too big to read, before anything else.
    pub fn entry_range(&self, entry: &ZipEntry, header: &[u8]) -> Result<Range<u64>> {
        if entry.uncompressed_size > MAX_INFLATED_SIZE {
            return Err(ZipReadError::EntryTooLarge(entry.uncompressed_size));
        }
        let start = self.header_range(entry)?.start;
        let data_start = local_data_start(header)?;
        let end = start
            .checked_add(data_start)
            .and_then(|v| v.checked_add(entry.compressed_size))
            .ok_or(ZipReadError::BadOffset)?
            .min(self.len);
        // A compressed size no entry within the limit could have.
        if end - start > MAX_ENTRY_SPAN {
            return Err(ZipReadError::EntryTooLarge(entry.compressed_size));
        }
        Ok(start..end)
    }

    /// The bytes [`password_check`](Self::password_check) needs for encrypted
    /// `entry`, given `header` (the bytes at
    /// [`header_range`](Self::header_range)): the local header and the first
    /// 18 bytes of data. `None` when it isn't encrypted or the header is
    /// unreadable.
    pub fn password_check_range(&self, entry: &ZipEntry, header: &[u8]) -> Option<Range<u64>> {
        if !entry.is_encrypted() {
            return None;
        }
        let start = self.header_range(entry).ok()?.start;
        let data_start = local_data_start(header).ok()?;
        let end = start
            .checked_add(data_start)?
            .checked_add(PASSWORD_CHECK_LEN)?
            .min(self.len);
        Some(start..end)
    }

    /// Decompresses `entry` from `bytes`, the archive's bytes at
    /// [`entry_range`](Self::entry_range).
    pub fn read_entry(&self, entry: &ZipEntry, bytes: &[u8]) -> Result<Vec<u8>> {
        self.read_entry_with_password(entry, bytes, None)
    }

    /// Decompresses `entry` from `bytes` (the archive's bytes at
    /// [`entry_range`](Self::entry_range)), decrypting with `password` when
    /// encrypted.
    pub fn read_entry_with_password(
        &self,
        entry: &ZipEntry,
        bytes: &[u8],
        password: Option<&str>,
    ) -> Result<Vec<u8>> {
        if entry.uncompressed_size > MAX_INFLATED_SIZE {
            return Err(ZipReadError::EntryTooLarge(entry.uncompressed_size));
        }
        read_local_entry(bytes, 0, entry, password)
    }

    /// The [`PasswordCheck`] for `entry` from `bytes`, the archive's bytes at
    /// [`password_check_range`](Self::password_check_range).
    pub fn password_check(&self, entry: &ZipEntry, bytes: &[u8]) -> Option<PasswordCheck> {
        if !entry.is_encrypted() {
            return None;
        }
        local_password_check(bytes, 0, entry)
    }

    /// Reads and decompresses `entry` with a blocking `read(offset, buf)`
    /// (see [`open`](Self::open)): two reads, its local header and then the
    /// entry itself, decrypting with `password` when encrypted.
    pub fn fetch_entry<E: From<ZipReadError>>(
        &self,
        entry: &ZipEntry,
        password: Option<&str>,
        mut read: impl FnMut(u64, &mut [u8]) -> std::result::Result<(), E>,
    ) -> std::result::Result<Vec<u8>, E> {
        if entry.uncompressed_size > MAX_INFLATED_SIZE {
            return Err(ZipReadError::EntryTooLarge(entry.uncompressed_size).into());
        }
        let too_large = ZipReadError::EntryTooLarge(entry.compressed_size);
        let header = read_range(self.header_range(entry)?, &mut read, too_large.clone())?;
        let range = self.entry_range(entry, &header)?;
        let bytes = read_range(range, &mut read, too_large)?;
        Ok(self.read_entry_with_password(entry, &bytes, password)?)
    }

    /// The [`PasswordCheck`] for `entry` with a blocking `read(offset, buf)`
    /// (see [`open`](Self::open)): `None` without a read when it isn't
    /// encrypted, otherwise two small reads.
    pub fn fetch_password_check<E: From<ZipReadError>>(
        &self,
        entry: &ZipEntry,
        mut read: impl FnMut(u64, &mut [u8]) -> std::result::Result<(), E>,
    ) -> std::result::Result<Option<PasswordCheck>, E> {
        if !entry.is_encrypted() {
            return Ok(None);
        }
        let Ok(range) = self.header_range(entry) else {
            return Ok(None);
        };
        let too_large = ZipReadError::EntryTooLarge(entry.compressed_size);
        let header = read_range(range, &mut read, too_large.clone())?;
        let Some(range) = self.password_check_range(entry, &header) else {
            return Ok(None);
        };
        let bytes = read_range(range, &mut read, too_large)?;
        Ok(self.password_check(entry, &bytes))
    }
}

/// Reads `range` with `read` into a new buffer, failing with `too_large`
/// rather than aborting when the buffer can't be allocated.
fn read_range<E: From<ZipReadError>>(
    range: Range<u64>,
    read: &mut impl FnMut(u64, &mut [u8]) -> std::result::Result<(), E>,
    too_large: ZipReadError,
) -> std::result::Result<Vec<u8>, E> {
    let n = usize::try_from(range.end - range.start).map_err(|_| too_large.clone())?;
    let mut buf = Vec::new();
    buf.try_reserve_exact(n).map_err(|_| too_large)?;
    buf.resize(n, 0);
    read(range.start, &mut buf)?;
    Ok(buf)
}

/// Where an entry's data starts, from the start of its local header, given
/// the header's fixed 30 bytes; the same checks, in the same order, as
/// reading it in memory.
fn local_data_start(header: &[u8]) -> Result<u64> {
    if u32_at(header, 0)? != LOCAL_HEADER_SIG {
        return Err(ZipReadError::BadSignature);
    }
    let name_len = u64::from(u16_at(header, 26)?);
    let extra_len = u64::from(u16_at(header, 28)?);
    Ok(LOCAL_HEADER_LEN as u64 + name_len + extra_len)
}

impl From<ZipReadError> for std::io::Error {
    fn from(e: ZipReadError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An archive of `n` empty stored entries named by `name`.
    fn archive(n: usize, name: impl Fn(usize) -> String) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for i in 0..n {
            let name = name(i);
            let offset = out.len() as u32;
            out.extend_from_slice(&LOCAL_HEADER_SIG.to_le_bytes());
            out.extend_from_slice(&[20, 0, 0, 0, 0, 0]); // needed, flags, method
            out.extend_from_slice(&[0; 16]); // time, date, crc, sizes
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&[0, 0]); // extra
            out.extend_from_slice(name.as_bytes());
            central.extend_from_slice(&CENTRAL_HEADER_SIG.to_le_bytes());
            central.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0]); // made by, needed, flags, method
            central.extend_from_slice(&[0; 16]); // time, date, crc, sizes
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&[0; 12]); // extra, comment, disk, attributes
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_offset = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(&EOCD_SIG.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(n as u16).to_le_bytes());
        out.extend_from_slice(&(n as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out
    }

    #[test]
    fn a_big_directory_is_parsed_once_and_not_held_twice() {
        // 60,000 entries with 300-byte names: about 21 MB of directory. Only
        // the first 64 KiB of each read is supplied, so it arrives in over
        // 300 pieces; parsing it again on every one would take minutes.
        let data = archive(60_000, |i| format!("{i:0>300}"));
        let mut opener = ZipIndexOpener::new(data.len() as u64);
        let (mut reads, mut parsed) = (0, 0);
        while let Some(range) = opener.next_read().expect("next read") {
            reads += 1;
            if let Some(walk) = &opener.walk {
                assert!(walk.entries.len() >= parsed);
                parsed = walk.entries.len();
                // What's held is the tail and less than one header of the
                // directory: the rest is parsed and dropped.
                let held: u64 = opener.held.iter().map(|(_, p)| p.len() as u64).sum();
                assert!(held <= TAIL_LEN + 1024, "{held} bytes held");
            }
            let end = range.end.min(range.start + 65_536);
            let bytes = &data[range.start as usize..end as usize];
            opener.supply(range.start, bytes).expect("supply");
        }
        assert!(reads > 300, "{reads} reads");
        let index = opener.finish().expect("finish");
        assert_eq!(index.len(), 60_000);
        assert_eq!(index.entries()[59_999].name(), format!("{:0>300}", 59_999));
        let memory = ZipReader::new(&data).expect("parse");
        assert_eq!(
            format!("{:?}", memory.entries()),
            format!("{:?}", index.entries())
        );
    }

    #[test]
    fn finishing_early_is_an_error() {
        let data = archive(3, |i| format!("f{i}"));
        let opener = ZipIndexOpener::new(data.len() as u64);
        assert_eq!(
            opener.finish().map(|i| i.len()),
            Err(ZipReadError::Truncated)
        );
    }
}
