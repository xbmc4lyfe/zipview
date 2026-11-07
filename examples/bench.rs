//! Times the crate's hot paths.
//!
//! ```text
//! cargo run --release --example bench              # every case
//! cargo run --release --example bench -- aes inflate   # cases whose name contains a word
//! ```
//!
//! Each case runs for a number of rounds and prints the fastest and the median
//! round, so a busy machine skews the median but rarely the fastest. Archives
//! are built in memory by `tests/writer.rs`, the same writer the tests use.

// The writer is also a test file; its tests and their imports go unused here.
#[path = "../tests/writer.rs"]
#[allow(unused_imports)]
mod writer;

use std::hint::black_box;
use std::time::Instant;
use writer::Entry;

/// xorshift64: deterministic, so every machine times the same bytes.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Text that compresses about as well as XML or prose (roughly 3-4x).
fn text(len: usize, seed: u64) -> Vec<u8> {
    const WORDS: &[&str] = &[
        "the",
        "of",
        "and",
        "<w:r>",
        "</w:r>",
        "<w:t>",
        "</w:t>",
        "document",
        "property",
        "xml:space=\"preserve\"",
        "metadata",
        "title",
        "creator",
        "2026-11-06T12:00:00Z",
        "paragraph",
        "style",
        "font",
        "size",
        "colour",
        "table",
        "row",
        "cell",
        "value",
        "zipview",
        "archive",
        "entry",
        "central",
        "directory",
        "local",
        "header",
        "inflate",
    ];
    let mut rng = Rng(seed);
    let mut out = Vec::with_capacity(len + 32);
    while out.len() < len {
        let r = rng.next();
        out.extend_from_slice(WORDS[(r % WORDS.len() as u64) as usize].as_bytes());
        out.push(if r >> 60 == 0 { b'\n' } else { b' ' });
        if r >> 56 == 1 {
            out.extend_from_slice(format!("{}", r >> 40).as_bytes());
        }
    }
    out.truncate(len);
    out
}

fn random(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng(seed);
    (0..len).map(|_| (rng.next() >> 32) as u8).collect()
}

/// Runs `f` (which returns how many bytes it handled) for `rounds` rounds of
/// `iters` calls and prints the fastest and median time per call.
fn case(name: &str, rounds: usize, iters: usize, mut f: impl FnMut() -> usize) {
    let filters: Vec<String> = std::env::args().skip(1).collect();
    if !filters.is_empty() && !filters.iter().any(|w| name.contains(w.as_str())) {
        return;
    }
    let mut bytes = f(); // warm-up
    let mut times = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let t0 = Instant::now();
        for _ in 0..iters {
            bytes = black_box(f());
        }
        times.push(t0.elapsed().as_secs_f64() / iters as f64);
    }
    times.sort_by(f64::total_cmp);
    let (best, median) = (times[0], times[rounds / 2]);
    let rate = if bytes > 0 {
        format!("{:9.1} MB/s", bytes as f64 / best / 1e6)
    } else {
        String::new()
    };
    println!(
        "{name:<18} best {:10.3} us  median {:10.3} us {rate}",
        best * 1e6,
        median * 1e6
    );
}

/// The check byte a ZipCrypto header decrypts to under `password`.
fn crypto_check_byte(password: &str, header: &[u8; 12]) -> u8 {
    (0..=255u8)
        .find(|&c| zipview::decrypt_zipcrypto(password, c, header).is_some())
        .expect("one check byte matches")
}

fn main() {
    let rounds: usize = std::env::var("ROUNDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(15);

    // Inflate: one big text entry, and many small XML-sized parts.
    let big = text(16 << 20, 1);
    let arc = writer::build(&[Entry::deflated("big.txt", &big)], "");
    let zip = zipview::ZipReader::new(&arc).unwrap();
    let e = zip.by_name("big.txt").unwrap();
    case("inflate-16M", rounds, 1, || {
        zip.read_entry(e).unwrap().len()
    });

    let parts: Vec<Vec<u8>> = (0..2000)
        .map(|i| text(4096 + i % 1024, 10 + i as u64))
        .collect();
    let names: Vec<String> = (0..parts.len())
        .map(|i| format!("word/part{i}.xml"))
        .collect();
    let entries: Vec<Entry<'_>> = names
        .iter()
        .zip(&parts)
        .map(|(n, b)| Entry::deflated(n, b))
        .collect();
    let arc_small = writer::build(&entries, "");
    let zip_small = zipview::ZipReader::new(&arc_small).unwrap();
    case("inflate-2000x4K", rounds, 1, || {
        zip_small
            .entries()
            .iter()
            .map(|e| zip_small.read_entry(e).unwrap().len())
            .sum()
    });

    let noise = random(16 << 20, 2);
    let arc_stored = writer::build(&[Entry::stored("noise.bin", &noise)], "");
    let zip_stored = zipview::ZipReader::new(&arc_stored).unwrap();
    let e = zip_stored.by_name("noise.bin").unwrap();
    case("stored-16M", rounds, 1, || {
        zip_stored.read_entry(e).unwrap().len()
    });

    // Opening: a big directory, then name lookups.
    let empty: Vec<String> = (0..20_000)
        .map(|i| format!("res/drawable/icon_{i:05}.png"))
        .collect();
    let entries: Vec<Entry<'_>> = empty.iter().map(|n| Entry::stored(n, b"")).collect();
    let arc_dir = writer::build(&entries, "");
    case("open-20000", rounds, 3, || {
        zipview::ZipReader::new(&arc_dir).unwrap().len()
    });
    // The same directory through byte ranges, served from memory.
    let read = |offset: u64, buf: &mut [u8]| -> Result<(), zipview::ZipReadError> {
        let start = offset as usize;
        buf.copy_from_slice(&arc_dir[start..start + buf.len()]);
        Ok(())
    };
    case("index-open-20000", rounds, 3, || {
        zipview::ZipIndex::open(arc_dir.len() as u64, read)
            .unwrap()
            .len()
    });
    let zip_dir = zipview::ZipReader::new(&arc_dir).unwrap();
    case("by_name-100", rounds, 3, || {
        (0..100)
            .filter(|i| zip_dir.contains(&empty[i * 197]))
            .count()
    });

    // ZipCrypto.
    let sealed = random(8 << 20, 3);
    let header: [u8; 12] = sealed[..12].try_into().unwrap();
    let check = crypto_check_byte("secret", &header);
    case("zipcrypto-8M", rounds, 1, || {
        zipview::decrypt_zipcrypto("secret", check, &sealed)
            .unwrap()
            .len()
    });
    let crypto = zipview::PasswordCheck::Crypto { header, check };
    case("zipcrypto-accepts", rounds, 2000, || {
        usize::from(crypto.accepts("wrong!"))
    });

    // WinZip AES: CTR decryption, key derivation and the password check.
    let key128 = random(16, 4);
    let key256 = random(32, 5);
    case("aes128-ctr-8M", rounds, 1, || {
        zipview::decrypt_winzip_ctr(&key128, &sealed).unwrap().len()
    });
    case("aes256-ctr-8M", rounds, 1, || {
        zipview::decrypt_winzip_ctr(&key256, &sealed).unwrap().len()
    });
    let salt: [u8; 16] = random(16, 6).try_into().unwrap();
    case("aes-derive-256", rounds, 5, || {
        black_box(zipview::aes_derive(b"secret", &salt, 32).unwrap());
        0
    });
    let aes = zipview::PasswordCheck::Aes {
        strength: 3,
        salt,
        verifier: [0, 0],
    };
    case("aes256-accepts", rounds, 5, || {
        black_box(aes.accepts("wrong!"));
        0
    });
    let aes128 = zipview::PasswordCheck::Aes {
        strength: 1,
        salt,
        verifier: [0, 0],
    };
    case("aes128-accepts", rounds, 5, || {
        black_box(aes128.accepts("wrong!"));
        0
    });

    // A whole AES-256 entry: derive, verify, decrypt (Stored inside).
    let derived = zipview::aes_derive(b"secret", &salt, 32).unwrap();
    let plain = text(1 << 20, 7);
    let mut payload = salt.to_vec();
    payload.extend_from_slice(&derived[64..66]);
    payload.extend_from_slice(&zipview::decrypt_winzip_ctr(&derived[..32], &plain).unwrap());
    payload.extend_from_slice(&[0u8; 10]);
    let full = Some(payload.len() as u64);
    case("aes256-entry-1M", rounds, 2, || {
        zipview::decrypt_winzip_aes("secret", 3, &payload, full)
            .unwrap()
            .len()
    });
}
