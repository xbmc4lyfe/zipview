# zipview

Read-only ZIP container reader for Rust. Opens an in-memory archive, lists its
entries, inflates the ones you ask for. That is all it does.

It **cannot** write an archive, extract to disk, decrypt, or touch the
filesystem. That is the point.

```rust
let archive = zipview::ZipReader::new(bytes)?;

for entry in archive.entries() {
    println!("{} — {} bytes, {}", entry.name(), entry.size(), entry.compression_name());
}

let xml = archive.read_to_string("docProps/core.xml")?;
```

## Why

Written to replace the `zip` crate in a metadata tool that needed about five
percent of what it does — open an archive, find an entry by name, inflate a few
small XML members — and was inheriting its whole dependency tree for the
privilege. Removing it dropped **27 crates** from that project's lockfile,
including an AES/cipher stack and three `zstd` crates it never used.

Seven RUSTSEC advisories went with them:

| Advisories | What they were |
|---|---|
| RUSTSEC-2026-0367/0368/0369 | SUID/SGID preservation, symlink escape, permissions through symlinks — all in `ZipArchive::extract` |
| RUSTSEC-2026-0391/0398/0403/0410 | `zstd`, `zstd-safe`, `zstd-sys`, transitive, only so Zstd entries could be decompressed |

The first three are the interesting part. A reader that **cannot extract** makes
that class of bug *inapplicable by construction* rather than patched, which is a
stronger property than being up to date. The rest left with the crate that
wanted them.

## When not to use this

Use [`zip`](https://crates.io/crates/zip) if you need to write archives, extract
files, decrypt, or decompress beyond Stored and Deflate. It is a good crate; it
is just much more crate than a metadata reader needs.

This is for reading metadata out of ZIP containers — OOXML (`.docx`/`.xlsx`/
`.pptx`), EPUB, iWork, ODF, JAR, APK.

### Unsupported methods still enumerate

Only Stored and Deflate are decompressed. An entry in any other method is still
**fully enumerated** — name, sizes, CRC, timestamp, mode, method name — and only
reading its bytes fails. Metadata about a Zstd or LZMA entry is still correct and
complete.

## Design

One dependency: `flate2`. Reimplementing inflate would be a bad trade — it is
the one part of this problem where a subtle bug is both likely and hard to find.
It runs on the `zlib-rs` backend, a Rust port of zlib, for speed: it inflates
2.3–2.6× faster than flate2's default `miniz_oxide` on Apple M4/M5 cores.

Every field is read through bounds-checked helpers, so a truncated or hostile
archive yields `Err`, never a panic. Parsing has no `unsafe`. The crate's only
`unsafe` is in `src/accel.rs`, which runs the processor's AES instructions
(ARMv8 AES, x86 AES-NI) after checking for them at run time; without them the
portable table-driven code runs, and the tests hold both to the same reference.
`zlib-rs` uses `unsafe` internally for its SIMD paths too.

- **The central directory is the only source of sizes and offsets.** Local
  headers are checked for their signature and nothing else: a streamed entry
  writes zeros there and defers the real values to a data descriptor after the
  payload, so trusting them is wrong.
- **Inflation is capped at the declared size.** A zip bomb that lies about its
  size errors instead of allocating unboundedly. A stream that inflates to a
  *different* size than declared also errors — a silently short XML document
  parses into wrong values, which is worse than no values.
- **The declared entry count is a hint, not a promise.** It is clamped against
  what the buffer could hold, since each central directory header needs ≥46
  bytes.
- **Self-extracting archives work.** A stub before the first local header shifts
  every offset the central directory records; the shift is derived, not assumed.

## Testing

No dev-dependencies. The whole point is having nothing worth auditing, and
`cargo audit` reads dev-dependencies too — a ZIP writer pulled in for fixtures
would undo that. `tests/writer.rs` builds archives byte by byte instead, and
duplicates the four ZIP signatures rather than importing them from the reader,
so a round-trip cannot pass by sharing a wrong constant.

Beyond the usual cases, the suite sweeps **every truncation** of a valid archive
and **flips every single byte**, asserting only that nothing panics.

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

### Fuzzing

```bash
python3 fuzz/gen_seeds.py            # valid archives to start from
cargo run --example seedcheck        # confirm they are actually valid
mkdir -p fuzz/corpus/fuzz_zip
cargo +nightly fuzz run fuzz_zip fuzz/corpus/fuzz_zip fuzz/seeds
```

The target both lists *and reads* every entry, because a reader that parsed
headers safely but trusted the payload offset would pass an enumeration-only
target.

The corpus directory comes **first** and the seeds second: libFuzzer writes
new inputs to the first directory it is given and treats the rest as read-only.
Passing `fuzz/seeds` first makes the run mutate the curated seeds in place.

**Pass the seeds.** Unseeded, this target is close to useless: random bytes
almost never contain a valid end-of-central-directory signature, so the fuzzer
bails at the first check and never reaches the parser. A measured 181-second
unseeded run managed 437,933 executions at **30 edges covered** — almost all of
them "not a zip, return". The seeds are valid archives, including the
self-extracting prefix and an entry in a method the reader cannot decompress,
so mutation starts inside the parser.

The seeds are generated by `fuzz/gen_seeds.py` rather than by
`tests/writer.rs`, deliberately: a second independent implementation of the
format is a cross-check, where reusing the Rust writer would only confirm it
agrees with itself.

> If `cargo fuzz` reports `error: 1 nightly option were parsed`, your `cargo` on
> `PATH` is not rustup's shim (Homebrew installs its own). cargo-fuzz spawns a
> bare `cargo`, so:
> `PATH="$HOME/.cargo/bin:$PATH" RUSTUP_TOOLCHAIN=nightly cargo fuzz run fuzz_zip`

## A note on how the prefix bug was found

The reader originally treated the end-of-central-directory's offset as absolute.
For a self-extracting archive that is wrong, and the result was **zero entries,
silently** — no error, no panic, just an empty archive.

Nothing in the code looked wrong. It was caught by differential testing against
the `zip` crate, which proved the reader correct before that dependency was
dropped. That test could not be kept (it would have kept the advisories in
`cargo audit`), so the round-trip tests and the fuzz target stand in its place.
Worth knowing if you extend the parsing: the failure mode here is silence.

## Status

Early. The API is small and unlikely to churn much, but it has not been through
a release.

## License

GPL-3.0. See [LICENSE](LICENSE).

Copyleft is deliberate here, so the practical consequence is worth stating
plainly rather than discovering later: linking this crate into a distributed
binary makes that binary's terms GPL-3.0 as well. That is fine for a GPL tool —
which is where it came from — and a blocker for a permissively licensed one.

If you need a read-only ZIP reader under permissive terms, the format is
documented in [APPNOTE.TXT][appnote] and this crate is about 600 lines; it is a
weekend, not a dependency. The parts that are easy to get wrong are written
down in [CONTRIBUTING.md](CONTRIBUTING.md) and in the module docs, and both
describe the self-extracting-prefix bug in enough detail to avoid repeating it.

[appnote]: https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
