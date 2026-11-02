# Contributing

## The one rule that matters

ZIP is a hostile format and this reader is the only thing between a caller and
it. **A malformed archive must produce `Err`, never a panic and never a wrong
value.** In that order of preference:

1. Correct value
2. `Err`
3. *(nothing)*
4. A plausible wrong value ← never this

Point 4 is not theoretical here. The prefix bug described in the README
returned an empty archive rather than an error, and read as success.

## Before you push

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

New parsing paths want a fuzz run too — minutes, not hours, is usually enough to
catch an indexing mistake:

```bash
python3 fuzz/gen_seeds.py && mkdir -p fuzz/corpus/fuzz_zip
PATH="$HOME/.cargo/bin:$PATH" RUSTUP_TOOLCHAIN=nightly \
  cargo fuzz run fuzz_zip fuzz/corpus/fuzz_zip fuzz/seeds -- -max_total_time=120
```

## Adding a field

Read it from the **central directory**, not the local header. Local headers are
zeroed for streamed entries, with the real values in a data descriptor after the
payload. Use the `u16_at` / `u32_at` / `u64_at` helpers so the read is
bounds-checked, and `offset_to_index` for anything that becomes a buffer index —
that function exists so every archive-supplied offset is validated in one place.

## Adding a compression method

Decompression needs a size-capped reader, like `inflate`. The cap is what makes
a zip bomb harmless, so a method added without one is a regression even if it
works.

Note that `compression_name()` already names methods the crate cannot
decompress, on purpose: an entry's metadata is still correct and complete when
its bytes are unreadable.

## No dependencies

Not even dev-dependencies. `cargo audit` reads those too, and the crate's whole
argument is that there is nothing to audit. Fixtures go in `tests/writer.rs`,
which writes archives by hand.

The writer deliberately duplicates the ZIP signature constants instead of
importing them from the reader. A shared constant means a round-trip test cannot
notice that the constant is wrong.

## License of contributions

By submitting a change you agree it is licensed GPL-3.0, the same as the rest
of the crate. New source files should carry the notice at the top of
`src/lib.rs`.
