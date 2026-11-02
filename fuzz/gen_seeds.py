#!/usr/bin/env python3
"""Generate seed archives for fuzz_zip.

Without seeds the fuzzer is nearly useless here: random bytes almost never
contain a valid end-of-central-directory signature, so it bails at the first
check and never reaches the parser. A 181-second run managed 437,933
executions at 30 edges covered -- almost all of them "not a zip, return".

These seeds are valid (or near-valid) archives, so libFuzzer starts inside the
parser and mutates from there. Python rather than Rust so no writer has to be
shipped in the crate or duplicated for a third time.
"""
import pathlib, struct, zlib

OUT = pathlib.Path(__file__).parent / "seeds"
LOCAL, CENTRAL, EOCD = 0x04034B50, 0x02014B50, 0x06054B50


def archive(entries, comment=b"", prefix=b""):
    """entries: list of (name, body, method) where method is 0 or 8."""
    out = bytearray(prefix)
    centrals = []
    for name, body, method in entries:
        n = name.encode()
        payload = zlib.compressobj(9, zlib.DEFLATED, -15).compress(body) + \
            zlib.compressobj(9, zlib.DEFLATED, -15).flush() if False else (
                body if method == 0 else _deflate(body))
        off = len(out)
        out += struct.pack("<IHHHHHIIIHH", LOCAL, 20, 0x0800, method, 0, 0x2821,
                           zlib.crc32(body) & 0xFFFFFFFF, len(payload), len(body),
                           len(n), 0) + n + payload
        centrals.append((n, method, zlib.crc32(body) & 0xFFFFFFFF,
                         len(payload), len(body), off))
    cd_off = len(out)
    for n, method, crc, clen, ulen, off in centrals:
        out += struct.pack("<IHHHHHHIIIHHHHHII", CENTRAL, 0x031E, 20, 0x0800,
                           method, 0, 0x2821, crc, clen, ulen, len(n), 0, 0, 0, 0,
                           0o100644 << 16, off) + n
    cd_len = len(out) - cd_off
    out += struct.pack("<IHHHHIIH", EOCD, 0, 0, len(centrals), len(centrals),
                       cd_len, cd_off, len(comment)) + comment
    return bytes(out)


def _deflate(data):
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def main():
    OUT.mkdir(exist_ok=True)
    seeds = {
        # Smallest valid archive: EOCD only.
        "empty.zip": struct.pack("<IHHHHIIH", EOCD, 0, 0, 0, 0, 0, 0, 0),
        "stored.zip": archive([("a.txt", b"hello world", 0)]),
        "deflated.zip": archive([("doc.xml", b"<x>" + b"y" * 4000 + b"</x>", 8)]),
        "empty-entry.zip": archive([("e", b"", 8)]),
        # OOXML shape: the real workload.
        "ooxml.zip": archive([
            ("[Content_Types].xml", b"<Types/>", 0),
            ("docProps/core.xml", b"<cp:coreProperties/>", 8),
            ("word/document.xml", b"<w:document/>", 8),
        ]),
        "directories.zip": archive([("d/", b"", 0), ("d/f.txt", b"c", 8)]),
        "comment.zip": archive([("a", b"x", 0)], comment=b"a trailing comment"),
        # Self-extracting: the shape that produced a silent zero-entry read.
        "sfx-prefix.zip": archive([("a.txt", b"payload", 8)],
                                  prefix=b"#!/bin/sh\nexit 0\n"),
        "unicode.zip": archive([("日本語.txt", b"nihongo", 8)]),
        # A method the reader cannot decompress: must still enumerate.
        "zstd-method.zip": archive([("a.txt", b"x", 93)]),
        "many.zip": archive([(f"d{i % 7}/f{i}.xml", f"<n>{i}</n>".encode(), 8)
                             for i in range(40)]),
    }
    for name, data in seeds.items():
        (OUT / name).write_bytes(data)
    print(f"wrote {len(seeds)} seeds to {OUT}")


if __name__ == "__main__":
    main()
