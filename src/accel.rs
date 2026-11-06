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

//! The processor's own AES and SHA-1 instructions, where it has them.
//!
//! This is the crate's only `unsafe`: calling an instruction the compiler
//! cannot assume the processor has, and reading and writing whole 16-byte
//! words of a buffer. Every entry point checks for the instructions at run
//! time and returns `false` without them, so the caller falls back to the
//! portable code, which the tests hold to the same reference.

/// XORs `data` with the WinZip AES-CTR keystream, whose little-endian counter
/// starts at one, under the expanded key `rk` of `nr` rounds, using the
/// processor's AES instructions. `false`, with `data` untouched, when it has
/// none.
pub(crate) fn aes_ctr_xor(rk: &[u32; 60], nr: usize, data: &mut [u8]) -> bool {
    imp::aes_ctr_xor(rk, nr, data)
}

/// The round keys as the 16-byte blocks the instructions take: each round's
/// four big-endian words in order.
#[cfg_attr(
    not(any(target_arch = "aarch64", target_arch = "x86_64")),
    allow(dead_code)
)]
fn key_bytes(rk: &[u32; 60]) -> [[u8; 16]; 15] {
    let mut out = [[0u8; 16]; 15];
    for (block, words) in out.iter_mut().zip(rk.chunks_exact(4)) {
        for (bytes, w) in block.chunks_exact_mut(4).zip(words) {
            bytes.copy_from_slice(&w.to_be_bytes());
        }
    }
    out
}

/// How many counter blocks go through the rounds together. An AES round
/// instruction takes a few cycles to finish but a new one can start every
/// cycle, so eight independent blocks keep the unit busy.
#[cfg_attr(
    not(any(target_arch = "aarch64", target_arch = "x86_64")),
    allow(dead_code)
)]
const LANES: usize = 8;

#[cfg(target_arch = "aarch64")]
mod imp {
    use super::{LANES, key_bytes};
    use std::arch::aarch64::*;

    pub(super) fn aes_ctr_xor(rk: &[u32; 60], nr: usize, data: &mut [u8]) -> bool {
        if !std::arch::is_aarch64_feature_detected!("aes") {
            return false;
        }
        let keys = key_bytes(rk);
        // SAFETY: the processor has the AES instructions (checked above), and
        // NEON is part of every 64-bit ARM processor
        unsafe {
            match nr {
                10 => run::<10>(&keys, data),
                12 => run::<12>(&keys, data),
                _ => run::<14>(&keys, data),
            }
        }
        true
    }

    /// `AESE` is AddRoundKey, SubBytes and ShiftRows, and `AESMC` is
    /// MixColumns, so a round is the pair; the last round has no MixColumns
    /// and adds the final key on its own.
    #[target_feature(enable = "aes,neon")]
    unsafe fn run<const NR: usize>(keys: &[[u8; 16]; 15], data: &mut [u8]) {
        let rk: [uint8x16_t; 15] = std::array::from_fn(|r| {
            // SAFETY: reads the 16 bytes of `keys[r]`
            unsafe { vld1q_u8(keys[r].as_ptr()) }
        });
        let block = |counter: u128| -> uint8x16_t {
            let b = counter.to_le_bytes();
            // SAFETY: reads the 16 bytes of `b`
            unsafe { vld1q_u8(b.as_ptr()) }
        };
        let mut counter = 1u128;
        let mut groups = data.chunks_exact_mut(16 * LANES);
        for group in &mut groups {
            let mut s: [uint8x16_t; LANES] =
                std::array::from_fn(|i| block(counter.wrapping_add(i as u128)));
            counter = counter.wrapping_add(LANES as u128);
            for key in &rk[..NR - 1] {
                for b in &mut s {
                    *b = vaesmcq_u8(vaeseq_u8(*b, *key));
                }
            }
            for (i, b) in s.iter().enumerate() {
                let ks = veorq_u8(vaeseq_u8(*b, rk[NR - 1]), rk[NR]);
                let p = group[16 * i..].as_mut_ptr();
                // SAFETY: `group` holds LANES blocks of 16 bytes, so the 16
                // at `p` are inside it
                unsafe { vst1q_u8(p, veorq_u8(vld1q_u8(p), ks)) };
            }
        }
        for chunk in groups.into_remainder().chunks_mut(16) {
            let mut b = block(counter);
            counter = counter.wrapping_add(1);
            for key in &rk[..NR - 1] {
                b = vaesmcq_u8(vaeseq_u8(b, *key));
            }
            let ks = veorq_u8(vaeseq_u8(b, rk[NR - 1]), rk[NR]);
            let mut bytes = [0u8; 16];
            // SAFETY: writes the 16 bytes of `bytes`
            unsafe { vst1q_u8(bytes.as_mut_ptr(), ks) };
            for (c, k) in chunk.iter_mut().zip(bytes) {
                *c ^= k;
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod imp {
    use super::{LANES, key_bytes};
    use std::arch::x86_64::*;

    pub(super) fn aes_ctr_xor(rk: &[u32; 60], nr: usize, data: &mut [u8]) -> bool {
        if !std::arch::is_x86_feature_detected!("aes") {
            return false;
        }
        let keys = key_bytes(rk);
        // SAFETY: the processor has AES-NI (checked above), and SSE2 is part
        // of every x86-64 processor
        unsafe {
            match nr {
                10 => run::<10>(&keys, data),
                12 => run::<12>(&keys, data),
                _ => run::<14>(&keys, data),
            }
        }
        true
    }

    /// `AESENC` is a whole round (ShiftRows, SubBytes, MixColumns,
    /// AddRoundKey) and `AESENCLAST` the last one, without MixColumns.
    #[target_feature(enable = "aes,sse2")]
    unsafe fn run<const NR: usize>(keys: &[[u8; 16]; 15], data: &mut [u8]) {
        let rk: [__m128i; 15] = std::array::from_fn(|r| {
            // SAFETY: reads the 16 bytes of `keys[r]`; loadu needs no alignment
            unsafe { _mm_loadu_si128(keys[r].as_ptr().cast()) }
        });
        // the counter's low 64 bits are its first eight bytes, as stored
        let block = |counter: u128| _mm_set_epi64x((counter >> 64) as i64, counter as i64);
        let mut counter = 1u128;
        let mut groups = data.chunks_exact_mut(16 * LANES);
        for group in &mut groups {
            let mut s: [__m128i; LANES] = std::array::from_fn(|i| {
                _mm_xor_si128(block(counter.wrapping_add(i as u128)), rk[0])
            });
            counter = counter.wrapping_add(LANES as u128);
            for key in &rk[1..NR] {
                for b in &mut s {
                    *b = _mm_aesenc_si128(*b, *key);
                }
            }
            for (i, b) in s.iter().enumerate() {
                let ks = _mm_aesenclast_si128(*b, rk[NR]);
                let p = group[16 * i..].as_mut_ptr().cast::<__m128i>();
                // SAFETY: `group` holds LANES blocks of 16 bytes, so the 16
                // at `p` are inside it; loadu and storeu need no alignment
                unsafe { _mm_storeu_si128(p, _mm_xor_si128(_mm_loadu_si128(p), ks)) };
            }
        }
        for chunk in groups.into_remainder().chunks_mut(16) {
            let mut b = _mm_xor_si128(block(counter), rk[0]);
            counter = counter.wrapping_add(1);
            for key in &rk[1..NR] {
                b = _mm_aesenc_si128(b, *key);
            }
            let ks = _mm_aesenclast_si128(b, rk[NR]);
            let mut bytes = [0u8; 16];
            // SAFETY: writes the 16 bytes of `bytes`
            unsafe { _mm_storeu_si128(bytes.as_mut_ptr().cast(), ks) };
            for (c, k) in chunk.iter_mut().zip(bytes) {
                *c ^= k;
            }
        }
    }
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
mod imp {
    pub(super) fn aes_ctr_xor(_: &[u32; 60], _: usize, _: &mut [u8]) -> bool {
        false
    }
}

/// The rest of a PBKDF2-HMAC-SHA1 block after its first MAC `u`: the XOR of
/// `u` and the `iterations - 1` MACs chained from it, each the HMAC of the
/// one before under the key whose compressed pads are `inner` and `outer`.
/// Runs on the processor's SHA-1 instructions; `None` when it has none.
pub(crate) fn pbkdf2_sha1_rest(
    inner: [u32; 5],
    outer: [u32; 5],
    u: [u32; 5],
    iterations: u32,
) -> Option<[u32; 5]> {
    sha::pbkdf2_rest(inner, outer, u, iterations)
}

#[cfg(target_arch = "aarch64")]
mod sha {
    use std::arch::aarch64::*;

    pub(super) fn pbkdf2_rest(
        inner: [u32; 5],
        outer: [u32; 5],
        u: [u32; 5],
        iterations: u32,
    ) -> Option<[u32; 5]> {
        // The SHA-1 instructions come under the `sha2` feature.
        if !std::arch::is_aarch64_feature_detected!("sha2") {
            return None;
        }
        // SAFETY: the processor has the SHA-1 instructions (checked above),
        // and NEON is part of every 64-bit ARM processor
        Some(unsafe { rest(inner, outer, u, iterations) })
    }

    #[target_feature(enable = "neon,sha2")]
    fn words(w: [u32; 4]) -> uint32x4_t {
        let v = vsetq_lane_u32::<0>(w[0], vdupq_n_u32(0));
        let v = vsetq_lane_u32::<1>(w[1], v);
        let v = vsetq_lane_u32::<2>(w[2], v);
        vsetq_lane_u32::<3>(w[3], v)
    }

    /// One SHA-1 compression of the block `w` (four vectors of four words)
    /// into the state `abcd`, `e`. `SHA1C`, `SHA1P` and `SHA1M` each do four
    /// rounds with their round function, `SHA1H` gives the `e` for the next
    /// four, and `SHA1SU0`/`SHA1SU1` extend the message schedule four words
    /// at a time.
    #[target_feature(enable = "neon,sha2")]
    #[inline]
    fn compress(abcd0: uint32x4_t, e0: u32, mut w: [uint32x4_t; 4]) -> (uint32x4_t, u32) {
        let (mut abcd, mut e) = (abcd0, e0);
        // Four rounds on schedule vector `$i`, with the round function `$op`.
        macro_rules! rounds {
            ($i:expr, $op:ident, $k:expr) => {
                let wk = vaddq_u32(w[$i % 4], vdupq_n_u32($k));
                let next_e = vsha1h_u32(vgetq_lane_u32::<0>(abcd));
                abcd = $op(abcd, e, wk);
                e = next_e;
            };
        }
        // The same, then schedule vector `$i + 4` in the slot `$i` used.
        macro_rules! rounds_and_schedule {
            ($i:expr, $op:ident, $k:expr) => {
                rounds!($i, $op, $k);
                w[$i % 4] = vsha1su1q_u32(
                    vsha1su0q_u32(w[$i % 4], w[($i + 1) % 4], w[($i + 2) % 4]),
                    w[($i + 3) % 4],
                );
            };
        }
        rounds_and_schedule!(0, vsha1cq_u32, 0x5a82_7999);
        rounds_and_schedule!(1, vsha1cq_u32, 0x5a82_7999);
        rounds_and_schedule!(2, vsha1cq_u32, 0x5a82_7999);
        rounds_and_schedule!(3, vsha1cq_u32, 0x5a82_7999);
        rounds_and_schedule!(4, vsha1cq_u32, 0x5a82_7999);
        rounds_and_schedule!(5, vsha1pq_u32, 0x6ed9_eba1);
        rounds_and_schedule!(6, vsha1pq_u32, 0x6ed9_eba1);
        rounds_and_schedule!(7, vsha1pq_u32, 0x6ed9_eba1);
        rounds_and_schedule!(8, vsha1pq_u32, 0x6ed9_eba1);
        rounds_and_schedule!(9, vsha1pq_u32, 0x6ed9_eba1);
        rounds_and_schedule!(10, vsha1mq_u32, 0x8f1b_bcdc);
        rounds_and_schedule!(11, vsha1mq_u32, 0x8f1b_bcdc);
        rounds_and_schedule!(12, vsha1mq_u32, 0x8f1b_bcdc);
        rounds_and_schedule!(13, vsha1mq_u32, 0x8f1b_bcdc);
        rounds_and_schedule!(14, vsha1mq_u32, 0x8f1b_bcdc);
        rounds_and_schedule!(15, vsha1pq_u32, 0xca62_c1d6);
        rounds!(16, vsha1pq_u32, 0xca62_c1d6);
        rounds!(17, vsha1pq_u32, 0xca62_c1d6);
        rounds!(18, vsha1pq_u32, 0xca62_c1d6);
        rounds!(19, vsha1pq_u32, 0xca62_c1d6);
        (vaddq_u32(abcd, abcd0), e.wrapping_add(e0))
    }

    /// Each iteration hashes a 20-byte digest after a 64-byte key block, so
    /// its block is the digest, the padding bit, zeros and a length of 84
    /// bytes: built in registers, with nothing stored.
    #[target_feature(enable = "neon,sha2")]
    fn rest(inner: [u32; 5], outer: [u32; 5], u: [u32; 5], iterations: u32) -> [u32; 5] {
        let zero = vdupq_n_u32(0);
        let length = vsetq_lane_u32::<3>((64 + 20) * 8, zero);
        let tail = |e: u32| vsetq_lane_u32::<1>(0x8000_0000, vsetq_lane_u32::<0>(e, zero));
        let (ia, ie) = (words([inner[0], inner[1], inner[2], inner[3]]), inner[4]);
        let (oa, oe) = (words([outer[0], outer[1], outer[2], outer[3]]), outer[4]);
        let (mut ua, mut ue) = (words([u[0], u[1], u[2], u[3]]), u[4]);
        let (mut sa, mut se) = (ua, ue);
        for _ in 1..iterations {
            let (ha, he) = compress(ia, ie, [ua, tail(ue), zero, length]);
            (ua, ue) = compress(oa, oe, [ha, tail(he), zero, length]);
            sa = veorq_u32(sa, ua);
            se ^= ue;
        }
        [
            vgetq_lane_u32::<0>(sa),
            vgetq_lane_u32::<1>(sa),
            vgetq_lane_u32::<2>(sa),
            vgetq_lane_u32::<3>(sa),
            se,
        ]
    }
}

#[cfg(target_arch = "x86_64")]
mod sha {
    use std::arch::x86_64::*;

    pub(super) fn pbkdf2_rest(
        inner: [u32; 5],
        outer: [u32; 5],
        u: [u32; 5],
        iterations: u32,
    ) -> Option<[u32; 5]> {
        if !std::arch::is_x86_feature_detected!("sha") {
            return None;
        }
        // SAFETY: the processor has the SHA extensions (checked above), and
        // SSE2 is part of every x86-64 processor
        Some(unsafe { rest(inner, outer, u, iterations) })
    }

    /// Four words in the instructions' order: the first in the top lane.
    #[target_feature(enable = "sha,sse2")]
    fn words(w: [u32; 4]) -> __m128i {
        _mm_set_epi32(w[0] as i32, w[1] as i32, w[2] as i32, w[3] as i32)
    }

    /// Lane `N` of `v`, counted from the bottom.
    #[target_feature(enable = "sha,sse2")]
    fn lane<const N: i32>(v: __m128i) -> u32 {
        _mm_cvtsi128_si32(_mm_shuffle_epi32::<N>(v)) as u32
    }

    /// One SHA-1 compression of the block `w` (four vectors of four words)
    /// into the state `abcd`, with `e` in the top lane of its own vector.
    /// `SHA1RNDS4` does four rounds, its immediate picking the round function
    /// and constant. It takes `e` added to the first of the four words, which
    /// `SHA1NEXTE` does: the `e` four rounds on is the `a` from before them,
    /// rotated. `SHA1MSG1`, a XOR and `SHA1MSG2` extend the message schedule
    /// four words at a time.
    #[target_feature(enable = "sha,sse2")]
    #[inline]
    fn compress(abcd0: __m128i, e0: __m128i, mut w: [__m128i; 4]) -> (__m128i, __m128i) {
        let mut abcd = abcd0;
        // `abcd` before the last four rounds, whose `a` gives the next `e`
        let mut before = abcd0;
        // Four rounds on schedule vector `$i`, with round function `$f`.
        macro_rules! rounds {
            ($i:expr, $f:expr) => {
                let wk = if $i == 0 {
                    _mm_add_epi32(e0, w[0])
                } else {
                    _mm_sha1nexte_epu32(before, w[$i % 4])
                };
                before = abcd;
                abcd = _mm_sha1rnds4_epu32::<$f>(abcd, wk);
            };
        }
        // The same, then schedule vector `$i + 4` in the slot `$i` used.
        macro_rules! rounds_and_schedule {
            ($i:expr, $f:expr) => {
                rounds!($i, $f);
                w[$i % 4] = _mm_sha1msg2_epu32(
                    _mm_xor_si128(
                        _mm_sha1msg1_epu32(w[$i % 4], w[($i + 1) % 4]),
                        w[($i + 2) % 4],
                    ),
                    w[($i + 3) % 4],
                );
            };
        }
        rounds_and_schedule!(0, 0);
        rounds_and_schedule!(1, 0);
        rounds_and_schedule!(2, 0);
        rounds_and_schedule!(3, 0);
        rounds_and_schedule!(4, 0);
        rounds_and_schedule!(5, 1);
        rounds_and_schedule!(6, 1);
        rounds_and_schedule!(7, 1);
        rounds_and_schedule!(8, 1);
        rounds_and_schedule!(9, 1);
        rounds_and_schedule!(10, 2);
        rounds_and_schedule!(11, 2);
        rounds_and_schedule!(12, 2);
        rounds_and_schedule!(13, 2);
        rounds_and_schedule!(14, 2);
        rounds_and_schedule!(15, 3);
        rounds!(16, 3);
        rounds!(17, 3);
        rounds!(18, 3);
        rounds!(19, 3);
        (_mm_add_epi32(abcd, abcd0), _mm_sha1nexte_epu32(before, e0))
    }

    /// Each iteration hashes a 20-byte digest after a 64-byte key block, so
    /// its block is the digest, the padding bit, zeros and a length of 84
    /// bytes. A digest's `e` vector is its fifth word with zeros below, so
    /// the block's second vector is that vector with the padding bit added:
    /// built in registers, with nothing stored.
    #[target_feature(enable = "sha,sse2")]
    fn rest(inner: [u32; 5], outer: [u32; 5], u: [u32; 5], iterations: u32) -> [u32; 5] {
        let zero = _mm_setzero_si128();
        let length = words([0, 0, 0, (64 + 20) * 8]);
        let padding = words([0, 0x8000_0000, 0, 0]);
        let state = |s: [u32; 5]| (words([s[0], s[1], s[2], s[3]]), words([s[4], 0, 0, 0]));
        let (ia, ie) = state(inner);
        let (oa, oe) = state(outer);
        let (mut ua, mut ue) = state(u);
        let (mut sa, mut se) = (ua, ue);
        for _ in 1..iterations {
            let (ha, he) = compress(ia, ie, [ua, _mm_or_si128(ue, padding), zero, length]);
            (ua, ue) = compress(oa, oe, [ha, _mm_or_si128(he, padding), zero, length]);
            sa = _mm_xor_si128(sa, ua);
            se = _mm_xor_si128(se, ue);
        }
        [
            lane::<3>(sa),
            lane::<2>(sa),
            lane::<1>(sa),
            lane::<0>(sa),
            lane::<3>(se),
        ]
    }
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
mod sha {
    pub(super) fn pbkdf2_rest(_: [u32; 5], _: [u32; 5], _: [u32; 5], _: u32) -> Option<[u32; 5]> {
        None
    }
}
