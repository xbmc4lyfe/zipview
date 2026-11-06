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

//! The processor's own AES instructions, where it has them.
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
