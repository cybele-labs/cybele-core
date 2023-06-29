use std::ops::Shr;

/// Compute the SHA-256 hash of the given message, without making any heap allocation.
/// Specification can be found here: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
pub fn sha256(message: &[u8]) -> [u8; 32] {
    let message_bytes_count = message.len();
    let message_bits_count = 8 * message_bytes_count;
    if message_bytes_count >= (2 << 61) {
        panic!("cannot hash messages containing more than 2^64 bits");
    }

    // The message is padded to be a multiple of 64 bytes:
    //  - start with a '1' bit followed by '0' bits
    //  - end with the message bit size encoded using 64 bits (big-endian)
    // Notes:
    //  - we must use rem_euclid because rust's % doesn't work on negative integers
    //  - the padding may use up to 72 bytes (for messages that are `64 * n + 56` bytes long)
    let pad_len = ((((448i64 - (message_bits_count as i64) - 1).rem_euclid(512)) + 1) / 8) as usize;

    // SHA-256 constants.
    #[rustfmt::skip]
    let k256: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    // Initialize intermediate hash values.
    let mut h0: u32 = 0x6a09e667;
    let mut h1: u32 = 0xbb67ae85;
    let mut h2: u32 = 0x3c6ef372;
    let mut h3: u32 = 0xa54ff53a;
    let mut h4: u32 = 0x510e527f;
    let mut h5: u32 = 0x9b05688c;
    let mut h6: u32 = 0x1f83d9ab;
    let mut h7: u32 = 0x5be0cd19;

    // Initialize message schedule.
    let mut w = [0u32; 64];

    // Then process the message with its padding as 64-bytes blocks.
    let blocks_count = (message_bytes_count + pad_len + 8) / 64;
    for i in 0..blocks_count {
        // Parse the message block into 16 4-bytes words.
        for j in 0..16 {
            w[j] = 0;
            for k in 0..4 {
                let index = 64 * i + 4 * j + k;
                if index < message_bytes_count {
                    w[j] = w[j].wrapping_add((message[index] as u32) << (8 * (3 - k)));
                } else if index == message_bytes_count {
                    // Padding starts with a '1' bit followed by '0' bits.
                    // We only support byte-aligned messages, so the first padding byte is 0x80.
                    w[j] = w[j].wrapping_add((128 as u32) << (8 * (3 - k)));
                } else if index < message_bytes_count + pad_len {
                    // The message is then padded with '0' bytes.
                    // The message schedule is not impacted.
                } else {
                    // Padding ends with the message bit size encoded using 64 bits (big-endian).
                    let padding_byte = (message_bits_count >> (64 - 8 * (index - message_bytes_count - pad_len + 1))) as u8;
                    w[j] = w[j].wrapping_add((padding_byte as u32) << (8 * (3 - k)));
                }
            }
        }
        // Compute the next elements of the message schedule.
        for j in 16..64 {
            w[j] = w[j - 2].rotate_right(17) ^ w[j - 2].rotate_right(19) ^ w[j - 2].shr(10); // sigma_1
            w[j] = w[j].wrapping_add(w[j - 7]);
            w[j] = w[j].wrapping_add(w[j - 15].rotate_right(7) ^ w[j - 15].rotate_right(18) ^ w[j - 15].shr(3)); // sigma_0
            w[j] = w[j].wrapping_add(w[j - 16]);
        }
        // Initialize working variables.
        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;
        let mut f = h5;
        let mut g = h6;
        let mut h = h7;
        // Update working variables.
        for t in 0..64 {
            let t1: u32 = h
                .wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25))
                .wrapping_add((e & f) ^ (!e & g))
                .wrapping_add(k256[t])
                .wrapping_add(w[t]);
            let t2: u32 = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22)).wrapping_add((a & b) ^ (a & c) ^ (b & c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        // Compute intermediate hash values.
        h0 = a.wrapping_add(h0);
        h1 = b.wrapping_add(h1);
        h2 = c.wrapping_add(h2);
        h3 = d.wrapping_add(h3);
        h4 = e.wrapping_add(h4);
        h5 = f.wrapping_add(h5);
        h6 = g.wrapping_add(h6);
        h7 = h.wrapping_add(h7);
    }

    #[rustfmt::skip]
    let result: [u8; 32] = [
        (h0 >> 24) as u8, (h0 >> 16) as u8, (h0 >> 8) as u8, h0 as u8,
        (h1 >> 24) as u8, (h1 >> 16) as u8, (h1 >> 8) as u8, h1 as u8,
        (h2 >> 24) as u8, (h2 >> 16) as u8, (h2 >> 8) as u8, h2 as u8,
        (h3 >> 24) as u8, (h3 >> 16) as u8, (h3 >> 8) as u8, h3 as u8,
        (h4 >> 24) as u8, (h4 >> 16) as u8, (h4 >> 8) as u8, h4 as u8,
        (h5 >> 24) as u8, (h5 >> 16) as u8, (h5 >> 8) as u8, h5 as u8,
        (h6 >> 24) as u8, (h6 >> 16) as u8, (h6 >> 8) as u8, h6 as u8,
        (h7 >> 24) as u8, (h7 >> 16) as u8, (h7 >> 8) as u8, h7 as u8,
    ];
    result
}

mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn official_test_vectors() {
        let h1 = hex::encode(sha256(b"abc"));
        assert_eq!(h1, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        let h2 = hex::encode(sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
        assert_eq!(h2, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    }

    #[test]
    fn hash_long_message() {
        let message = [42u8; 150000];
        let h = sha256(&message);
        assert_eq!(hex::encode(h), "dc7dc699db6610842790da50372dca1eec1609d3016bcefebb1f89abff64b020");
    }

    // To run benchmarks:
    //  - add #![feature(test)] to lib.rs
    //  - add extern crate test; to lib.rs
    //  - run cargo +nightly bench
    // #[bench]
    // fn bench_sha256(b: &mut Bencher) {
    //     b.iter(|| sha256(b"roses are blue, cryptography is amazing, hash functions are hot, rust is fun"));
    // }
}
