use std::io::Write;

use crate::hash::sha256;

/// Compute the HMAC-SHA256 for the given message.
/// We only support keys smaller than 64 bytes, which avoids an additional hashing.
pub fn authenticate(key: &[u8], message: &[u8]) -> [u8; 32] {
    assert!(key.len() <= 64);
    // SHA256 uses 64 bytes blocks, so we must expand our key: K0 = K || 0x00...
    // We first compute SHA256((K0 ^ ipad) || message).
    let mut inner_data: Vec<u8> = Vec::with_capacity(64 + message.len());
    key.iter().for_each(|&x| inner_data.push(x ^ 0x36));
    (0..(64 - key.len())).for_each(|_| inner_data.push(0x36));
    inner_data.write_all(message).unwrap();
    let inner_hash = sha256::hash(&inner_data);
    // We then compute SHA256((K0 ^ opad) || SHA256((K0 ^ ipad) || message)).
    let mut outer_data: Vec<u8> = Vec::with_capacity(96);
    key.iter().for_each(|&x| outer_data.push(x ^ 0x5c));
    (0..32).for_each(|_| outer_data.push(0x5c));
    outer_data.write_all(&inner_hash).unwrap();
    sha256::hash(&outer_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::hex;
    use rand::rngs::OsRng;
    use rand::{Rng, RngCore};

    #[test]
    fn authenticate_random_messages() {
        let mut csprng = OsRng {};
        let mut key: [u8; 32] = [0u8; 32];
        csprng.fill_bytes(&mut key);
        let message_size: usize = csprng.gen_range(1..1000);
        let mut message: Vec<u8> = vec![0; message_size];
        csprng.fill_bytes(&mut message);
        let mac1: [u8; 32] = authenticate(&key, &message);
        let mac2: [u8; 32] = authenticate(&key, &message);
        assert_eq!(mac1, mac2);
        let mac3: [u8; 32] = authenticate(&key, b"this is not the same message");
        assert_ne!(mac1, mac3);
        csprng.fill_bytes(&mut key);
        let mac4: [u8; 32] = authenticate(&key, &message);
        assert_ne!(mac1, mac4);
    }

    #[test]
    fn test_vector() {
        let key: [u8; 32] = hex::decode("a3a07ba8aaaeb0d60fad767437b544cbfd790a95702af8e0819f2eb706b46660").unwrap().try_into().unwrap();
        let message = "cybele controls the keys to the world";
        let expected: [u8; 32] = hex::decode("6397c4768a0a7b122dfbb5d45cd9a3cbed6a6c826365f133a331489ecc5fbcdf").unwrap().try_into().unwrap();
        let mac = authenticate(&key, message.as_bytes());
        assert_eq!(expected, mac);
    }

    // To run benchmarks:
    //  - add #![feature(test)] to lib.rs
    //  - add extern crate test; to lib.rs
    //  - run cargo +nightly bench
    // #[bench]
    // fn bench_sha256(b: &mut Bencher) {
    //     let key: [u8; 32] = hex::decode("a3a07ba8aaaeb0d60fad767437b544cbfd790a95702af8e0819f2eb706b46660").unwrap().try_into().unwrap();
    //     b.iter(|| authenticate(&key, b"authentication matters folks"));
    // }
}
