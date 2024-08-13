use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

pub fn encrypt(key: [u8; 32], plaintext: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_slice()).expect("32 bytes should be a valid ChaCha20 key size");
    let nonce = Nonce::from([0u8; 12]);
    cipher.encrypt(&nonce, plaintext).map_err(|_| eprintln!("Failed to encrypt")).ok()
}

pub fn decrypt(key: [u8; 32], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_slice()).expect("32 bytes should be a valid ChaCha20 key size");
    let nonce = Nonce::from([0u8; 12]);
    cipher.decrypt(&nonce, ciphertext).map_err(|_| eprintln!("Failed to decrypt")).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::rngs::OsRng;
    use rand::RngCore;

    #[test]
    fn encrypt_decrypt() {
        let mut csprng = OsRng {};
        let mut key: [u8; 32] = [0u8; 32];
        csprng.fill_bytes(&mut key);
        let message: &[u8] = b"this is very secret";
        let encrypted = encrypt(key, message).unwrap();
        let decrypted = decrypt(key, encrypted.as_slice()).unwrap();
        assert_eq!(message, decrypted);
    }

    #[test]
    fn decryption_failure() {
        let result = decrypt([0u8; 32], &[0u8; 48]);
        assert_eq!(result, None);
    }
}
