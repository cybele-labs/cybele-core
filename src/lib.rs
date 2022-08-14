#![crate_name = "cybele_core"]

extern crate rand;

use rand::rngs::OsRng;
use rand::RngCore;

use self::crypto::cipher;
use self::crypto::keys;
pub use self::crypto::keys::Purpose;
pub use self::crypto::version::{get_version, Version};

mod crypto;

pub struct SaltedCiphertext {
    pub salt: [u8; 32],
    pub ciphertext: Vec<u8>,
}

pub fn encrypt(version: Version, password: &[u8], plaintext: &[u8], purpose: Purpose) -> Option<SaltedCiphertext> {
    let mut csprng = OsRng {};
    let mut salt: [u8; 32] = [0u8; 32];
    csprng.fill_bytes(&mut salt);
    let encryption_key = keys::derive_key(version, password, &salt, purpose)?;
    let ciphertext = cipher::encrypt(encryption_key, plaintext)?;
    Some(SaltedCiphertext { salt, ciphertext })
}

pub fn decrypt(version: Version, password: &[u8], salt: &[u8], ciphertext: &[u8], purpose: Purpose) -> Option<Vec<u8>> {
    let encryption_key = keys::derive_key(version, password, salt, purpose)?;
    cipher::decrypt(encryption_key, ciphertext)
}

#[cfg(test)]
mod tests {
    use crate::crypto::keys::Purpose;
    use crate::crypto::version::{get_version, Version};

    use super::*;

    #[test]
    fn decode_version() {
        let v0 = get_version(0u8);
        assert_eq!(v0, Some(Version::Test));
        let v1 = get_version(1u8);
        assert_eq!(v1, Some(Version::V1));
        assert_eq!(get_version(2u8), None);
        assert_eq!(get_version(255u8), None);
    }

    #[test]
    fn encrypt_and_decrypt_data() {
        let password: &[u8] = b"master password";
        let plaintext: &[u8] = b"secret message";
        let encrypted = encrypt(Version::Test, password, plaintext, Purpose::Password).unwrap();
        let decrypted = decrypt(
            Version::Test,
            password,
            &encrypted.salt,
            encrypted.ciphertext.as_slice(),
            Purpose::Password,
        );
        assert_eq!(plaintext, decrypted.unwrap().as_slice());
    }

    #[test]
    fn generate_random_salt() {
        let password: &[u8] = b"master password";
        let plaintext: &[u8] = b"secret message";
        let encrypted1: SaltedCiphertext = encrypt(Version::Test, password, plaintext, Purpose::Password).unwrap();
        let encrypted2: SaltedCiphertext = encrypt(Version::Test, password, plaintext, Purpose::Password).unwrap();
        assert_ne!(encrypted1.salt, encrypted2.salt);
    }

    #[test]
    fn decryption_failure() {
        let password: &[u8] = b"master password";
        let plaintext: &[u8] = b"secret message";
        let encrypted: SaltedCiphertext = encrypt(Version::Test, password, plaintext, Purpose::Password).unwrap();
        let invalid_password = decrypt(
            Version::Test,
            b"not my password",
            &encrypted.salt,
            encrypted.ciphertext.as_slice(),
            Purpose::Password,
        );
        assert_eq!(invalid_password, None);
        let invalid_purpose = decrypt(
            Version::Test,
            password,
            &encrypted.salt,
            encrypted.ciphertext.as_slice(),
            Purpose::File,
        );
        assert_eq!(invalid_purpose, None);
        let invalid_salt = decrypt(
            Version::Test,
            password,
            &[0u8; 32],
            encrypted.ciphertext.as_slice(),
            Purpose::Password,
        );
        assert_eq!(invalid_salt, None);
        let invalid_ciphertext = decrypt(Version::Test, password, &encrypted.salt, plaintext, Purpose::Password);
        assert_eq!(invalid_ciphertext, None);
    }
}
