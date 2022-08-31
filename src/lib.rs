#![crate_name = "cybele_core"]

extern crate rand;

use rand::rngs::OsRng;
use rand::RngCore;

use self::crypto::cipher;
use self::crypto::keys;
pub use self::crypto::keys::Purpose;
pub use self::version::Version;

mod crypto;
pub mod vault;
mod version;

pub struct SaltedCiphertext {
    pub salt: [u8; 32],
    pub ciphertext: Vec<u8>,
}

pub fn encrypt(version: Version, password: &str, plaintext: &[u8], purpose: Purpose) -> Option<SaltedCiphertext> {
    let mut csprng = OsRng {};
    let mut salt: [u8; 32] = [0u8; 32];
    csprng.fill_bytes(&mut salt);
    let encryption_key = keys::derive_key(version, password, &salt, purpose)?;
    let ciphertext = cipher::encrypt(encryption_key, plaintext)?;
    Some(SaltedCiphertext { salt, ciphertext })
}

pub fn decrypt(version: Version, password: &str, salt: &[u8], ciphertext: &[u8], purpose: Purpose) -> Option<Vec<u8>> {
    let encryption_key = keys::derive_key(version, password, salt, purpose)?;
    cipher::decrypt(encryption_key, ciphertext)
}

#[cfg(test)]
mod tests {
    use crate::crypto::keys::Purpose;
    use crate::Version;

    use super::*;

    #[test]
    fn encrypt_and_decrypt_data() {
        let password: &str = "master password";
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
        let password: &str = "master password";
        let plaintext: &[u8] = b"secret message";
        let encrypted1: SaltedCiphertext = encrypt(Version::Test, password, plaintext, Purpose::Password).unwrap();
        let encrypted2: SaltedCiphertext = encrypt(Version::Test, password, plaintext, Purpose::Password).unwrap();
        assert_ne!(encrypted1.salt, encrypted2.salt);
    }

    #[test]
    fn decryption_failure() {
        let password: &str = "master password";
        let plaintext: &[u8] = b"secret message";
        let encrypted: SaltedCiphertext = encrypt(Version::Test, password, plaintext, Purpose::Password).unwrap();
        let invalid_password = decrypt(
            Version::Test,
            "not my password",
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
