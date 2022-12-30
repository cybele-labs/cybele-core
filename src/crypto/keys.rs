use argon2::password_hash::{Output, PasswordHasher, SaltString};
use argon2::{Algorithm, Argon2, Params};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::Version;

#[derive(Debug)]
pub enum Purpose {
    File,
    Password,
}

impl Purpose {
    pub fn encode(self) -> &'static [u8] {
        match self {
            Purpose::File => b"file",
            Purpose::Password => b"password",
        }
    }
}

pub fn derive_key(version: Version, password: &str, salt: &[u8], purpose: Purpose) -> Option<[u8; 32]> {
    // Argon2 parameters are frozen for each version.
    let params: Params = match version {
        Version::Test => Params::new(512, 1, 1, Some(32)).unwrap(),
        Version::V1 => Params::new(32_768, 128, 4, Some(32)).unwrap(),
    };
    let argon2: Argon2 = Argon2::new(Algorithm::Argon2id, argon2::Version::V0x13, params);

    // We first derive a 256-bit master key based on the password and salt.
    let mut master_key: [u8; 32] = [0u8; 32];
    let salt_str: SaltString = SaltString::b64_encode(salt)
        .map_err(|e| eprintln!("Invalid Argon2 salt: {}", e))
        .ok()?;
    let password_hash: Output = argon2
        .hash_password(password.as_bytes(), &salt_str)
        .map_err(|e| eprintln!("Cannot hash password: {}", e))
        .ok()?
        .hash?;
    master_key.copy_from_slice(password_hash.as_bytes());

    // We then use HKDF to derive an encryption key.
    let key_derivation: Hkdf<Sha256> = Hkdf::new(None, &master_key);
    let mut encryption_key: [u8; 32] = [0u8; 32];
    key_derivation
        .expand(purpose.encode(), &mut encryption_key)
        .expect("32 bytes should be a valid sha256 output length");

    Some(encryption_key)
}

#[cfg(test)]
mod tests {
    use hex;

    use super::*;

    #[test]
    fn derive_keys() {
        let password: &str = "password";
        let salt: &[u8] = &hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap();
        let key1: [u8; 32] = derive_key(Version::Test, password, salt, Purpose::File).unwrap();
        let key2: [u8; 32] = derive_key(Version::Test, password, salt, Purpose::File).unwrap();
        let key3: [u8; 32] = derive_key(Version::Test, password, salt, Purpose::Password).unwrap();
        let zeroes: [u8; 32] = [0u8; 32];
        assert_ne!(key1, zeroes);
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn invalid_salt() {
        let password: &str = "password";
        let salt: &[u8] = &[0u8; 3];
        let result = derive_key(Version::Test, password, salt, Purpose::File);
        assert_eq!(result, None);
    }
}
