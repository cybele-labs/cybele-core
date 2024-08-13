use argon2::password_hash::{Output, PasswordHasher, SaltString};
use argon2::{Algorithm, Argon2, Params};

use crate::crypto::hmac256;
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
        Version::V1 => Params::new(32_768, 64, 4, Some(32)).unwrap(),
    };
    let argon2: Argon2 = Argon2::new(Algorithm::Argon2id, argon2::Version::V0x13, params);

    // We first derive a 256-bit master key based on the password and salt.
    let mut master_key: [u8; 32] = [0u8; 32];
    let salt_str: SaltString = SaltString::encode_b64(salt).map_err(|e| eprintln!("Invalid Argon2 salt: {}", e)).ok()?;
    let password_hash: Output = argon2
        .hash_password(password.as_bytes(), &salt_str)
        .map_err(|e| eprintln!("Cannot hash password: {}", e))
        .ok()?
        .hash?;
    master_key.copy_from_slice(password_hash.as_bytes());

    // We then use HMAC-SHA256 to derive an encryption key.
    Some(hmac256::authenticate(&master_key, purpose.encode()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn derive_keys() {
        let password1: &str = "this is a strong password";
        let password2: &str = "tH1s m4Y b3 a str0ng#r p4sS0rD";
        let salt1: [u8; 32] = hex::decode("06b301aadfabf3f756b0ef5d9c7318cf90c4ea4e24ee793bb160fe53e8921efa").unwrap().try_into().unwrap();
        let salt2: [u8; 32] = hex::decode("da424954b09e6deb057d92c155d214e33cf863a42ac64e4eec42030823bc5f42").unwrap().try_into().unwrap();
        let keys = [
            derive_key(Version::Test, password1, &salt1, Purpose::File).unwrap(),
            derive_key(Version::Test, password1, &salt1, Purpose::Password).unwrap(),
            derive_key(Version::Test, password1, &salt2, Purpose::File).unwrap(),
            derive_key(Version::Test, password1, &salt2, Purpose::Password).unwrap(),
            derive_key(Version::Test, password2, &salt1, Purpose::File).unwrap(),
            derive_key(Version::Test, password2, &salt1, Purpose::Password).unwrap(),
        ];
        assert_eq!(hex::encode(&keys[0]), "d0737c9cdfbe860348fbd31bf91187bf70a46ac5248f2cc0c9e2bc556718bb1d");
        assert_eq!(hex::encode(&keys[1]), "ce2c731f80fa9adb43447a516e7c6919846725434169ddd45422ed664f560536");
        assert_eq!(hex::encode(&keys[2]), "f46ee80977905dcf620b129bb8ac979a16af0f78a2211f579c2e88629713f5ed");
        assert_eq!(hex::encode(&keys[3]), "f8fddfb3aec70a4e3fa438028f6b87c111ca3d5e0464f24e316bbcd4b03ee7d7");
        assert_eq!(hex::encode(&keys[4]), "11198ccfdc63034b7406b3b62fa9a9873f1f12cccb3e77fea608415c2891bae2");
        assert_eq!(hex::encode(&keys[5]), "16df8c15d638192b5ce739bd81ec623bc1359ba5b902087c4cf7bfe564cc1009");
    }

    #[test]
    fn invalid_salt() {
        let password: &str = "password";
        let salt: &[u8] = &[0u8; 3];
        let result = derive_key(Version::Test, password, salt, Purpose::File);
        assert_eq!(result, None);
    }
}
