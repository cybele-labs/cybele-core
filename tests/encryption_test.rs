#[cfg(test)]
mod tests {
    use cybele_core::{decrypt, encrypt, Purpose, Version};

    #[test]
    fn encrypt_password() {
        let master_password: &str = "master password";
        let password: &str = "mail account password";
        let encrypted_password = encrypt(Version::V1, master_password.as_bytes(), password.as_bytes(), Purpose::Password).unwrap();
        assert_ne!(encrypted_password.salt, [0u8; 32]);
        let decrypted_password = decrypt(
            Version::V1,
            master_password.as_bytes(),
            &encrypted_password.salt,
            encrypted_password.ciphertext.as_slice(),
            Purpose::Password,
        );
        assert_eq!(password.as_bytes(), decrypted_password.unwrap().as_slice());
    }
}
