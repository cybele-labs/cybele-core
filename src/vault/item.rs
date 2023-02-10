use std::io::{BufReader, Read, Write};

use rand::rngs::OsRng;
use rand::RngCore;

use crate::{cipher, keys, Purpose, Version};

#[derive(Debug, Eq, PartialEq)]
pub struct VaultItem {
    version: Version,
    pub name: String,
    salt: [u8; 32],
    pub encrypted_value: Vec<u8>,
}

impl VaultItem {
    pub fn encrypt(version: Version, name: &str, value: &str, password: &str) -> Option<VaultItem> {
        // Initialize random salt.
        let mut csprng = OsRng {};
        let mut salt: [u8; 32] = [0u8; 32];
        csprng.fill_bytes(&mut salt);
        // Encrypt item content.
        let encryption_key = keys::derive_key(version, password, &salt, Purpose::Password)?;
        let encrypted_value = cipher::encrypt(encryption_key, value.as_bytes())?;
        let item = VaultItem {
            version,
            name: String::from(name),
            salt,
            encrypted_value,
        };
        Some(item)
    }

    pub fn decrypt(&self, password: &str) -> Option<Vec<u8>> {
        let encryption_key = keys::derive_key(self.version, password, &self.salt, Purpose::Password)?;
        cipher::decrypt(encryption_key, &self.encrypted_value)
    }

    pub(crate) fn size(&self) -> usize {
        match self.version {
            Version::Test | Version::V1 => 2 + self.name.as_bytes().len() + 32 + 1 + self.encrypted_value.len(),
        }
    }

    #[allow(dead_code)]
    fn serialize(&self) -> Vec<u8> {
        let mut w: Vec<u8> = Vec::with_capacity(self.size());
        self.serialize_into(&mut w);
        w
    }

    pub(crate) fn serialize_into(&self, w: &mut Vec<u8>) {
        match self.version {
            Version::Test | Version::V1 => {
                // [u16: name_len]
                let name_bytes: &[u8] = self.name.as_bytes();
                w.write_all(&[(name_bytes.len() >> 8) as u8, name_bytes.len() as u8]).unwrap();
                // [name_len*u8: name]
                w.write_all(name_bytes).unwrap();
                // [32*u8: salt]
                w.write_all(&self.salt).unwrap();
                // [u16: encrypted_value_len]
                w.write_all(&[(self.encrypted_value.len() >> 8) as u8, self.encrypted_value.len() as u8]).unwrap();
                // [encrypted_value_len*u8: encrypted_value]
                w.write_all(&self.encrypted_value).unwrap();
            }
        }
    }

    #[allow(dead_code)]
    fn deserialize(version: Version, bin: &[u8]) -> Option<VaultItem> {
        let mut r = BufReader::new(bin);
        VaultItem::deserialize_from(version, &mut r)
    }

    pub(crate) fn deserialize_from(version: Version, r: &mut BufReader<&[u8]>) -> Option<VaultItem> {
        match version {
            Version::Test | Version::V1 => {
                // [u16: name_len]
                let mut name_len_bytes = [0u8; 2];
                r.read_exact(&mut name_len_bytes).ok()?;
                let name_len = (((name_len_bytes[0] as u16) << 8) | name_len_bytes[1] as u16) as usize;
                // [name_len*u8: name]
                let mut name = vec![0u8; name_len];
                r.read_exact(&mut name).ok()?;
                // [32*u8: salt]
                let mut salt = [0u8; 32];
                r.read_exact(&mut salt).ok()?;
                // [u16: encrypted_value_len]
                let mut encrypted_value_len_bytes = [0u8; 2];
                r.read_exact(&mut encrypted_value_len_bytes).ok()?;
                let encrypted_value_len = (((encrypted_value_len_bytes[0] as u16) << 8) | encrypted_value_len_bytes[1] as u16) as usize;
                // [encrypted_value_len*u8: encrypted_value]
                let mut encrypted_value = vec![0u8; encrypted_value_len];
                r.read_exact(&mut encrypted_value).ok()?;
                let item = VaultItem {
                    version,
                    name: String::from_utf8(name).ok()?,
                    salt,
                    encrypted_value,
                };
                if name_len == 0 || encrypted_value_len == 0 {
                    return None;
                }
                Some(item)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::vault::VaultItem;
    use crate::Version;

    #[test]
    fn encrypt_decrypt_vault_item() {
        let item = VaultItem::encrypt(Version::Test, "item 1", "s3cr3t stufF", "p4ssw0rd").unwrap();
        let decrypted = item.decrypt("p4ssw0rd").unwrap();
        assert_eq!(String::from_utf8(decrypted).unwrap(), "s3cr3t stufF");
    }

    #[test]
    fn decryption_failure() {
        let item = VaultItem::encrypt(Version::Test, "item 1", "s3cr3t stufF", "p4ssw0rd").unwrap();
        assert_eq!(item.decrypt("password"), None);
    }

    #[test]
    fn serialize_vault_item() {
        let item = VaultItem {
            version: Version::V1,
            name: String::from("4chan pwd"),
            salt: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1],
            encrypted_value: hex::decode("deadbeef").unwrap(),
        };
        let serialized: Vec<u8> = item.serialize();
        let deserialized = VaultItem::deserialize(Version::V1, &serialized);
        assert_eq!(
            hex::encode(item.serialize()),
            "0009346368616e2070776400010203040506070809000102030405060708090001020304050607080900010004deadbeef"
        );
        assert_eq!(item, deserialized.unwrap());
    }

    #[test]
    fn serialize_long_vault_item() {
        let item = VaultItem {
            version: Version::V1,
            name: String::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb cccccccccccccccccccccccccccccccccccccccccccccccccc dddddddddddddddddddddddddddddddddddddddddddddddddd eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee ffffffffffffffffffffffffffffffffffffffffffffffffff"),
            salt: [42u8; 32],
            encrypted_value: hex::decode("03958e0a08d2d23e708d0b0778c87c83140e089fdf908903958e0a08d2d23e708d0b0778c87c83140e089fdf908903958e0a08d2d23e708d0b0778c87c83140e089fdf908903958e0a08d2d23e708d0b0778c87c83140e089fdf908903958e0a08d2d23e708d0b0778c87c83140e089fdf908903958e0a08d2d23e708d0b0778c87c83140e089fdf908903958e0a08d2d23e708d0b0778c87c83140e089fdf908903958e0a08d2d23e708d0b0778c87c83140e089fdf908903958e0a08d2d23e708d0b0778c87c83140e089fdf908903958e0a08d2d23e708d0b0778c87c83140e089fdf908903958e0a08d2d23e708d0b0778c87c83140e089fdf908903958e0a08d2d23e708d0b0778c87c83140e089fdf9089").unwrap(),
        };
        let serialized: Vec<u8> = item.serialize();
        let deserialized = VaultItem::deserialize(Version::V1, &serialized);
        assert_eq!(hex::encode(item.serialize()), "013161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161612062626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262622063636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363632064646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464642065656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565656565652066666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666662a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a011403958e0a08d2d23e708d0b0778c87c83140e089fdf908903958e0a08d2d23e708d0b0778c87c83140e089fdf908903958e0a08d2d23e708d0b0778c87c83140e089fdf908903958e0a08d2d23e708d0b0778c87c83140e089fdf908903958e0a08d2d23e708d0b0778c87c83140e089fdf908903958e0a08d2d23e708d0b0778c87c83140e089fdf908903958e0a08d2d23e708d0b0778c87c83140e089fdf908903958e0a08d2d23e708d0b0778c87c83140e089fdf908903958e0a08d2d23e708d0b0778c87c83140e089fdf908903958e0a08d2d23e708d0b0778c87c83140e089fdf908903958e0a08d2d23e708d0b0778c87c83140e089fdf908903958e0a08d2d23e708d0b0778c87c83140e089fdf9089");
        assert_eq!(item, deserialized.unwrap());
    }

    #[test]
    fn deserialize_vault_item_failure() {
        let test_cases = vec![
            // invalid name length
            hex::decode("09346368616e20707764000102030405060708090001020304050607080900010203040506070809000104deadbeef").unwrap(),
            // truncated encrypted value
            hex::decode("0009346368616e20707764000102030405060708090001020304050607080900010203040506070809000104dead").unwrap(),
        ];
        for t in test_cases {
            assert_eq!(VaultItem::deserialize(Version::V1, &t), None);
        }
    }
}
