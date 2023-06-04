use std::io::{BufReader, Read, Write};

use rand::rngs::OsRng;
use rand::RngCore;

use crate::vault::item::VaultItem;
use crate::{cipher, keys, Purpose, Version};

mod item;

pub struct Vault {
    pub version: Version,
    salt: [u8; 32],
    items: Vec<VaultItem>,
}

impl Vault {
    pub fn create(salt: Option<[u8; 32]>) -> Vault {
        let salt: [u8; 32] = match salt {
            Some(salt) => salt,
            None => {
                let mut csprng = OsRng {};
                let mut salt: [u8; 32] = [0u8; 32];
                csprng.fill_bytes(&mut salt);
                salt
            }
        };
        Vault {
            version: Version::V1,
            salt,
            items: Vec::new(),
        }
    }

    pub fn add(&mut self, name: &str, value: &str, password: &str) -> Option<()> {
        VaultItem::encrypt(self.version, name, value, password).map(|item| self.items.push(item))
    }

    pub fn remove(&mut self, name: &str) {
        self.items.retain(|i| i.name != name)
    }

    pub fn get(&self, name: &str, password: &str) -> Option<String> {
        self.items
            .iter()
            .find(|i| i.name == name)
            .and_then(|i| VaultItem::decrypt(i, password))
            .and_then(|v| String::from_utf8(v).ok())
    }

    pub fn list(&self) -> Vec<String> {
        self.items.iter().map(|i| i.name.clone()).collect()
    }

    pub fn serialize(&self, password: &str) -> Option<Vec<u8>> {
        match self.version {
            Version::Test | Version::V1 => {
                let items_len: usize = self.items.iter().map(|i| i.size()).sum();
                let mut items_writer: Vec<u8> = Vec::with_capacity(2 + items_len);
                items_writer.write_all(&[(self.items.len() >> 8) as u8, self.items.len() as u8]).unwrap();
                self.items.iter().for_each(|i| i.serialize_into(&mut items_writer));
                // We encrypt the serialized items, including the length.
                let encryption_key = keys::derive_key(self.version, password, &self.salt, Purpose::File)?;
                let encrypted_items = cipher::encrypt(encryption_key, &items_writer)?;
                // We serialize the result.
                let mut w: Vec<u8> = Vec::with_capacity(1 + 32 + encrypted_items.len());
                // [u8: version]
                w.write_all(&[self.version.to_byte()]).unwrap();
                // [32*u8: salt]
                w.write_all(&self.salt).unwrap();
                // encrypted([u16: items_len][...items])
                w.write_all(&encrypted_items).unwrap();
                Some(w)
            }
        }
    }

    pub fn deserialize(bin: &[u8], password: &str) -> Option<Vault> {
        // [u8: version]
        let mut r = BufReader::new(bin);
        let mut version_byte = [0u8];
        r.read_exact(&mut version_byte).ok()?;
        let version = Version::from_byte(version_byte[0])?;
        // [32*u8: salt]
        let mut salt = [0u8; 32];
        r.read_exact(&mut salt).ok()?;
        // encrypted([u16: items_len][...items])
        let mut encrypted_items = vec![0u8; bin.len() - 32 - 1];
        r.read_exact(&mut encrypted_items).ok()?;
        // We decrypt the serialized items.
        let encryption_key = keys::derive_key(version, password, &salt, Purpose::File)?;
        let decrypted_items = cipher::decrypt(encryption_key, &encrypted_items)?;
        // We deserialize the resulting items.
        let mut items_reader = BufReader::new(decrypted_items.as_slice());
        let mut items_len_bytes = [0u8; 2];
        items_reader.read_exact(&mut items_len_bytes).ok()?;
        let items_len = (((items_len_bytes[0] as u16) << 8) | items_len_bytes[1] as u16) as usize;
        let mut items: Vec<VaultItem> = Vec::with_capacity(items_len);
        (0..items_len).for_each(|_| {
            let item = VaultItem::deserialize_from(version, &mut items_reader).unwrap();
            items.push(item);
        });
        Some(Vault { version, salt, items })
    }
}

#[cfg(test)]
mod tests {
    use crate::hex;
    use crate::vault::Vault;
    use crate::Version;

    #[test]
    fn serialize_deserialize_empty_vault() {
        let mut vault = Vault::create(Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1]));
        vault.version = Version::Test;
        let serialized = vault.serialize("file password").unwrap();
        assert_eq!(serialized.len(), 51); // don't forget the 16-byte trailing mac!
        assert_eq!(
            serialized.starts_with(&hex::decode("000001020304050607080900010203040506070809000102030405060708090001").unwrap()),
            true
        );
        let deserialized = Vault::deserialize(&serialized, "file password").unwrap();
        assert_eq!(deserialized.version, vault.version);
        assert_eq!(deserialized.salt, vault.salt);
        assert_eq!(deserialized.items.len(), 0);
    }

    #[test]
    fn serialize_deserialize_vault() {
        let mut vault = Vault::create(Some([42u8; 32]));
        vault.version = Version::Test;
        vault.add("item 1", "secret stuff", "s3cr3t p4ss0rd");
        vault.add("item 2", "more secret stuff", "s3cr3t p4ss0rd");
        let serialized = vault.serialize("f1l3 p4ssw0rd").unwrap();
        let deserialized = Vault::deserialize(&serialized, "f1l3 p4ssw0rd").unwrap();
        assert_eq!(deserialized.version, vault.version);
        assert_eq!(deserialized.salt, vault.salt);
        assert_eq!(deserialized.items.len(), 2);
        assert_eq!(deserialized.items, vault.items);
    }

    #[test]
    fn deserialize_failure() {
        let mut vault = Vault::create(Some([42u8; 32]));
        vault.version = Version::Test;
        vault.add("item 1", "secret stuff", "s3cr3t p4ss0rd");
        vault.add("item 2", "more secret stuff", "another s3cr3t p4ss0rd");
        let serialized = vault.serialize("password").unwrap();
        // Truncated in the middle of salt.
        assert_eq!(Vault::deserialize(&serialized[0..16], "password").is_none(), true);
        // Truncated after salt.
        assert_eq!(Vault::deserialize(&serialized[0..33], "password").is_none(), true);
        // Mac truncated.
        assert_eq!(Vault::deserialize(&serialized[0..serialized.len() - 4], "password").is_none(), true);
        // Invalid password.
        assert_eq!(Vault::deserialize(&serialized, "passw0rd").is_none(), true);
        // Additional trailing bytes.
        let mut trailing = Vec::from(serialized);
        trailing.push(42u8);
        assert_eq!(Vault::deserialize(&trailing, "password").is_none(), true);
    }

    #[test]
    fn add_remove_items() {
        let mut vault = Vault::create(Some([42u8; 32]));
        vault.version = Version::Test;
        vault.add("item 1", "secret stuff", "password");
        assert_eq!(vec!["item 1"], vault.list());
        assert_eq!("secret stuff", vault.get("item 1", "password").unwrap());
        assert_eq!(None, vault.get("item 1", "p4ssword"));
        vault.remove("item 1");
        assert_eq!(vault.list().len(), 0);
        vault.add("item 1", "secret stuff", "password1");
        vault.add("item 2", "secret stuff", "password2");
        assert_eq!(vec!["item 1", "item 2"], vault.list());
        vault.remove("item 2");
        vault.remove("unknown item");
        assert_eq!(vec!["item 1"], vault.list());
        assert_eq!("secret stuff", vault.get("item 1", "password1").unwrap());
        assert_eq!(None, vault.get("item 2", "password2"));
    }
}
