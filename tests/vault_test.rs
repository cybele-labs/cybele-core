#[cfg(test)]
mod tests {
    use cybele_core::vault::Vault;
    use cybele_core::Version;

    #[test]
    fn create_and_use_vault() {
        let mut vault1: Vault = Vault::create(None);
        vault1.version = Version::Test;
        vault1.add("email stuff", "a gre4t passw0rd!", "m4st3r_p4ss0rd");
        vault1.add("laptop things", "very secret, much important work", "m4st3r_p4ss0rd");
        let serialized: Vec<u8> = vault1.serialize("0th3r_m4st3r").unwrap();
        let mut vault2: Vault = Vault::deserialize(&serialized, "0th3r_m4st3r").unwrap();
        assert_eq!(vec!["email stuff", "laptop things"], vault2.list());
        assert_eq!("a gre4t passw0rd!", vault2.get("email stuff", "m4st3r_p4ss0rd").unwrap());
        assert_eq!("very secret, much important work", vault2.get("laptop things", "m4st3r_p4ss0rd").unwrap());
        assert_eq!(None, vault2.get("email stuff", "0th3r_m4st3r"));
        vault2.remove("email stuff");
        assert_eq!(None, vault2.get("email stuff", "m4st3r_p4ss0rd"));
    }
}
