#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Version {
    Test,
    V1,
}

impl Version {
    pub fn to_byte(&self) -> u8 {
        match self {
            Version::Test => 0,
            Version::V1 => 1,
        }
    }

    pub fn from_byte(version: u8) -> Option<Version> {
        match version {
            0 => Some(Version::Test),
            1 => Some(Version::V1),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_from_byte() {
        let v0 = Version::from_byte(0u8);
        assert_eq!(v0, Some(Version::Test));
        assert_eq!(0u8, v0.unwrap().to_byte());
        let v1 = Version::from_byte(1u8);
        assert_eq!(v1, Some(Version::V1));
        assert_eq!(1u8, v1.unwrap().to_byte());
        assert_eq!(Version::from_byte(2u8), None);
        assert_eq!(Version::from_byte(255u8), None);
    }
}