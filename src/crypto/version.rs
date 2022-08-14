#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Version {
    Test,
    V1,
}

pub fn get_version(version: u8) -> Option<Version> {
    match version {
        0 => Some(Version::Test),
        1 => Some(Version::V1),
        _ => None,
    }
}
