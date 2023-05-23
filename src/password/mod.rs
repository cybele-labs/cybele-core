use rand::distributions::Uniform;
use rand::rngs::OsRng;
use rand::Rng;

// Note that we avoid characters that may be confused with other characters: I, l, O, 0
// We generally want more letters and numbers than special characters, which is why we duplicate them.
#[rustfmt::skip]
const PASSWORD_CHARS: [char; 141] = [
    'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'z', 'x', 'c', 'v', 'b', 'n', 'm',
    'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'z', 'x', 'c', 'v', 'b', 'n', 'm',
    'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'P', 'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'Z', 'X', 'C', 'V', 'B', 'N', 'M',
    'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'P', 'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'Z', 'X', 'C', 'V', 'B', 'N', 'M',
    '1', '2', '3', '4', '5', '6', '7', '8', '9',
    '1', '2', '3', '4', '5', '6', '7', '8', '9',
    '-', '_', '+', '=', '<', '>', '.', '!', '?', ':', ';', '~', '@', '#', '$', '%', '^', '&', '*', '(', ')', '[', ']', '{', '}'
];

pub fn generate_password(password_len: usize) -> String {
    let mut csprng = OsRng {};
    let between = Uniform::from(0..PASSWORD_CHARS.len());
    let mut password = String::with_capacity(password_len);
    for _ in 0..password_len {
        let i: usize = csprng.sample(between);
        password.push(PASSWORD_CHARS[i]);
    }
    password
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_passwords() {
        let p1 = generate_password(16);
        assert_eq!(p1.len(), 16);
        let p2 = generate_password(16);
        assert_eq!(p2.len(), 16);
        assert_ne!(p1, p2);
    }
}
