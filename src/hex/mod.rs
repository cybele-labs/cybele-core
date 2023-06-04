/// Encode to a hexadecimal string.
pub fn encode<T: AsRef<[u8]>>(data: T) -> String {
    let mut encoded = String::with_capacity(data.as_ref().len() * 2);
    for &x in data.as_ref() {
        encoded.push(byte_to_char(x >> 4));
        encoded.push(byte_to_char(x & 0x0f));
    }
    encoded
}

fn byte_to_char(b: u8) -> char {
    match b {
        0u8 => '0',
        1u8 => '1',
        2u8 => '2',
        3u8 => '3',
        4u8 => '4',
        5u8 => '5',
        6u8 => '6',
        7u8 => '7',
        8u8 => '8',
        9u8 => '9',
        10u8 => 'a',
        11u8 => 'b',
        12u8 => 'c',
        13u8 => 'd',
        14u8 => 'e',
        15u8 => 'f',
        _ => panic!("invalid half-byte value"),
    }
}

/// Decode an assumed valid hexadecimal string.
pub fn decode(data: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::<u8>::with_capacity(data.len() / 2);
    let mut carry = true;
    let mut half = 0u8;
    for c in data.chars() {
        let value = char_to_byte(c)?;
        match carry {
            true => {
                half = value << 4;
                carry = false;
            }
            false => {
                bytes.push(half + value);
                half = 0u8;
                carry = true;
            }
        }
    }
    Ok(bytes)
}

fn char_to_byte(c: char) -> Result<u8, String> {
    match c {
        '0' => Ok(0u8),
        '1' => Ok(1u8),
        '2' => Ok(2u8),
        '3' => Ok(3u8),
        '4' => Ok(4u8),
        '5' => Ok(5u8),
        '6' => Ok(6u8),
        '7' => Ok(7u8),
        '8' => Ok(8u8),
        '9' => Ok(9u8),
        'a' => Ok(10u8),
        'b' => Ok(11u8),
        'c' => Ok(12u8),
        'd' => Ok(13u8),
        'e' => Ok(14u8),
        'f' => Ok(15u8),
        c => Err(format!("non hexadecimal char: {}", c)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_hex() {
        let bytes: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
        let str = "deadbeef";
        assert_eq!(encode(bytes), str);
        assert_eq!(decode(str).unwrap(), bytes);
    }
}
