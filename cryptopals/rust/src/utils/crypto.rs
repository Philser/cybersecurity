use std::char;
use std::error::Error;

pub fn pad_pkcs7(text: &str, block_size: u32) -> Result<String, Box<dyn Error>> {
    let padding = block_size - text.len() as u32;
    if padding == 0 {
        return Ok(text.to_string());
    }

    let mut padded = text.to_string();
    for _i in 0..padding {
        padding.to_be_bytes();
        padded += &char::from_digit(padding, 16).ok_or("AAAA")?.to_string()
    }

    return Ok(padded);
}

#[cfg(tests)]
mod tests {

    #[test]
    fn can_pad() -> Result<String, Box<dyn Error>> {
        let expected = "YELLOW SUBMARINE\x04\x04\x04\x04";
        let padded = pad_pkcs7("YELLOW SUBMARINE", 20)?;

        assert_eq!(expected, padded);
    }
}
