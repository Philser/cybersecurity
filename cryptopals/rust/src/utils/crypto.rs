use openssl::symm::{encrypt, Cipher};
use std::char;
use std::error::Error;

pub fn pad_pkcs7(plaintext: Vec<u8>, block_size: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    if block_size > 128 {
        return Err(Box::from("block sizes > 128 not supported"));
    }

    let modulo = plaintext.len() % block_size;
    if modulo == 0 {
        return Ok(plaintext);
    }

    let padding = block_size - modulo;
    let character =
        char::from_u32(padding as u32).ok_or("Error converting padding to character")?;
    let intermediate = character.to_string();
    let byte_char = intermediate.as_bytes();
    let mut new = plaintext.clone();
    for _i in 0..padding {
        new.push(byte_char[0]);
    }

    return Ok(new);
}

#[test]
fn can_pad() {
    let mut expected = b"YELLOW SUBMARINE".to_vec();

    match pad_pkcs7(b"YELLOW SUBMARINE".to_vec(), 16) {
        Ok(padded) => assert_eq!(expected, padded),
        Err(_) => assert!(false, "Test should not have failed"),
    }
    expected = b"YELLOW SUBMARINE\x04\x04\x04\x04".to_vec();

    match pad_pkcs7(b"YELLOW SUBMARINE".to_vec(), 20) {
        Ok(padded) => assert_eq!(expected, padded),
        Err(_) => assert!(false, "Test should not have failed"),
    }

    expected = b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
        .to_vec();

    match pad_pkcs7(b"YELLOW SUBMARINE".to_vec(), 32) {
        Ok(padded) => assert_eq!(expected, padded),
        Err(_) => assert!(false, "Test should not have failed"),
    }
}
