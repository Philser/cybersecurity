use hex;
use openssl::symm::{encrypt, Cipher};
use std::char;
use std::error::Error;
use std::iter;
use std::iter::FromIterator;

fn num_to_byte(num: u8) -> Result<u8, Box<dyn Error>> {
    let character = char::from_u32(num as u32).ok_or("Error converting padding to character")?;
    let intermediate = character.to_string();
    let byte_char = intermediate.as_bytes();

    return Ok(byte_char[0]);
}

pub fn pad_pkcs7(plaintext: &Vec<u8>, block_size: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    if block_size > 128 {
        return Err(Box::from("block sizes > 128 not supported"));
    }

    let modulo = plaintext.len() % block_size;
    if modulo == 0 {
        return Ok(plaintext.clone());
    }

    let padding = block_size - modulo;
    let byte_char = num_to_byte(padding as u8)?;
    let mut new = plaintext.clone();
    for _i in 0..padding {
        new.push(byte_char);
    }

    return Ok(new);
}

pub fn encrypt_repeating_key_xor(
    plaintext: &Vec<u8>,
    key: &Vec<u8>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut cipher = vec![];
    for pos in 0..plaintext.len() {
        let xord: u8 = plaintext[pos] ^ key[pos % key.len()];
        let byte_char = num_to_byte(xord)?;
        cipher.push(byte_char);
    }

    return Ok(cipher.to_vec());
}

pub fn encrypt_aes_cbc(
    plaintext: &Vec<u8>,
    iv: &Vec<u8>,
    key: &Vec<u8>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let suite = Cipher::aes_128_ecb();

    let padded = pad_pkcs7(plaintext, suite.block_size())?;

    let mut offset;
    let mut cipher = b"".to_vec();
    let mut previous_block = iv.clone();
    let mut curr_block: Vec<u8>;
    let key_clone = key.clone().into_boxed_slice();
    for i in 0..(padded.len() / suite.block_size()) {
        offset = i * suite.block_size();
        curr_block = padded[offset..offset + suite.block_size()].to_vec();
        let intermediate = encrypt_repeating_key_xor(&curr_block, &previous_block)?;
        let mut encrypted = encrypt(suite, &key_clone, None, &intermediate.into_boxed_slice())?;
        cipher.append(&mut encrypted);

        previous_block = curr_block.clone();
    }

    Ok(cipher)
}

#[test]
fn can_pad() {
    let mut expected = b"YELLOW SUBMARINE".to_vec();

    match pad_pkcs7(&b"YELLOW SUBMARINE".to_vec(), 16) {
        Ok(padded) => assert_eq!(expected, padded),
        Err(_) => assert!(false, "Test should not have failed"),
    }
    expected = b"YELLOW SUBMARINE\x04\x04\x04\x04".to_vec();

    match pad_pkcs7(&b"YELLOW SUBMARINE".to_vec(), 20) {
        Ok(padded) => assert_eq!(expected, padded),
        Err(_) => assert!(false, "Test should not have failed"),
    }

    expected = b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
        .to_vec();

    match pad_pkcs7(&b"YELLOW SUBMARINE".to_vec(), 32) {
        Ok(padded) => assert_eq!(expected, padded),
        Err(_) => assert!(false, "Test should not have failed"),
    }
}

#[test]
fn can_encrypt_repeating_key_xor() {
    let expected_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2\
    6226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

    let input = b"Burning 'em, if you ain't quick and nimble\n\
        I go crazy when I hear a cymbal"
        .to_vec();

    match encrypt_repeating_key_xor(&input, &b"ICE".to_vec()) {
        Ok(result) => {
            let expected = hex::decode(expected_hex)
                .map_err(|_| assert!(false, "Error decoding expected hex string"))
                .unwrap();
            assert_eq!(expected, result)
        }
        Err(_) => assert!(false, "Function threw an error"),
    }
}

#[test]
fn can_encrypt_aes_cbc() {
    let expected = b"jx`\x035\x85a\xab\x9b\xb5M\xd4\xcf\x80\xb8\xab".to_vec();
    let mut iv = b"".to_vec();
    for _ in 0..16 {
        iv.append(&mut b"\x00".to_vec());
    }

    match encrypt_aes_cbc(&b"test".to_vec(), &iv, &b"YELLOW SUBMARINE".to_vec()) {
        Ok(encrypted) => {
            assert_eq!(expected, encrypted)
        }
        Err(_) => assert!(false, "Function threw error unexpectedly"),
    }
}
