use hex;
use openssl::symm::{decrypt, encrypt, Cipher, Crypter, Mode};
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

    let rest = plaintext.len() % block_size;
    if rest == 0 {
        return Ok(plaintext.clone());
    }

    let padding = block_size - rest;
    let byte_char = num_to_byte(padding as u8)?;
    let mut new = plaintext.clone();
    for _ in 0..padding {
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

pub fn decrypt_repeating_key_xor(cipher: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let mut spread_key = b"".to_vec();
    for i in 0..cipher.len() {
        spread_key.push(key[i % key.len()]);
    }

    let mut cleartext = b"".to_vec();
    for index in 0..cipher.len() {
        let deciphered = cipher[index] ^ spread_key[index];
        cleartext.push(deciphered);
    }

    return cleartext;
}

pub fn encrypt_aes_cbc(
    plaintext: &Vec<u8>,
    iv: Vec<u8>,
    key: &Vec<u8>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let suite = Cipher::aes_128_ecb();

    let padded = pad_pkcs7(plaintext, suite.block_size())?;
    let mut offset;
    let mut cipher = vec![0; padded.len() + suite.block_size()];
    let mut previous_block = iv;
    let mut curr_block: Vec<u8>;
    let mut a = Crypter::new(suite, Mode::Encrypt, &key, None)?;
    let mut bytes_written = 0;
    for i in 0..(padded.len() / suite.block_size()) {
        offset = i * suite.block_size();
        curr_block = padded[offset..offset + suite.block_size()].to_vec();
        let intermediate = encrypt_repeating_key_xor(&curr_block, &previous_block)?;
        bytes_written += a.update(&intermediate, &mut cipher[bytes_written..])?;

        previous_block = curr_block.clone();
    }
    bytes_written += a.finalize(&mut cipher[bytes_written..])?;
    cipher.truncate(bytes_written);
    Ok(cipher)
}

pub fn decrypt_aes_cbc(
    cipher: &Vec<u8>,
    iv: Vec<u8>,
    key: &Vec<u8>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let suite = Cipher::aes_128_ecb();
    if cipher.len() % suite.block_size() != 0 {
        return Err(Box::from(format!(
            "Invalid cipher. Length is not a multiple of {}",
            suite.block_size()
        )));
    }

    let mut offset;
    let mut plaintext = b"".to_vec();
    let mut previous_block = iv;
    let mut curr_block;
    for i in 0..(cipher.len() / suite.block_size()) {
        offset = i * suite.block_size();
        curr_block = cipher[offset..offset + suite.block_size()].to_vec();
        let mut intermediate = decrypt(suite, key, None, &curr_block)?;
        intermediate.truncate(suite.block_size());
        let mut decrypted = decrypt_repeating_key_xor(&intermediate, &previous_block);
        plaintext.append(&mut decrypted);

        previous_block = curr_block.clone();
    }

    return Ok(plaintext);
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

    expected = b"YELLOW SUBMARINE\x05\x05\x05\x05\x05".to_vec();

    match pad_pkcs7(&b"YELLOW SUBMARINE".to_vec(), 7) {
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
        Err(e) => assert!(false, "Function threw an error: {}", e),
    }
}

#[test]
fn can_decrypt_repeating_key_xor() {
    let expected = b"YELLOW SUBMARINE".to_vec();
    let key = b"KEY".to_vec();

    let encrypted = encrypt_repeating_key_xor(&expected, &key)
        .map_err(|_| assert!(false, "Error encrypting plaintext"))
        .unwrap();

    let decrypted = decrypt_repeating_key_xor(&encrypted, &key);
    assert_eq!(expected, decrypted);
}

#[test]
fn can_encrypt_aes_cbc() {
    let suite = Cipher::aes_128_cbc();
    let key = b"YELLOW SUBMARINE".to_vec();
    let mut iv = b"".to_vec();
    for _ in 0..16 {
        iv.append(&mut b"\x00".to_vec());
    }
    let mut plaintext = b"test".to_vec();

    let mut expected = encrypt(suite, &key, Some(&iv), &plaintext).unwrap();

    // match encrypt_aes_cbc(&plaintext, iv.clone(), &key) {
    //     Ok(encrypted) => {
    //         assert!(
    //             false,
    //             "{:?}",
    //             decrypt_aes_cbc(&encrypted, iv.clone(), &key).unwrap()
    //         );
    //         assert_eq!(expected, encrypted)
    //     }
    //     Err(_) => assert!(false, "Function threw error unexpectedly"),
    // }

    plaintext = b"Longer than 16 bytes".to_vec();

    expected = encrypt(suite, &key, Some(&iv), &plaintext).unwrap();

    match encrypt_aes_cbc(&plaintext, iv.clone(), &key) {
        Ok(encrypted) => {
            assert!(
                false,
                "{:?}",
                decrypt_aes_cbc(&encrypted, iv.clone(), &key).unwrap()
            );
            assert_eq!(expected, encrypted)
        }
        Err(_) => assert!(false, "Function threw error unexpectedly"),
    }
}
