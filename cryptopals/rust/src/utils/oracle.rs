use crate::utils::crypto;
use rand::Rng;
use std::error::Error;

fn generate_random_8_bytes() -> Vec<u8> {
    let mut rng = rand::thread_rng();

    (0..16)
        .map(|_| {
            let byte: u8 = rng.gen();
            byte
        })
        .collect()
}

pub fn aes_encryption_oracle(plaintext: &[u8]) -> Result<(Vec<u8>, &str), Box<dyn Error>> {
    let key = generate_random_8_bytes();

    let mut rng = rand::thread_rng();
    let mut to_encrypt: Vec<u8> = (0..rng.gen_range(5..=10))
        .map(|_| {
            let byte: u8 = rng.gen();
            byte
        })
        .collect();
    let postfix: Vec<u8> = (0..rng.gen_range(5..=10))
        .map(|_| {
            let byte: u8 = rng.gen();
            byte
        })
        .collect();

    to_encrypt.extend(&plaintext.to_vec());
    to_encrypt.extend(&postfix);

    let cipher;
    let mode;
    match rng.gen_range(0..=1) {
        0 => {
            mode = "CBC";
            let iv = generate_random_8_bytes();
            cipher = crypto::encrypt_aes_cbc(&to_encrypt, iv, &key)?;
        }
        1 => {
            mode = "ECB";
            cipher = crypto::encrypt_aes_ecb(&to_encrypt, &key)?
        }
        _ => {
            panic!("Good lord! The RNG produced a number other than 0 or 1!")
        }
    };

    Ok((cipher, mode))
}
