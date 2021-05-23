use crate::utils::crypto;
use rand::Rng;
use std::error::Error;

pub struct Oracle {
    key: Vec<u8>,
    blackbox_plaintext: Vec<u8>,
}

impl Oracle {
    pub fn new(blackbox_b64string: Option<String>) -> Result<Oracle, Box<dyn Error>> {
        let blackbox_string;

        if blackbox_b64string.is_some() {
            blackbox_string = base64::decode(blackbox_b64string.unwrap())?;
        } else {
            blackbox_string = base64::decode(
                "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
        YnkK",
            )?;
        }

        Ok(Oracle {
            key: Oracle::generate_random_byte_vec(16),
            blackbox_plaintext: blackbox_string,
        })
    }

    pub fn blackbox_encrypt_aes_ecb(&self, plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut to_encrypt = plaintext.to_vec();
        let unknown_string = &self.blackbox_plaintext;
        to_encrypt.extend(unknown_string);

        crypto::encrypt_aes_ecb(&to_encrypt, &self.key)
    }

    pub fn decrypt_aes_ecb(&self, cipher: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        crypto::decrypt_aes_ebc(cipher, &self.key, true)
    }

    /**
     * Static methods
     * */

    fn generate_random_byte_vec(len: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();

        (0..len)
            .map(|_| {
                let byte: u8 = rng.gen();
                byte
            })
            .collect()
    }

    pub fn aes_encryption_oracle(plaintext: &[u8]) -> Result<(Vec<u8>, &str), Box<dyn Error>> {
        let key = Oracle::generate_random_byte_vec(16);

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
                let iv = Oracle::generate_random_byte_vec(16);
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
}
