use crate::oracle::Oracle;
use crate::utils::crypto;
use rand::Rng;
use std::error::Error;

pub struct SimpleECBOracle {
    key: Vec<u8>,
    blackbox_plaintext: Vec<u8>,
    random_prefix: Vec<u8>,
}

impl Oracle for SimpleECBOracle {
    fn produce_cipher(&self) -> [u8] {
        let mut to_encrypt = plaintext.to_vec();
        to_encrypt.extend(&self.blackbox_plaintext);

        crypto::encrypt_aes_ecb(&to_encrypt, &self.key)
    }
}

impl SimpleECBOracle {
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
            random_prefix: Oracle::generate_random_byte_vec_arbitrary_length(),
        })
    }

    pub fn blackbox_encrypt_aes_ecb(&self, plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut to_encrypt = plaintext.to_vec();
        to_encrypt.extend(&self.blackbox_plaintext);

        crypto::encrypt_aes_ecb(&to_encrypt, &self.key)
    }

    pub fn blackbox_encrypt_aes_ecb_random_prefix(
        &self,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut to_encrypt = self.random_prefix.to_vec();
        to_encrypt.extend(plaintext.to_vec());
        to_encrypt.extend(&self.blackbox_plaintext);

        crypto::encrypt_aes_ecb(&to_encrypt, &self.key)
    }

    pub fn decrypt_aes_ecb(&self, cipher: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        crypto::decrypt_aes_ebc(cipher, &self.key, true)
    }
}
