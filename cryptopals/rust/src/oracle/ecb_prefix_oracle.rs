use crate::oracle::oracle::Oracle;
use crate::oracle::utils::generate_random_byte_vec;
use crate::utils::crypto;
use std::error::Error;

pub struct ECBPrefixOracle {
    key: Vec<u8>,
    blackbox_plaintext: Vec<u8>,
}

impl Oracle for ECBPrefixOracle {
    fn get_encrypted(&self, plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut to_encrypt = plaintext.to_vec();
        to_encrypt.extend(&self.blackbox_plaintext);

        crypto::encrypt_aes_ecb(&to_encrypt, &self.key)
    }
}

impl ECBPrefixOracle {
    pub fn new(blackbox_b64string: Option<String>) -> Result<ECBPrefixOracle, Box<dyn Error>> {
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

        Ok(ECBPrefixOracle {
            key: generate_random_byte_vec(16),
            blackbox_plaintext: blackbox_string,
        })
    }

    pub fn decrypt_aes_ecb(&self, cipher: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        crypto::decrypt_aes_ebc(cipher, &self.key, true)
    }
}
