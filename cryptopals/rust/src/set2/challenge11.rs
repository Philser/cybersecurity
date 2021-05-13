use crate::utils;
use std::error::Error;

pub fn run() -> Result<(), Box<dyn Error>> {
    // The idea is that since we control the plaintext, we can insert a reoccurring pattern
    // that will reveal ECB because ECB ciphertexts keep patterns in the plain texts intact
    let crafted_plaintext = b"YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE\
        YELLOW SUBMARINEYELLOW SUBMARINE"
        .to_vec();
    let cipher = utils::crypto::aes_encryption_oracle(&crafted_plaintext);

    println!("{:?}", cipher);
    Ok(())
}
