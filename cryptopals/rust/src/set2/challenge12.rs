use crate::utils::oracle::Oracle;
use std::error::Error;

pub fn run() -> Result<(), Box<dyn Error>> {
    let oracle = Oracle::new();

    // Discover block size
    let mut plaintext = b"A".to_vec();
    let mut cipher = oracle.blackbox_encrypt_aes_ecb(&plaintext)?;
    let mut last_block_size = cipher.len();
    let mut init_run = true;
    let mut padding_until_next_block = 0;
    let mut block_size = 0;

    // We first add more characters until a new block is added to the cipher.
    // From there, we can start fresh without having to take into account any additional
    // characters being added to the cipher.
    loop {
        plaintext.extend(b"A".to_vec());
        cipher = oracle.blackbox_encrypt_aes_ecb(&plaintext)?;
        if cipher.len() > last_block_size {
            if init_run {
                init_run = false;
                padding_until_next_block = plaintext.len();
                last_block_size = cipher.len();
                continue;
            }
            block_size = plaintext.len() - padding_until_next_block;
            println!("Block size is: {}", block_size);
            break;
        }
    }

    plaintext = (0..block_size * 4).map(|_| 41/*"A"*/).collect();
    cipher = oracle.blackbox_encrypt_aes_ecb(&plaintext)?;
    let pattern = cipher[16..20].to_vec();
    if pattern == cipher[32..36] && pattern == cipher[48..52] {
        println!("It's ECB!");
    }

    let mut index = block_size - 1;
    while index > 0 {
        plaintext = (0..index - 1).map(|_| 41/*"A"*/).collect();
        println!("{:?}", plaintext);
        
        index -= 1;
    }

    Ok(())
}