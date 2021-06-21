use std::error::Error;

use crate::oracle::{ecb_prefix_oracle::ECBPrefixOracle, oracle::Oracle};

pub enum AesMode {
    Ecb,
    Cbc 
}

pub fn decipher_oracle_secret(oracle: &dyn Oracle) -> Result<Vec<u8>, Box<dyn Error>> {
    // 1. Discover block size
    let block_size = discover_block_size(oracle)?;

    let plaintext: Vec<u8> = (0..block_size*4).map(|_| 65/*"A"*/).collect();
    let cipher = oracle.get_encrypted(&plaintext)?;

    // 2. Detect cipher mode
    match detect_cipher_mode(&plaintext, &cipher, block_size)? {
        AesMode::Ecb => {/*let's continue*/},
        _ => return Err(Box::from("Error: Cipher is not in ECB mode"))
    }


    // 3. - 6.
    let mut char_sequence: Vec<u8> = (0..block_size).map(|_| 65/*"A"*/).collect();
    let pure_cipher = oracle.get_encrypted(&b"".to_vec())?;
    let mut plaintext = b"".to_vec();
    for curr_block in 0..(pure_cipher.len() / block_size) {        
        let offset = curr_block * block_size;
        let mut secret = b"".to_vec();
        
        for _ in 0..block_size  {
            // 3. Craft input block that is one byte short
            
            if !char_sequence.is_empty() {
                char_sequence.remove(0); // Left shift by one at a time
            }
            let cipher = oracle.get_encrypted(&char_sequence)?;

            let mut guess = char_sequence.clone();
            guess.extend(&secret);

            if plaintext.len() + secret.len() == pure_cipher.len() {
                return Ok(plaintext);
            }

            // 4.-5. Brute force next byte by trying every possible byte and look for match
            match bruteforce_aes_ebc_byte(
                &guess, 
                &cipher[offset..offset + block_size], 
                oracle,
            ) {
                Ok(character) => secret.push(character),
                Err(_) => {
                    // Let's just assume that if he cannot brute force the next char it
                    // is because he reached the end of the string.
                    // TODO: We could also check if it is a padding char and only then stop, else
                    // throw an error
                    break;
                }
            }
        }

        plaintext.extend(&secret);
        char_sequence = secret;
    }
    
    Ok(plaintext)
}

fn discover_block_size(oracle: &dyn Oracle) -> Result<usize, Box<dyn Error>> {
    let mut plaintext = b"A".to_vec();
    let mut cipher = oracle.get_encrypted(&plaintext)?;
    let mut last_cipher_len = cipher.len();
    let mut init_run = true;
    let mut padding_until_next_block = 0;
    let block_size;

    // We first add more characters until a new block is added to the cipher.
    // From there, we can start fresh without having to take into account any additional
    // characters being added to the cipher.
    loop {
        plaintext.extend(b"A".to_vec());
        cipher = oracle.get_encrypted(&plaintext)?;
        if cipher.len() > last_cipher_len {
            if init_run {
                init_run = false;
                padding_until_next_block = plaintext.len();
                last_cipher_len = cipher.len();
                continue;
            }
            block_size = plaintext.len() - padding_until_next_block;
            break;
        }
    }

    Ok(block_size)
}

pub fn detect_cipher_mode(
    plaintext: &[u8],
    cipher: &[u8],
    block_size: usize, 
    ) -> Result<AesMode, Box<dyn Error>> {
    if plaintext.len() < block_size*3 {
        return Err(Box::from("Plaintext needs to have a length of at least three times the block size"));
    }

    if plaintext[block_size..block_size*2] != plaintext[block_size*2 .. block_size*3] {
        return Err(Box::from("Plaintext needs to be a recurring pattern"));
    }
    
    let pattern = cipher[block_size..block_size*2].to_vec();
    if pattern == cipher[block_size*2..block_size*3] {
        return Ok(AesMode::Ecb);
    }

    Ok(AesMode::Cbc)
}

fn bruteforce_aes_ebc_byte(
    plaintext: &[u8], 
    cipher_block: &[u8], 
    oracle: &dyn Oracle, 
) -> Result<u8, Box<dyn Error>> {
    let mut printable_chars = 
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!$%&/()=?*',.-;:_ +\n\t~#<>|\\".to_vec();  
    
    let paddings: Vec<u8> = (1..cipher_block.len()).map(|i| i as u8).collect();
    printable_chars.extend(paddings);
       
    for letter in printable_chars.iter() {
        let mut guess = plaintext.to_vec();
        guess.push(*letter);
    
        if &oracle.get_encrypted(&guess)?[0..cipher_block.len()] == cipher_block {
            return Ok(*letter);
        }
    }
    
    Err(
        Box::from(
            format!("Could not bruteforce character. Plaintext: {}", String::from_utf8(plaintext.to_vec())?)
        ))
}