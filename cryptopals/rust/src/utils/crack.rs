use std::error::Error;

use crate::oracle::{ecb_oracle::ECBOracle, oracle_trait::Oracle};

pub enum AesMode {
    Ecb,
    Cbc 
}

// TODO: This function ought to be applied to chall 12 & 14! (is this even possible?)
pub fn decipher_ecb_oracle_secret(oracle: &ECBOracle) -> Result<Vec<u8>, Box<dyn Error>> {
    // 1. Discover block size
    let block_size = discover_block_size(oracle)?;

    // 2. Detect cipher mode
    match detect_cipher_mode(oracle, block_size)? {
        AesMode::Ecb => {/*let's continue*/},
        _ => return Err(Box::from("Error: Cipher is not in ECB mode"))
    }

    // Bonus: Detect and evade prefix
    // B.1: Set a "prefix length" value to 0
    // B.2: Insert recurring pattern and look for repeating blocks at start of array
    // B.3.1: If recurring pattern was found BUT not of original length, increase "prefix length"
    // B.3.2: If recurring pattern of right length was found, "prefix length" is the right value
    //        and we memorize at which position the recurring pattern was found
    // B.4: For attacking the cipher, we now always insert "prefix length" and drop the first
    //      blocks that we know only hold the random prefix
    let (a, b) = get_prefix_counter_measures(oracle, block_size)?;


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
    oracle: &dyn Oracle,
    block_size: usize, 
    ) -> Result<AesMode, Box<dyn Error>> {
    let plaintext: Vec<u8> = (0..block_size*4).map(|_| 65/*"A"*/).collect();
    let cipher = oracle.get_encrypted(&plaintext)?;
    
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

/// Returns a tuple of (prefix_length, pos) where **prefix_length** is the number of chars
/// required to be inserted into oracle input so that **pos** is the block where the actual
/// input starts, with an oracle's inserted prefix being in the blocks before **pos**.
fn get_prefix_counter_measures(
    oracle: &dyn Oracle, 
    block_size: usize
) -> Result<(usize, usize), Box<dyn Error>> {
    let pattern_count = 4;
    
    let mut prefix_length = 0;
    let pattern: Vec<u8> = (0..block_size * pattern_count).map(|_| 41).collect();

    // TODO: Find prefix_length by observing block count
    
    while prefix_length < block_size - 1 {
        let mut input = (0..prefix_length).map(|_| 0).collect::<Vec<u8>>();
        input.extend(&pattern);

        let cipher = oracle.get_encrypted(&input)?;
        
        // Check if blocks at pos..pos + pattern_count are all equal
        let blocks = cipher.len() / block_size;
        for pos in 0..=blocks - pattern_count {
            let mut blocks_are_equal = true;
            let curr_slice = &cipher[pos * block_size .. pos * block_size + block_size];
            
            for i in pos + 1..pos + pattern_count {
                let next_slice = &cipher[i * block_size .. i * block_size + block_size];
                
                blocks_are_equal = *curr_slice == *next_slice;
            }

            if blocks_are_equal {
                return Ok((prefix_length, pos));
            }
        }

        prefix_length += 1;
    }

    Ok((0, 0))
}

#[test]
fn can_get_prefix_counter_measures() -> Result<(), Box<dyn Error>> {
    struct DummyOracle {}
    impl Oracle for DummyOracle {
        fn get_encrypted(&self, plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
            // One and a half block sizes of prefix
            let mut cipher: Vec<u8> = (0..24).map(|_| 50).collect(); 
            cipher.extend(plaintext.to_vec());

            Ok(cipher)
        }
    }

    let dummy = DummyOracle{};
    let (prefix_len, pos) = get_prefix_counter_measures(&dummy, 16)?;

    assert_eq!(8, prefix_len);
    assert_eq!(2, pos);

    Ok(())
}


// TODO: Tests