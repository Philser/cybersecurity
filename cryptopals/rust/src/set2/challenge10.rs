use crate::utils::crypto::decrypt_aes_cbc;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::str;

pub fn run() -> Result<(), Box<dyn Error>> {
    let cwd = env::current_dir()?;
    println!("{}", cwd.as_path().display());
    let mut iv = b"".to_vec();
    for _ in 0..16 {
        iv.append(&mut b"\x00".to_vec());
    }
    let mut file = File::open(cwd.join("src/set2/challenge10.enc"))?;
    let mut contents: Vec<u8> = Vec::new();
    file.read_to_end(&mut contents)?;

    let decrypted = decrypt_aes_cbc(&contents, iv, &b"YELLOW SUBMARINE".to_vec())?;

    println!("Decrypted:\n{}", hex::encode(&decrypted));

    Ok(())
}
