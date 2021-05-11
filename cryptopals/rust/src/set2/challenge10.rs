use crate::utils::crypto::decrypt_aes_cbc;
use base64;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{prelude::*, BufReader};
use std::str;

pub fn run() -> Result<(), Box<dyn Error>> {
    let cwd = env::current_dir()?;
    println!("{}", cwd.as_path().display());
    let mut iv = b"".to_vec();
    for _ in 0..16 {
        iv.append(&mut b"\x00".to_vec());
    }

    let file = File::open(cwd.join("src/set2/challenge10.enc"))?;
    let reader = BufReader::new(file);
    let mut contents = "".to_owned();
    for line in reader.lines() {
        contents.push_str(&line?);
    }
    let decoded = base64::decode(contents)?;

    let decrypted = decrypt_aes_cbc(&decoded, iv, &b"YELLOW SUBMARINE".to_vec(), false)?;

    unsafe {
        println!("Decrypted:\n{}", str::from_utf8_unchecked(&decrypted));
    }

    Ok(())
}
