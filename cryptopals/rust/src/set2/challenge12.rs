use crate::utils::crack;
use crate::utils::{crack::decipher_oracle_secret, oracle::Oracle};
use std::error::Error;

pub fn run() -> Result<(), Box<dyn Error>> {
    let oracle = Oracle::new(None)?;
    println!(
        "Secret: {}",
        String::from_utf8(decipher_oracle_secret(&oracle)?)?
    );
    Ok(())
}
