use crate::oracle::ecb_prefix_oracle::ECBPrefixOracle;
use crate::utils::crack::decipher_oracle_secret;
use std::error::Error;

pub fn run() -> Result<(), Box<dyn Error>> {
    let oracle = ECBPrefixOracle::new(None)?;
    println!(
        "Secret: {}",
        String::from_utf8(decipher_oracle_secret(&oracle)?)?
    );
    Ok(())
}
