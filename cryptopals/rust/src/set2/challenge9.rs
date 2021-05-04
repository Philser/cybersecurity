use crate::utils::crypto::pad_pkcs7;
use std::error::Error;

pub fn run() -> Result<(), Box<dyn Error>> {
    let expected = "YELLOW SUBMARINE\x04\x04\x04\x04";
    let padded = pad_pkcs7("YELLOW SUBMARINE", 20)?;

    assert_eq!(expected, padded);

    Ok(())
}
