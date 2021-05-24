use crate::utils::profile::Profile;
use std::error::Error;

pub fn run() -> Result<(), Box<dyn Error>> {
    // Idea: Make first block (email={email}) one block_size long, then take away a byte.
    // Then proceed as in challenge 12.

    let mut profile = Profile::new()?;
    let mut encrypted_cookie = profile.profile_for("t@test.com")?;
    println!("{}", encrypted_cookie);

    encrypted_cookie = profile.profile_for("@test.com")?;
    println!("{}", encrypted_cookie);

    Ok(())
}
