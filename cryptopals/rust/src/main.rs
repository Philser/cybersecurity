mod oracle;
mod set2;
mod utils;
use std::io::{self};

fn main() {
    let mut input = String::new();
    let stdin = io::stdin();

    loop {
        println!(
            r###"Available challenges:
        (10) - Implement CBC Mode
        (11) - An ECB/CBC Detection Oracle
        (12) - Byte-at-a-time ECB decryption (Simple)
        (13) - ECB cut-and-paste
        (q)  - Quit
    "###
        );

        input.clear();
        stdin
            .read_line(&mut input)
            .map_err(|_| "Whoops, something went wrong")
            .unwrap();
        println!("-----------------------------------------");
        input = input.trim_end_matches('\n').to_string();
        match input.as_ref() {
            // TODO: BAAAAD, Figure out a way to streamline error handling
            "10" => set2::challenge10::run().unwrap(),
            "11" => set2::challenge11::run().unwrap(),
            "12" => set2::challenge12::run().unwrap(),
            "13" => set2::challenge13::run().unwrap(),
            "q" => {
                println!("Goodbye");
                break;
            }
            _ => {
                println!("Invalid option: {}", input)
            }
        }
        println!("-----------------------------------------");
    }
}
