mod set2;
mod utils;
use std::io::{self, Read};

fn main() {
    let mut input = String::new();

    loop {
        println!(
            r###"Available challenges:
        (10) - Implement CBC Mode
        (q)  - Quit
    "###
        );

        io::stdin()
            .read_line(&mut input)
            .map_err(|_| "Whoops, something went wrong")
            .unwrap();
        input = input.trim_end_matches("\n").to_string();
        match input.as_ref() {
            // TODO: BAAAAD, Figure out a way to streamline error handling
            "10" => set2::challenge10::run().unwrap(),
            "q" => {
                println!("Goodbye");
                break;
            }
            _ => {
                println!("Invalid option")
            }
        }
    }
}
