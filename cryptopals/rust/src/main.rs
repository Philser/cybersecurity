mod set2;
mod utils;

fn main() {
    // match set2::challenge10::run() {
    //     Ok(_) => println!("Challenge 10 done"),
    //     Err(e) => println!("Challenge 10 failed with: {}", e),
    // }

    set2::challenge10::run().unwrap();
}
