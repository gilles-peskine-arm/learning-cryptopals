use std::env;
use base64::prelude::*;

fn main() {
    let args: Vec<String> = env::args().collect();
    // Panic if there are no arguments
    let hex_string = &args[1];
    // Panic if the hex string is invalid
    let data = hex::decode(hex_string).expect("Invalid hex string");
    // Panic if there isn't enough memory
    let base64_string = BASE64_STANDARD.encode(&data);
    println!("{}", base64_string);
}
