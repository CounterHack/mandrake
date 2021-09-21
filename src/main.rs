#![allow(dead_code)]

use std::env;
use std::process::exit;

// Import from the library
use mandrake::*;

fn main() {
    let args: Vec<String> = env::args().collect();

    // Get the code, passed in as an argument
    if args.len() != 2 {
        println!("Usage: {} <binary>", args[0]);
        exit(1);
    }

    let out = instrument_binary(&args[1]).unwrap();
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
