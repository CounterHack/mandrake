#![allow(dead_code)]

use std::env;
use std::process::exit;

// Import from the library
use mandrake::*;

fn main() {
    let args: Vec<String> = env::args().collect();

    // Get the code, passed in as an argument
//if args.len() != 2 {
//    println!("Usage: {} <binary>", args[0]);
//    exit(1);
//}

    let mandrake = Mandrake::new();
    //let out = mandrake.analyze_elf(&args[1]).unwrap();
    let out = mandrake.analyze_code(b"\xe8\x0c\x00\x00\x00\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x00\xb8\x02\x00\x00\x00\x5f\xbe\x00\x00\x00\x00\xba\x00\x00\x00\x00\x0f\x05\x48\x89\xc7\xb8\x00\x00\x00\x00\x48\x89\xe6\xba\x64\x00\x00\x00\x0f\x05\x48\x89\xc2\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x89\xe6\x0f\x05\xb8\x3c\x00\x00\x00\xbf\x00\x00\x00\x00\x0f\x05".to_vec(), None).unwrap();

    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
