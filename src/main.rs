#![allow(dead_code)]

use std::env;

use simple_error::SimpleError;
use clap::{App, Arg};

// Import from the library
use mandrake::*;

fn main() {
    let matches = App::new("Mandrake CLI")
                           .version("1.0")
                           .author("Ron Bowes <ron@counterhack.com>")
                           .about("Executes and instruments executables or raw machine code")
                           .arg(Arg::with_name("code")
                                .short("C")
                                .long("code")
                                .value_name("HEX")
                                .help("Hex-encoded machine code to execute")
                                .takes_value(true))
                           .arg(Arg::with_name("elf")
                                .short("E")
                                .long("elf")
                                .value_name("ELF_FILE")
                                .help("ELF binary to execute")
                                .takes_value(true))
                           .get_matches();

    // Get the harness from ENV, if it's there
    let harness = env::var("HARNESS").ok();

    let mandrake = Mandrake::new();

    let result = match (matches.value_of("code"), matches.value_of("elf")) {
        (None,       Some(elf)) => mandrake.analyze_elf(elf),
        (Some(code), None)      => {
            match hex::decode(code) {
                Ok(code) => mandrake.analyze_code(code, harness),
                Err(e) => Err(SimpleError::from(e)),
            }
        },
        (None,       None)      => Err(SimpleError::new("Please specify -C <code> or -E <elf>!")),
        (Some(_),    Some(_))   => Err(SimpleError::new("Please specify -C <code> OR -E <elf>!")),
    };

    match result {
        Ok(r)  => println!("{}", serde_json::to_string_pretty(&r).unwrap()),
        Err(e) => eprintln!("Execution failed: {}", e.to_string()),
    };

}
