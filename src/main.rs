#![allow(dead_code)]

use std::env;
use std::process;

use simple_error::{SimpleResult, SimpleError};
use clap::{App, Arg, AppSettings};

// Import from the library
use mandrake::*;

fn handle_code(mandrake: &Mandrake, code: &str) -> SimpleResult<MandrakeOutput> {
    let harness = env::var("HARNESS").ok();

    match hex::decode(code) {
        Ok(code) => mandrake.analyze_code(code, harness),
        Err(e) => Err(SimpleError::from(e)),
    }
}

fn handle_elf(mandrake: &Mandrake, elf: &str, args: Vec<&str>) -> SimpleResult<MandrakeOutput> {
    mandrake.analyze_elf(elf, args)
}

fn main() {
    let matches = App::new("Mandrake CLI")
                           .version("1.0")
                           .author("Ron Bowes <ron@counterhack.com>")
                           .about("Executes and instruments executables or raw machine code")

                           // Must use a subcommand
                           .setting(AppSettings::SubcommandRequiredElseHelp)
                           .subcommand(App::new("code")
                                       .about("Run code (encoded as hex)")
                                       .arg(Arg::with_name("CODE")
                                           .help("The code to execute, as a hex string")
                                           .required(true)
                                           .index(1)
                                       )
                           )

                           .subcommand(App::new("elf")
                                       .about("Run an ELF binary")
                                       .arg(Arg::with_name("ELF")
                                           .help("The binary to execute")
                                           .required(true)
                                           .index(1)
                                       )
                                       .arg(Arg::with_name("arg")
                                           .short("a")
                                           .long("arg")
                                           .help("An argument to pass to the binary (can have multiple)")
                                           .takes_value(true)
                                           .multiple(true)
                                       )
                           )

                           .get_matches();

    let mandrake = Mandrake::new();

    let result = if let Some(matches) = matches.subcommand_matches("code") {
        handle_code(&mandrake, matches.value_of("CODE").unwrap_or_else(|| {
            eprintln!("Code missing");
            process::exit(1);
        }))

    } else if let Some(matches) = matches.subcommand_matches("elf") {
        println!("{:?}", matches);

        let args: Vec<&str> = match matches.values_of("arg") {
            Some(a) => a.collect(),
            None => vec![],
        };

        handle_elf(&mandrake, matches.value_of("ELF").unwrap_or_else(|| {
            eprintln!("ELF path missing");
            process::exit(1);
        }), args)

    } else {
        eprintln!("No valid subcommand found - run with `elf` or `code`!");
        process::exit(1);
    };

    match result {
        Ok(r)  => println!("{}", serde_json::to_string_pretty(&r).unwrap()),
        Err(e) => eprintln!("Execution failed: {}", e.to_string()),
    };

}
