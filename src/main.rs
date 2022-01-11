#![allow(dead_code)]

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use simple_error::{SimpleResult, SimpleError, bail};
use clap::Parser;
use clap_num::maybe_hex;

// Import from the library
use mandrake::mandrake::Mandrake;

#[derive(Debug)]
enum OutputFormat {
    JSON,
    YAML,
}

impl FromStr for OutputFormat {
    type Err = SimpleError;

    fn from_str(input: &str) -> Result<OutputFormat, Self::Err> {
        match &input.to_lowercase()[..] {
            "json"  => Ok(OutputFormat::JSON),
            "yaml"  => Ok(OutputFormat::YAML),
            _       => bail!("Unknown format: {}", input),
        }
    }
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::JSON => write!(f, "JSON"),
            Self::YAML => write!(f, "YAML"),
        }
    }
}


#[derive(Parser, Debug)]
struct Elf {
    /// The ELF executable
    elf: String,

    /// The argument(s) to pass to the ELF executable
    args: Vec<String>,
}

#[derive(Parser, Debug)]
struct Code {
    /// The code, as a hex string (eg: "4831C0C3")
    code: String,

    /// The path to the required harness
    #[clap(long, default_value_t = String::from("./harness/harness"))]
    harness: String,
}

#[derive(clap::Subcommand, Debug)]
enum Action {
    Elf(Elf),
    Code(Code),
}

#[derive(Parser, Debug)]
#[clap(about, version, author)]
struct Args {
    /// The output format (JSON or YAML)
    #[clap(short, long, default_value_t = OutputFormat::JSON)]
    output_format: OutputFormat,

    /// The amount of context memory to read
    #[clap(short, long, default_value_t = 64, parse(try_from_str=maybe_hex))]
    snippit_length: usize,

    /// The number of consecutive ASCII bytes to be considered a string
    #[clap(short, long, default_value_t = 6, parse(try_from_str=maybe_hex))]
    minimum_viable_string: usize,

    /// The maximum number of instructions to read before stopping (to prevent infinite loops)
    #[clap(short='i', long, default_value_t = 128, parse(try_from_str=maybe_hex))]
    max_instructions: usize,

    /// Don't log addresses with this prefix (eg, 0x13370000)
    #[clap(long, parse(try_from_str=maybe_hex))]
    hidden_address: Option<u64>,

    /// The mask to apply before checking --hidden-address (eg, 0xFFFF0000)
    #[clap(long, parse(try_from_str=maybe_hex))]
    hidden_mask: Option<u64>,

    /// Only log addresses in this range (unless they're hidden)
    #[clap(long, parse(try_from_str=maybe_hex))]
    visible_address: Option<u64>,

    /// The mask to apply before checking --visible-address (eg, 0xFFFF0000)
    #[clap(long, parse(try_from_str=maybe_hex))]
    visible_mask: Option<u64>,

    #[clap(long)]
    ignore_stdout: bool,

    #[clap(long)]
    ignore_stderr: bool,

    #[clap(subcommand)]
    action: Action,
}

fn main() -> SimpleResult<()> {
    let args = Args::parse();

    println!("{:?}", args);

    let mandrake = Mandrake::new(
        args.snippit_length,
        args.minimum_viable_string,
        Some(args.max_instructions),
        args.hidden_address,
        args.hidden_mask,
        args.visible_address,
        args.visible_mask,
        args.ignore_stdout,
        args.ignore_stderr
    );

    let result = match args.action {
        Action::Code(code_args) => {
            match hex::decode(code_args.code) {
                Ok(code) => mandrake.analyze_code(code, &Path::new(&code_args.harness)),
                Err(e) => Err(SimpleError::new(format!("Could not decode hex: {}", e))),
            }
        },
        Action::Elf(elf_args) => {
            mandrake.analyze_elf(&Path::new(&elf_args.elf), vec![])
        },
    };

    match result {
        Ok(r)  => match args.output_format {
            OutputFormat::JSON => println!("{}", serde_json::to_string_pretty(&r).unwrap()),
            OutputFormat::YAML => println!("{}", serde_yaml::to_string(&r).unwrap()),
        },
        Err(e) => eprintln!("Execution failed: {}", e.to_string()),
    };

    Ok(())
}
