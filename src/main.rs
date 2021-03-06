use std::fmt;
use std::path::Path;
use std::str::FromStr;

use simple_error::{SimpleError, bail};
use clap::Parser;
use clap_num::maybe_hex;

// Import from the library
use mandrake::mandrake::Mandrake;
use mandrake::visibility_configuration::VisibilityConfiguration;

#[derive(Debug)]
enum OutputFormat {
    JSON,
    YAML,
    PLAINTEXT,
    PICKLE,
}

impl FromStr for OutputFormat {
    type Err = SimpleError;

    fn from_str(input: &str) -> Result<OutputFormat, Self::Err> {
        match &input.to_lowercase()[..] {
            "json"   => Ok(OutputFormat::JSON),
            "yaml"   => Ok(OutputFormat::YAML),
            "pickle" => Ok(OutputFormat::PICKLE),
            "plaintext" | "text" => Ok(OutputFormat::PLAINTEXT),

            _       => bail!("Unknown format: {}", input),
        }
    }
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::JSON      => write!(f, "JSON"),
            Self::YAML      => write!(f, "YAML"),
            Self::PICKLE    => write!(f, "PICKLE"),
            Self::PLAINTEXT => write!(f, "PLAINTEXT"),
        }
    }
}


#[derive(Parser, Debug)]
#[clap(about, version, author)]
struct Elf {
    #[clap(flatten)]
    visibility_configuration: VisibilityConfiguration,

    /// Standard in, encoded as hex (eg, "4141414141")
    #[clap(long)]
    stdin_data: Option<String>,

    /// The ELF executable
    elf: String,

    /// The argument(s) to pass to the ELF executable
    args: Vec<String>,
}

#[derive(Parser, Debug)]
#[clap(about, version, author)]
struct Code {
    /// The code, as a hex string (eg: "4831C0C3")
    code: String,

    /// The path to the required harness
    #[clap(long, default_value_t = String::from("./harness/harness"))]
    harness: String,

    /// If set, doesn't hide instructions executed outside of the harness
    /// (helpful if, say, you're analyzing shellcode that allocates memory)
    #[clap(long)]
    show_everything: bool,
}

#[derive(clap::Subcommand, Debug)]
enum Action {
    /// Analyze raw machine code using a harness
    Code(Code),

    /// Analyze an ELF file (Linux executable)
    Elf(Elf),
}

/// Mandrake is an open-source machine code analyzer / instrumenter written in Rust.
#[derive(Parser, Debug)]
#[clap(name = "Mandrake", about, version, author)]
struct Args {
    /// The output format ("JSON", "YAML", "Plaintext", or "Pickle")
    #[clap(short, long, default_value_t = OutputFormat::JSON)]
    output_format: OutputFormat,

    /// The amount of context memory to read
    #[clap(short, long, default_value_t = 64, parse(try_from_str=maybe_hex))]
    snippit_length: usize,

    /// The number of consecutive ASCII bytes to be considered a string
    #[clap(short, long, default_value_t = 6, parse(try_from_str=maybe_hex))]
    minimum_viable_string: usize,

    /// The maximum number of instructions to read before stopping (to prevent infinite loops)
    #[clap(short='i', long, default_value_t = 1024, parse(try_from_str=maybe_hex))]
    max_instructions: usize,

    /// Don't save output from stdout
    #[clap(long)]
    ignore_stdout: bool,

    /// Don't save output from stderr
    #[clap(long)]
    ignore_stderr: bool,

    /// Enable to follow exec syscalls (usually not desirable, because exec starts a process from scratch and following that is very slow)
    #[clap(long)]
    follow_exec_syscalls: bool,

    #[clap(subcommand)]
    action: Action,
}

/// Main intentially does not return an error.
///
/// That means that we're sorta forced to handle all errors cleanly (or
/// panic :) ).
fn main() {
    // Parse the commandline options
    let args = Args::parse();

    // Create an instance of Mandrake with the configurations
    let mandrake = Mandrake::new(
        args.snippit_length,
        args.minimum_viable_string,
        Some(args.max_instructions),
        args.ignore_stdout,
        args.ignore_stderr,
        args.follow_exec_syscalls,
    );

    // Check which subcommand they ran
    let result = match args.action {
        Action::Code(code_args) => {
            match hex::decode(code_args.code) {
                Ok(code) => mandrake.analyze_code(code, &Path::new(&code_args.harness), code_args.show_everything),
                Err(e) => Err(SimpleError::new(format!("Could not decode hex: {}", e))),
            }
        },
        Action::Elf(elf_args) => {
            mandrake.analyze_elf(&Path::new(&elf_args.elf), elf_args.stdin_data, elf_args.args, &elf_args.visibility_configuration)
        },
    };

    // Handle errors somewhat more cleanly than just bailing
    match result {
        Ok(r)  => match args.output_format {
            OutputFormat::JSON   => println!("{}", serde_json::to_string_pretty(&r).unwrap()),
            OutputFormat::YAML   => println!("{}", serde_yaml::to_string(&r).unwrap()),
            OutputFormat::PICKLE => {
                println!("import base64");
                println!("import pickle");
                println!();
                println!("pickle.loads(base64.b64decode(\"{}\"))", base64::encode(serde_pickle::to_vec(&r, Default::default()).unwrap()));
            },
            OutputFormat::PLAINTEXT => {
                for entry in r.history {
                    match entry.get("rip") {
                        Some(entry) => {
                            println!("{}", entry);
                        },
                        None => {
                            eprintln!("Missing rip in entry");
                        },
                    }
                }

                if let Some(stdout) = r.stdout {
                    if stdout != "" {
                        println!();
                        println!("Stdout: {}", stdout);
                    }
                }

                if let Some(stderr) = r.stderr {
                    if stderr != "" {
                        println!();
                        println!("stderr: {}", stderr);
                    }
                }
            },
        },
        Err(e) => eprintln!("Execution failed: {}", e.to_string()),
    };
}
