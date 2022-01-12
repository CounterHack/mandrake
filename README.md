A binary analysis / instrumentation library for Rust.

# TODO

* Make sure all the arguments work
* Learn how to publish on cargo
* Document how to use effectively

# Author

Ron Bowes from Counter Hack

License: Apache

# Purpose

Mandrake is a framework for executing and instrumenting machine code or ELF
binaries. It'll execute either a full binary or a block of hex-encoded machine
code, and output the results as JSON or YAML.

The goal is to help understand or analyze unknown code. While most disassembly
tools (such as `ndisasm`) will do a great job of showing what each instruction
and opcode do, `mandrake` goes a step further and *executes* the code, showing
what actually ran.

That means that packed, self-modified, and looping code can be analyzed much
more easily, since you'll see very clearly which syscalls are being performed!

# Install

Right now, download + build. That's described later.

Later, we'll need to publish on `cargo`.

# Usage

`mandrake` has two modes, implemented as subcommnds - either `code` or `elf`.
You can run it with `--help` to see the full options, including for the
subcommands:

```
$ ./mandrake --help
$ ./mandrake code --help
$ ./mandrake elf --help
```

# Build

To build a debug version, install the Rust toolchain then use `cargo build` or
`cargo run`:

```
$ cargo build
   Compiling autocfg v1.0.1
   Compiling proc-macro2 v1.0.36
   [...]
Compiling mandrake v0.1.0 (/home/ron/counterhack/mandrake)
    Finished dev [unoptimized + debuginfo] target(s) in 23.02s
```

To build a release, install Docker then run `make` - that will build the
Mandrake binary as well as the `harness` executable (used for analyzing
raw shellcode):

```
$ make
docker build . -t build-mandrake -f Dockerfile.build
Sending build context to Docker daemon    422MB
Step 1/5 : FROM rust:latest
 ---> 4db2e2d14f99
Step 2/5 : MAINTAINER "Ron Bowes"
 ---> Using cache
 ---> 139c6de59829
Step 3/5 : RUN mkdir /src
 ---> Using cache
 ---> b932d35fb223
Step 4/5 : WORKDIR /src
 ---> Using cache
 ---> cd060ab50adc
Step 5/5 : CMD ["make", "indocker"]
 ---> Using cache
 ---> 09759d644859
Successfully built 09759d644859
Successfully tagged build-mandrake:latest
docker run --rm -v /home/ron/counterhack/mandrake:/src --env UID=1000 --env GID=1000 -ti build-mandrake
# Build the binary
cargo build --release
    Updating crates.io index
[...]
Compiling mandrake v0.1.0 (/src)
    Finished release [optimized] target(s) in 1m 12s
chown -R 1000:1000 .
strip target/release/mandrake
# Build the harness
cd harness && make
make[1]: Entering directory '/src/harness'
make[1]: Nothing to be done for 'all'.
make[1]: Leaving directory '/src/harness'
```

# Execute

# How to use it effectively

# How it works

# Appendix: Usage

This is just the output of `--help`. Be warned - I might forget to update this,
run the actual application for up-to-date help!

```
$ mandrake --help

USAGE:
    mandrake [OPTIONS] <SUBCOMMAND>

OPTIONS:
    -h, --help
            Print help information

        --hidden-address <HIDDEN_ADDRESS>
            Don't log addresses with this prefix (eg, 0x13370000)

        --hidden-mask <HIDDEN_MASK>
            The mask to apply before checking --hidden-address (eg, 0xFFFF0000)

    -i, --max-instructions <MAX_INSTRUCTIONS>
            The maximum number of instructions to read before stopping (to prevent infinite loops)
            [default: 128]

        --ignore-stderr
            

        --ignore-stdout
            

    -m, --minimum-viable-string <MINIMUM_VIABLE_STRING>
            The number of consecutive ASCII bytes to be considered a string [default: 6]

    -o, --output-format <OUTPUT_FORMAT>
            The output format (JSON or YAML) [default: JSON]

    -s, --snippit-length <SNIPPIT_LENGTH>
            The amount of context memory to read [default: 64]

    -V, --version
            Print version information

        --visible-address <VISIBLE_ADDRESS>
            Only log addresses in this range (unless they're hidden)

        --visible-mask <VISIBLE_MASK>
            The mask to apply before checking --visible-address (eg, 0xFFFF0000)

SUBCOMMANDS:
    code    
    elf     
    help    Print this message or the help of the given subcommand(s)
```

The `code` subcommand runs raw hex as machine code:

```
$ mandrake code --help
mandrake-code 

USAGE:
    mandrake code [OPTIONS] <CODE>

ARGS:
    <CODE>    The code, as a hex string (eg: "4831C0C3")

OPTIONS:
    -h, --help                 Print help information
        --harness <HARNESS>    The path to the required harness [default: ./harness/harness]
```

The harness is built along with `mandrake`, and is required to analyze raw
machine code.

The `elf` subcommand runs an elf executable with optional arguments:

```
$ mandrake elf --help
mandrake-elf 

USAGE:
    mandrake elf <ELF> [ARGS]...

ARGS:
    <ELF>        The ELF executable
    <ARGS>...    The argument(s) to pass to the ELF executable

OPTIONS:
    -h, --help    Print help information
```
