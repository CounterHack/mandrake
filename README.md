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

*Warning: This DOES run the code on your machine, using Ptrace. You probably don't want to analyze malicious code!*

# Installation

Right now, download + build using `cargo`. That's described later.

Later, we'll need to publish properly on `cargo`.

# Usage

`mandrake` has two modes, implemented as subcommnds - either `code` or `elf`.
You can run it with `--help` to see the full options, including for the
subcommands:

```
$ ./mandrake --help
$ ./mandrake code --help
$ ./mandrake elf --help
```

## Code Mode

To use `mandrake` to analyze raw machine code, you need two things:

* The `harness` executable - available on Github
* The hex-encoded machine code

How you get hex-encoded machine code is sort of up to you, but if you want
something simple to test, try `c3` (`ret`) or `4831c048ffc0c3`
(`xor rax, rax` / `inc rax` / `ret`) - aka, `return 1`.

You can either run the `mandrake` executable, or use `cargo run --` as shown
below:

```
$ cargo run -- --snippit-length 4 code 'c3'

{
  "success": true,
  "pid": 1046429,
  "history": [
    {
      "rdx": {
        "value": 0,
        "memory": null,
        "as_instruction": null,
        "as_string": null
      },
      "rip": {
        "value": 322371584,
        "memory": [
          195
        ],
        "as_instruction": "ret",
        "as_string": null
      },
[...]
    }
  ],
  "stdout": "",
  "stderr": "",
  "exit_reason": "Process exited cleanly with exit code 0",
  "exit_code": 0
}
```

This example also demonstrates how to use a custom path to the `harness`:

```
$ cargo run -- --snippit-length 4 code --harness=./harness/harness '4831c048ffc0c3'

{
  "success": true,
  "pid": 1053809,
  "history": [
    {
      "rbx": {
        "value": 0,
        "memory": null,
        "as_instruction": null,
        "as_string": null
      },
[...]
"rip": {
        "value": 322371590,
        "memory": [
          195
        ],
        "as_instruction": "ret",
        "as_string": null
      },
      "rdi": {
        "value": 0,
        "memory": null,
        "as_instruction": null,
        "as_string": null
      }
    }
  ],
  "stdout": "",
  "stderr": "",
  "exit_reason": "Process exited cleanly with exit code 1",
  "exit_code": 1
}
```

If the shellcode crashes, that's also fine; this shellcode runs
`push 0x41414141` / `ret`, which will crash at `0x41414141`:

```
$ cargo run -- --snippit-length 4 code --harness=./harness/harness '6841414141c3'
   Compiling mandrake v0.1.0 (/home/ron/counterhack/mandrake)
    Finished dev [unoptimized + debuginfo] target(s) in 1.92s
     Running `target/debug/mandrake --snippit-length 4 code --harness=./harness/harness 6841414141c3`

{
  "success": true,
  "pid": 1054409,
  "history": [
    {
[...]
    }
  ],
  "stdout": "",
  "stderr": "",
  "exit_reason": "Execution crashed with a segmentation fault (SIGSEGV) @ 0x41414141",
  "exit_code": null
}
```

We can also capture `stdout`:

```
$ cargo run -- --snippit-length 4 code 'e80d00000048656c6c6f20576f726c64210048c7c00100000048c7c7010000005e48c7c20c0000000f05c3'
{                              
  "success": true,             
  "pid": 1055334,        
  "history": [                 
[...]
  ],
  "stdout": "Hello World!",
  "stderr": "",
  "exit_reason": "Process exited cleanly with exit code 12",
  "exit_code": 12
```

## Elf mode

In addition to raw shellcode, we can also instrument an ELF (Linux) binary! We
haven't used ELF binaries as much as shellcode, so 

## What do I do with All That JSON?

Well, you can also output with `--output-format=YAML`. :)

We can actually support any type that [Serde](https://serde.rs/) supports,
please file a bug or send a patch if you'd like Pickle or something.

But to answer the question.. I dunno! At Counter Hack, we wrapped a web
interface around it to teach shellcoding. I bet there are a lot more cool
things you can do, though, use your imagination!

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

# How it works

# Appendix: Usage

This is just the output of `--help`. Be warned - I might forget to update this,
run the actual application for up-to-date help!

