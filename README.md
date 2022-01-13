A binary analysis / instrumentation library for Rust.

# Author

Ron Bowes from Counter Hack

License: MIT

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

*This must be run on an x64-based Linux system!*

The best way to execute `mandrake` is to check it out from
[the Github repo](https://github.com/counterhack/mandrake), then build + run
with either `cargo` (the Rust toolchain) or `docker`.

## Executing with cargo

To run with `cargo`, you need the `edition2021` edition of Rust (which usually
means installing [rustup](https://rustup.rs/) (or using the `rust:latest`
Docker image). Probably distros will start including that edition in their
repos eventually, and I hate depending on it, but some of the dependencies I
pull in require it.

Once you have `cargo` and `edition2021`, you can build and run from source:

```
$ git clone https://github.com/CounterHack/mandrake.git
$ cd mandrake
$ mandrake --help
```

## Installing with docker

Alternatively, we include a `Makefile` that just uses the `rust:latest` Docker
container. You can run `make` to use that:

```
$ make run
docker build . -t mandrake-build -f Dockerfile.build

[...]

Successfully tagged mandrake-execute:latest

To execute, run:

docker run --rm -ti mandrake-execute --help
```

Or you can use an interactive Docker environment directly:

```
$ docker run -ti -v $PWD:/src rust:latest /bin/bash
root@6764c399bc84:/# cd src
root@6764c399bc84:/src# mandrake --help
```

## Building a Binary

We have included a Dockerfile to build binary releases. To build a release,
execute `make` in the source directory. That will use `docker` to build
releases in the `build/` directory.

Once those are built, you should be able to execute `build/mandrake` with no
extra dependencies (besides the hardness, which will also be compiled into
`build/`.

*We plan to do proper binary releases but have not yet. By the time this is
public, we'll have a link here.*

# Usage

For the remainder, of this README, we will assume you are executing using
a `mandrake` binary. You can just as easily use `cargo run --` anywhere you
see `mandrake`!

`mandrake` has two modes, implemented as subcommnds - either `code` or `elf`.
You can run it with `--help` to see the full options, including for the
subcommands:

```
$ mandrake --help
$ mandrake code --help
$ mandrake elf --help
```

## Analyzing Raw Code

To use `mandrake` to analyze raw machine code, you need two things:

* The `harness` executable - you'll get this when you check out the codebase, but you can also get it [directly from Github](https://github.com/CounterHack/mandrake/blob/main/harness/harness)
* The hex-encoded machine code

How you get hex-encoded machine code is sort of up to you, but if you want
something simple to test, try `c3` (`ret`) or `4831c048ffc0c3`
(`xor rax, rax` / `inc rax` / `ret`) - aka, `return 1`.

Here is an example:

```
$ mandrake --snippit-length 4 code 'c3'

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
$ mandrake --snippit-length 4 code --harness=./harness/harness '4831c048ffc0c3'

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
$ mandrake --snippit-length 4 code --harness=./harness/harness '6841414141c3'
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
$ mandrake --snippit-length 4 code 'e80d00000048656c6c6f20576f726c64210048c7c00100000048c7c7010000005e48c7c20c0000000f05c3'
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

## Analyzing Elf Files

In addition to raw shellcode, we can also instrument an ELF (Linux) binary! We
haven't used ELF binaries as much as shellcode, so this isn't as well tested
and hardy. Your mileage may vary!

The biggest thing to know is that, in an ELF binary, there's gonna be A LOT
more junk, potentially, especially if you call out to libc functions. It might
also run REALLLLY slow if you trace through all the libc stuff.

To initially trigger the logger, put an `int 3` instruction in front of the
code that you want to instrument. I don't love doing it that way, but otherwise
it takes a LONG time to run.

To turn the debugger back off again, put an `int 3` AFTER the code that you want
to instrument.

If you have an `int 3` within the code you want to instrument, you're gonna have
a bad time (sorry, I wish I could think of a better way!)

Here's an example of something you might want to instrument:

```
$ cat demo.c
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
  int i = 0;
  char buffer[16];

  asm("int 3");

  asm("nop");
  asm("nop");
  asm("nop");

  asm("int 3");

  return 0;
}

$ gcc -o demo -O0 -masm=intel --no-pie demo.c
```

When you execute it in mandrake, you will see the three `nop` instructions:

```
$ mandrake --snippit-length 4 elf ./demo
{
  "success": true,
  "pid": 1121316,
  "history": [
    {
      "rip": {
        "value": 93824992235867,
        "memory": [
          144
        ],
        "as_instruction": "nop",
        "as_string": null
      }
[...]
```

But if there are libc calls, things can get a bit big! Here's another example:

```
$ cat demo2.c
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
  int i = 0;
  char buffer[16];

  asm("int 3");
  asm("nop");

  strcpy(buffer, argv[1]);
  printf("%s\n", buffer);

  asm("nop");
  asm("int 3");

  return 0;
}

$ gcc -o demo2 -O0 -masm=intel --no-pie demo2.c
```

If we try to instrument that, we quickly run into our execution cap:

```
$ mandrake --snippit-length 4 elf ./demo2 abc

[...]
"exit_reason": "Execution stopped at instruction cap (max instructions: 128)",
```

We can raise that, but we end up with a whole lot of output:

```
$ mandrake --max-instructions 10000 --snippit-length 4 elf ./demo2 abc
[...]
{
  "instructions_executed": 3209,
  "success": true,
```

Maybe you're okay with looking through 3209 instructions, but I sure don't
want to!

The best you can do is probably to turn off ASLR, then filter down to simply
the binary you want to see. Here's how I do that:

To do that, ensure your binary is compiled with `--no-pie`, then turn off ASLR,
execute it, and have a look at the starting address:

```
$ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
$ mandrake --max-instructions 1 --snippit-length 4 elf ./demo2 abc
[...]
{
  "starting_address": 93824992235899,
  "instructions_executed": 1,
```

That value is `0x55555555517b` in hex. It might vary for you, so don't use
this command directly if you're following along!

By default, `mandrake` masks out the last 4 nibbles, meaning effectively the
address is 0x555555550000 when compared. The mask can be changed with
`--hidden-mask` if you want, but we don't need to:

```
$ mandrake --output-format=json --snippit-length 4 elf ./demo2 --visible-address 0x0000555555550000
[...]
{
  "starting_address": 93824992235899,
  "instructions_executed": 13,
  "success": true,
[...]
```

Much better!

## What do I do with all that JSON?

Well, you can also output with `--output-format=YAML`. :)

We can actually support any type that [Serde](https://serde.rs/) supports,
please file a bug or send a patch if you'd like Pickle or something.

<Edit: I added `--output-format=PICKLE`>

But to answer the question.. I dunno! At Counter Hack, we wrapped a web
interface around it to teach shellcoding. I bet there are a lot more cool
things you can do, though, use your imagination!

# Build

If you have the Rust toolchain (`cargo`), you don't really need to build it!
It'll automatically build when you `cargo run`.

But if you don't want to install `cargo`, fear not! You can just run `make` in
the root folder, and it should build you a binary release using a Docker
environment (requires Docker).

The build files are copies into the build/ folder when complete.

# Appendix: Usage

This is just the output of `--help`. Be warned - I might forget to update this,
run the actual application for up-to-date help!

```
$ mandrake --help
Mandrake 0.1.0
Ron Bowes <ron@counterhack.com>
Mandrake is an open-source machine code analyzer / instrumenter written in Rust

USAGE:
    mandrake [OPTIONS] <SUBCOMMAND>

OPTIONS:
    -h, --help
            Print help information

    -i, --max-instructions <MAX_INSTRUCTIONS>
            The maximum number of instructions to read before stopping (to prevent infinite loops)
            [default: 128]

        --ignore-stderr
            Don't save output from stderr

        --ignore-stdout
            Don't save output from stdout

    -m, --minimum-viable-string <MINIMUM_VIABLE_STRING>
            The number of consecutive ASCII bytes to be considered a string [default: 6]

    -o, --output-format <OUTPUT_FORMAT>
            The output format ("JSON", "YAML", or "Pickle") [default: JSON]

    -s, --snippit-length <SNIPPIT_LENGTH>
            The amount of context memory to read [default: 64]

    -V, --version
            Print version information

SUBCOMMANDS:
    code    Analyze raw machine code using a harness
    elf     Analyze an ELF file (Linux executable)
    help    Print this message or the help of the given subcommand(s)
```

```
$ mandrake code --help
mandrake-code 0.1.0
Ron Bowes <ron@counterhack.com>
Analyze raw machine code using a harness

USAGE:
    mandrake code [OPTIONS] <CODE>

ARGS:
    <CODE>    The code, as a hex string (eg: "4831C0C3")

OPTIONS:
    -h, --help                 Print help information
        --harness <HARNESS>    The path to the required harness [default: ./harness/harness]
    -V, --version              Print version information
```

```
$ mandrake elf --help
mandrake-elf 0.1.0
Ron Bowes <ron@counterhack.com>
Analyze an ELF file (Linux executable)

USAGE:
    mandrake elf [OPTIONS] <ELF> [ARGS]...

ARGS:
    <ELF>        The ELF executable
    <ARGS>...    The argument(s) to pass to the ELF executable

OPTIONS:
    -h, --help
            Print help information

        --hidden-address <HIDDEN_ADDRESS>
            Hide instructions that match this address (ANDed with the --hidden-mask)

        --hidden-mask <HIDDEN_MASK>
            ANDed with the --hidden-address before comparing - by default, 0xFFFFFFFFFFFF0000

    -V, --version
            Print version information

        --visible-address <VISIBLE_ADDRESS>
            Only show instructions that match this address (ANDed with the --visible-mask)

        --visible-mask <VISIBLE_MASK>
            ANDed with the --visible-address before comparing - by default, 0xFFFFFFFFFFFF0000
```
