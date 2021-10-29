A binary analysis / instrumentation library for Rust.

Basically, this will execute and debug a binary. If that binary runs `int 3` at
any point, it will toggle between tracing and not-tracing. While tracing, every
instruction is logged, along with registers and important memory context.

To compile, locally, use `cargo build` or `cargo run`. To compile for a
container, use `make`, which will build inside Docker.
