A binary analysis / instrumentation library for Rust.

Basically, this will execute and debug a binary. If that binary runs `int 3` at
any point, it will toggle between tracing and not-tracing. While tracing, every
instruction is logged, along with registers and important memory context.

To compile, locally, use `cargo build` or `cargo run`. To compile for a
container, use `make`, which will build inside Docker.

The important part for execution is that it has to know where the `harness`
binary is. By default, it'll check `./harness/harness`, which works nicely for
dev, less good for prod. In prod, use the environmental variable `HARNESS`:

HARNESS=/bin/harness mandrake
