A binary analysis / instrumentation library for Rust.

Basically, this will execute and debug a binary. If that binary runs `int 3` at
any point, it will toggle between tracing and not-tracing. While tracing, every
instruction is logged, along with registers and important memory context.
