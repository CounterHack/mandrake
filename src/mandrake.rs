use std::io::prelude::*;
use std::process::{Command, Stdio, Child};
use std::collections::HashMap;
use std::path::Path;

use nix::sys::ptrace::{getregs, step, cont, kill};
use nix::sys::signal::Signal;
use nix::sys::wait::{wait, WaitStatus};
use nix::unistd::Pid;
use simple_error::{bail, SimpleResult, SimpleError};
use spawn_ptrace::CommandPtraceSpawn;

use crate::analyzed_value::AnalyzedValue;
use crate::mandrake_output::MandrakeOutput;
use crate::visibility_configuration::VisibilityConfiguration;

/// Represents the mandrake configuration.
#[derive(Debug)]
pub struct Mandrake {
    snippit_length:          usize,
    minimum_viable_string:   usize,
    max_logged_instructions: Option<usize>,
    capture_stdout:          bool,
    capture_stderr:          bool,
}

impl Mandrake {
    pub fn new(snippit_length: usize, minimum_viable_string: usize, max_logged_instructions: Option<usize>, ignore_stdout: bool, ignore_stderr: bool) -> Self {
        Self {
            snippit_length:          snippit_length,
            minimum_viable_string:   minimum_viable_string,
            max_logged_instructions: max_logged_instructions,
            capture_stdout:          !ignore_stdout,
            capture_stderr:          !ignore_stderr,
        }
    }

    fn go(&self, child: Child, visibility: &VisibilityConfiguration) -> SimpleResult<MandrakeOutput> {
        // Build a state then loop, one instruction at a time, till this ends
        let mut result = MandrakeOutput::new(child.id());
        let pid = Pid::from_raw(child.id() as i32);

        loop {
            match wait() {
                Ok(WaitStatus::Exited(_, code)) => {
                    result.exit_reason = Some(format!("Process exited cleanly with exit code {}", code));
                    result.exit_code = Some(code);
                    break;
                }
                Ok(WaitStatus::Stopped(_, sig)) => {
                    // Get rip when it crashes
                    let regs = self.get_registers_from_pid(pid)
                        .map_err(|e| SimpleError::new(format!("Couldn't read registers: {}", e)))?;

                    // Get the value for RIP, die if it's missing (shouldn't happen)
                    let rip = match regs.get("rip") {
                        Some(rip) => rip,
                        None => bail!("RIP is missing from the register list!"),
                    };

                    match sig {
                        // Do nothing, this is the happy call
                        Signal::SIGTRAP => {
                            // No matter what, step past the instruction
                            step(pid, None)
                                .map_err(|e| SimpleError::new(&format!("Couldn't step through code: {}", e)))?;

                            // If we get an int3, it means we want to stop logging (ie, continue)
                            if let Some(instruction) = &rip.as_instruction {
                                if instruction == "int3" {
                                    // Waiting for the step() to finish before continuing is important
                                    wait()
                                        .map_err(|e| SimpleError::new(&format!("Couldn't step over breakpoint: {}", e)))?;

                                    cont(pid, None)
                                        .map_err(|e| SimpleError::new(&format!("Couldn't resume execution after breakpoint: {}", e)))?;
                                    continue;
                                }
                            }

                            // Count the instructions
                            result.instructions_executed += 1;

                            // Count the actual instructions executed (even if they're invisible)
                            if let Some(max_instructions) = self.max_logged_instructions {
                                if result.instructions_executed >= max_instructions {
                                    result.exit_reason = Some(format!("Execution stopped at instruction cap (max instructions: {})", max_instructions));
                                    break;
                                }
                            }

                            // Check if we're supposed to see this
                            if !visibility.is_visible(rip.value) {
                                continue;
                            }

                            // If we don't have a first address, save the current address
                            if result.starting_address.is_none() {
                                result.starting_address = Some(rip.value);
                            }

                            result.history.push(regs);

                            continue;
                        },

                        // Check for the special timeout symbol (since we set alarm() in the harness)
                        Signal::SIGALRM => { result.exit_reason = Some(format!("Execution timed out (SIGALRM) @ {}", rip)); break; },

                        // Try and catch other obvious problems
                        Signal::SIGABRT => { result.exit_reason = Some(format!("Execution crashed with an abort (SIGABRT) @ {}", rip)); break; }
                        Signal::SIGBUS => { result.exit_reason = Some(format!("Execution crashed with a bus error (bad memory access) (SIGBUS) @ {}", rip)); break; }
                        Signal::SIGFPE => { result.exit_reason = Some(format!("Execution crashed with a floating point error (SIGFPE) @ {}", rip)); break; }
                        Signal::SIGILL => { result.exit_reason = Some(format!("Execution crashed with an illegal instruction (SIGILL) @ {}", rip)); break; },
                        Signal::SIGKILL => { result.exit_reason = Some(format!("Execution was killed (SIGKILL) @ {}", rip)); break; },
                        Signal::SIGSEGV => { result.exit_reason = Some(format!("Execution crashed with a segmentation fault (SIGSEGV) @ {}", rip)); break; },
                        Signal::SIGTERM => { result.exit_reason = Some(format!("Execution was terminated (SIGTERM) @ {}", rip)); break; },

                        _ => { result.exit_reason = Some(format!("Execution stopped by unexpected signal: {}", sig)); break; }
                    };

                },
                Ok(s) => bail!("Unexpected stop reason: {:?}", s),
                Err(e) => bail!("Unexpected wait() error: {:?}", e),
            };
        }

        // I don't know why, but this fixes a random timeout that sometimes breaks
        // this :-/
        //
        // As of 2022-01, I have no idea if this is still needed or if the bug
        // this fixed is long-gone, but I'm too afraid to try because the bug
        // was always sporadic :)
        println!("");

        // Whatever situation we're in, we need to make sure the process is dead
        // (We discard errors here, because we don't really care if it was already
        // killed or failed to kill or whatever)
        match kill(pid) {
            Ok(_) => (),
            Err(_) => (),
        };

        // If we made it here, grab the stdout + stderr
        if self.capture_stdout {
            let mut stdout: Vec<u8> = vec![];
            child.stdout
                .ok_or_else(|| SimpleError::new(format!("Couldn't get a handle to stdout")))?
                .read_to_end(&mut stdout)
                .map_err(|e| SimpleError::new(format!("Failed while trying to read stdout: {}", e)))?;

            result.stdout = Some(String::from_utf8_lossy(&stdout).to_string());
        }

        if self.capture_stderr {
            let mut stderr: Vec<u8> = vec![];
            child.stderr
                .ok_or_else(|| SimpleError::new(format!("Couldn't get a handle to stderr")))?
                .read_to_end(&mut stderr)
                .map_err(|e| SimpleError::new(format!("Failed while trying to read stderr: {}", e)))?;
            result.stderr = Some(String::from_utf8_lossy(&stderr).to_string());
        }

        Ok(result)
    }

    fn get_registers_from_pid(&self, pid: Pid) -> SimpleResult<HashMap<String, AnalyzedValue>> {
        // Try and get the registers
        let regs = match getregs(pid) {
            Ok(r) => r,
            Err(e) => bail!("Couldn't read registers: {}", e),
        };

        // Analyze and save each one
        let mut out: HashMap<String, AnalyzedValue> = vec![
            ("rip".to_string(), AnalyzedValue::new(pid, regs.rip, true,  self.snippit_length, self.minimum_viable_string)),
            ("rax".to_string(), AnalyzedValue::new(pid, regs.rax, false, self.snippit_length, self.minimum_viable_string)),
            ("rbx".to_string(), AnalyzedValue::new(pid, regs.rbx, false, self.snippit_length, self.minimum_viable_string)),
            ("rcx".to_string(), AnalyzedValue::new(pid, regs.rcx, false, self.snippit_length, self.minimum_viable_string)),
            ("rdx".to_string(), AnalyzedValue::new(pid, regs.rdx, false, self.snippit_length, self.minimum_viable_string)),
            ("rsi".to_string(), AnalyzedValue::new(pid, regs.rsi, false, self.snippit_length, self.minimum_viable_string)),
            ("rdi".to_string(), AnalyzedValue::new(pid, regs.rdi, false, self.snippit_length, self.minimum_viable_string)),
            ("rbp".to_string(), AnalyzedValue::new(pid, regs.rbp, false, self.snippit_length, self.minimum_viable_string)),
            ("rsp".to_string(), AnalyzedValue::new(pid, regs.rsp, false, self.snippit_length, self.minimum_viable_string)),
        ].into_iter().collect();

        // Handle special instructions
        if let Some(rip) = &out.get("rip") {
            if let Some(instruction) = &rip.as_instruction {
                if instruction == "syscall" {
                    // Load + clone registers before getting a mutable instance of
                    // rip (Rust smartly doesn't let us read and write a variable
                    // at the same time!)
                    let rax = out.get("rax").ok_or_else(|| SimpleError::new(format!("Could not read value of rax")))?.clone();
                    let rdi = out.get("rdi").ok_or_else(|| SimpleError::new(format!("Could not read value of rdi")))?.clone();
                    let rsi = out.get("rsi").ok_or_else(|| SimpleError::new(format!("Could not read value of rsi")))?.clone();
                    let rdx = out.get("rdx").ok_or_else(|| SimpleError::new(format!("Could not read value of rdx")))?.clone();

                    // This gets a mutable handle to `out` - that means we can't
                    // read from `out` within this block!
                    out.get_mut("rip").map(|rip| {
                        rip.extra = Some(AnalyzedValue::syscall_info(&rax, &rdi, &rsi, &rdx));
                    });
                }
            }
        }

        Ok(out)
    }

    pub fn analyze_code(&self, code: Vec<u8>, harness_path: &Path, show_everything: bool) -> SimpleResult<MandrakeOutput> {
        if !harness_path.exists() {
            bail!("Could not find the execution harness: {:?} - use --harness to specify the path to the 'harness' executable (which is available on https://github.com/counterhack)", harness_path);
        }

        let child = Command::new(harness_path)
            .arg(hex::encode(code))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn_ptrace()
            .map_err(|e| SimpleError::new(format!("Could not execute testing harness: {}", e)))?;

        // Get a pid structure
        let pid = Pid::from_raw(child.id() as i32);

        // Find the first breakpiont
        cont(pid, None).map_err(|e| SimpleError::new(format!("Couldn't resume execution: {}", e)))?;
        wait().map_err(|e| SimpleError::new(format!("Failed while waiting for process to resume: {}", e)))?;

        // Step over it - this will perform the call() and move us to the start of
        // the user's code
        step(pid, None).map_err(|e| SimpleError::new(format!("Failed to stop into the shellcode: {}", e)))?;

        // At this point, we can proceed to normal analysis
        match show_everything {
            false => self.go(child, &VisibilityConfiguration::full_visibility()),
            true  => self.go(child, &VisibilityConfiguration::harness_visibility()),
        }
    }

    pub fn analyze_elf(&self, binary: &Path, stdin: Option<String>, args: Vec<String>, visibility: &VisibilityConfiguration) -> SimpleResult<MandrakeOutput> {
        // Decode the stdin before starting the command, so we don't start the
        // process if the stdin is badly encoded
        let stdin = match stdin {
            Some(stdin) => Some(hex::decode(stdin).map_err(|e| SimpleError::new(format!("Could not parse --stdin-data as a hex string: {}", e)))?),
            None => None,
        };

        // This spawns the process and calls waitpid(), so it reaches the first
        // system call (execve)
        let mut command = Command::new(binary);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        match stdin {
            // If there's a stdin, use it
            Some(_) => command.stdin(Stdio::piped()),
            // If there's no stdin, close it
            None => command.stdin(Stdio::null()),
        };

        for arg in args {
            command.arg(arg);
        }

        let mut child = command.spawn_ptrace()
            .map_err(|e| SimpleError::new(format!("Could not execute testing harness: {}", e)))?;

        if let Some(stdin) = stdin {
            child.stdin.take()
                .ok_or_else(|| SimpleError::new(format!("Couldn't get a handle to stdin")))?
                .write_all(&stdin)
                .map_err(|e| SimpleError::new(format!("Failed while trying to write to stdin: {}", e)))?;
        }

        // Find the first breakpiont
        let pid = Pid::from_raw(child.id() as i32);
        cont(pid, None)
            .map_err(|e| SimpleError::new(format!("Couldn't resume execution: {}", e)))?;

        self.go(child, visibility)
    }
}
