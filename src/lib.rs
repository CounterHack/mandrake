use std::io::prelude::*;
use std::process::{Command, Stdio, Child};
use std::collections::HashMap;
use std::path::Path;

use nix::sys::ptrace::{step, cont, kill};
use nix::sys::signal::Signal;
use nix::sys::wait::{wait, WaitStatus};
use nix::unistd::Pid;
use serde::{Serialize, Deserialize};
use simple_error::{bail, SimpleResult, SimpleError};
use spawn_ptrace::CommandPtraceSpawn;

mod analyzed_value;
use analyzed_value::*;

// pub const DEFAULT_SNIPPIT_LENGTH: u64 = 64;
pub const DEFAULT_MINIMUM_VIABLE_STRING: u64 = 6;
pub const DEFAULT_HARNESS_PATH: &'static str = "./harness/harness";

// The cap on how many instructions we can run
pub const MAX_INSTRUCTIONS: usize = 128;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MandrakeOutput {
    success: bool, // Will always be true
    pid: u32,
    history: Vec<HashMap<String, AnalyzedValue>>,
    stdout: Option<String>,
    stderr: Option<String>,
    exit_reason: Option<String>,
    exit_code: Option<i32>,
}

impl MandrakeOutput {
    fn new(pid: u32) -> Self {
        MandrakeOutput {
            success: true,
            pid: pid,
            history: vec![],
            stdout: None,
            stderr: None,
            exit_reason: None,
            exit_code: None,
        }
    }

    pub fn print(&self) {
        // I'm hoping that the to-json part can't fail
        println!("{}", serde_json::to_string_pretty(self).unwrap());
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Mandrake {
    // snippit_length: u64,
    minimum_viable_string: u64,
    hidden_address: Option<u64>,
    hidden_mask: Option<u64>,
    visible_address: Option<u64>,
    visible_mask: Option<u64>,
    max_logged_instructions: Option<usize>,
    capture_stdout: bool,
    capture_stderr: bool,
}

impl Mandrake {
    pub fn new() -> Self {
        Mandrake {
            // snippit_length: DEFAULT_SNIPPIT_LENGTH,
            minimum_viable_string: DEFAULT_MINIMUM_VIABLE_STRING,
            visible_address: None,
            visible_mask: None,
            hidden_address: None,
            hidden_mask: None,
            max_logged_instructions: Some(MAX_INSTRUCTIONS),
            capture_stdout: true,
            capture_stderr: true,
        }
    }

    pub fn set_hidden_address(&mut self, address: u64, mask: u64) {
        self.hidden_address = Some(address);
        self.hidden_mask = Some(mask);
    }

    pub fn set_visible_address(&mut self, address: u64, mask: u64) {
        self.visible_address = Some(address);
        self.visible_mask = Some(mask);
    }

    fn go(&self, child: Child) -> SimpleResult<MandrakeOutput> {
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
                    let regs = get_registers_from_pid(pid)
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

                            // Suppress addresses that match the hidden_address / hidden_mask, if set
                            if let Some(hidden_address) = self.hidden_address {
                                if let Some(hidden_mask) = self.hidden_mask {
                                    if (rip.value & hidden_mask) == hidden_address {
                                        continue;
                                    }
                                }
                            }

                            // Suppress addresses that don't match the visible_address / visible_mask
                            if let Some(visible_address) = self.visible_address {
                                if let Some(visible_mask) = self.visible_mask {
                                    if (rip.value & visible_mask) != visible_address {
                                        continue;
                                    }
                                }
                            }

                            result.history.push(regs);

                            if let Some(max_instructions) = self.max_logged_instructions {
                                if result.history.len() > max_instructions {
                                    result.exit_reason = Some(format!("Execution stopped at instruction cap (max instructions: {})", max_instructions));
                                    break;
                                }
                            }

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

    pub fn analyze_code(&self, code: Vec<u8>, harness_path: Option<String>) -> SimpleResult<MandrakeOutput> {
        let harness_path = harness_path.unwrap_or(DEFAULT_HARNESS_PATH.to_string());
        if !Path::new(&harness_path).exists() {
            bail!("Could not find the execution harness: {}", harness_path);
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
        self.go(child)
    }

    pub fn analyze_elf(&self, binary_path: &str, args: Vec<&str>) -> SimpleResult<MandrakeOutput> {
        // This spawns the process and calls waitpid(), so it reaches the first
        // system call (execve)
        let mut command = Command::new(binary_path);
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        for arg in args {
            command.arg(arg);
        }

        let child = command.spawn_ptrace()
            .map_err(|e| SimpleError::new(format!("Could not execute testing harness: {}", e)))?;

        // Find the first breakpiont
        let pid = Pid::from_raw(child.id() as i32);
        cont(pid, None)
            .map_err(|e| SimpleError::new(format!("Couldn't resume execution: {}", e)))?;

        self.go(child)
    }
}
