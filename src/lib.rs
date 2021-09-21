use std::fmt;
use std::io::prelude::*;
use std::process::{exit, Command, Stdio};

use byteorder::{LittleEndian, WriteBytesExt};
use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};
use nix::sys::ptrace::{getregs, read, AddressType, step, cont, kill};
use nix::sys::signal::Signal;
use nix::sys::wait::{wait, WaitStatus};
use nix::unistd::Pid;
use serde::{Serialize, Deserialize};
use simple_error::{bail, SimpleResult};
use spawn_ptrace::CommandPtraceSpawn;


// The number of bytes to read when analyzing memory
const SNIPPIT_LENGTH: usize = 32;
const MINIMUM_VIABLE_STRING: usize = 6;
//const MAX_INSTRUCTIONS: usize = 128; // TODO: This is too short

// These let us have "hidden" addresses that don't show up in execution logs
const HIDDEN_ADDR: u64 = 0x12120000;
const HIDDEN_MASK: u64 = 0xFFFF0000;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct AnalyzedPointer {
    // The memory - 128-bits of it, which seems like enough
    // We use this instead of a numeric value because we wouldn't know how many bits of the value to use
    memory: Vec<u8>,

    // The decoded instruction, if possible
    as_instruction: Option<String>,

    // A decoded string (UTF-8), if possible
    as_string: Option<String>,
}

impl AnalyzedPointer {
    fn from_memory(pid: Pid, addr: usize, truncate_to_code: bool) -> Option<Self> {
        let mut data: Vec<u8> = vec![];

        // This reads just enough data to get the proper length
        for i in 0..((SNIPPIT_LENGTH + 7) / 8) {
            let this_chunk = match read(pid, (addr + (i * 8)) as AddressType) {
                Ok(chunk) => chunk,
                // If the memory isn't readable, just return None
                Err(_e) => return None,
            };

            // I don't think this can actually fail
            data.write_i64::<LittleEndian>(this_chunk).unwrap();
        }

        // Truncate it to the actual size they asked for
        data.truncate(SNIPPIT_LENGTH);

        // Try and decode from assembly
        let mut decoder = Decoder::with_ip(64, &data, addr as u64, DecoderOptions::NONE);
        let as_instruction = match decoder.can_decode() {
            true => {
                let mut output = String::new();
                let decoded = decoder.decode();

                if truncate_to_code {
                    data.truncate(decoded.len());
                }
                NasmFormatter::new().format(&decoded, &mut output);

                if output == "(bad)" {
                    None
                } else {
                    Some(output)
                }
            }
            false => None,
        };

        // Try and interpret as a string
        let string_data: Vec<u8> = data.clone().into_iter().take_while(|d| *d != 0).collect();
        let as_string = match std::str::from_utf8(&string_data) {
            Ok(s)  => {
                if s.len() > MINIMUM_VIABLE_STRING {
                    Some(s.to_string())
                } else {
                    None
                }
            },
            Err(_) => None,
        };

        Some(AnalyzedPointer {
            memory: Vec::new(),//data,
            as_instruction: as_instruction,
            as_string: as_string,
        })
    }
}

impl fmt::Display for AnalyzedPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let data: Vec<String> = self.memory.iter().map(|b| format!("{:02x}", b)).collect();

        write!(f, "{}", data.join(" "))?;

        if let Some(s) = &self.as_string {
            write!(f, " (\"{}\")", s)?;
        }

        if let Some(i) = &self.as_instruction {
            write!(f, " ({})", i)?;
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct AnalyzedValue {
    // The actual value
    value: u64,

    // If it's a pointer, this is information about what it's pointing to
    target: Option<AnalyzedPointer>,
}

impl AnalyzedValue {
    fn from_u64(n: u64, pid: Pid, truncate_to_code: bool) -> Self {
        AnalyzedValue {
            value: n,
            target: AnalyzedPointer::from_memory(pid, n as usize, truncate_to_code),
        }
    }
}

impl fmt::Display for AnalyzedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.target {
            Some(t) => write!(f, "{:x} ({})", self.value, t)?,
            None => write!(f, "{:x}", self.value)?,
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Regs {
    rip: AnalyzedValue,
    rax: AnalyzedValue,
    rbx: AnalyzedValue,
    rcx: AnalyzedValue,
    rdx: AnalyzedValue,
    rsi: AnalyzedValue,
    rdi: AnalyzedValue,
    rbp: AnalyzedValue,
    rsp: AnalyzedValue,
}

impl Regs {
    fn from_pid(pid: Pid) -> SimpleResult<Regs> {
        // Try and get the registers
        let regs = match getregs(pid) {
            Ok(r) => r,
            Err(e) => bail!("Couldn't read registers: {}", e),
        };

        // Analyze and save each one
        Ok(Regs {
            rip: AnalyzedValue::from_u64(regs.rip, pid, true),
            rax: AnalyzedValue::from_u64(regs.rax, pid, false),
            rbx: AnalyzedValue::from_u64(regs.rbx, pid, false),
            rcx: AnalyzedValue::from_u64(regs.rcx, pid, false),
            rdx: AnalyzedValue::from_u64(regs.rdx, pid, false),
            rsi: AnalyzedValue::from_u64(regs.rsi, pid, false),
            rdi: AnalyzedValue::from_u64(regs.rdi, pid, false),
            rbp: AnalyzedValue::from_u64(regs.rbp, pid, false),
            rsp: AnalyzedValue::from_u64(regs.rsp, pid, false),
        })
    }
}

impl fmt::Display for Regs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let instruction = match &self.rip.target {
            Some(t) => t.to_string(),
            None => "Invalid instruction pointer".to_string(),
        };
        writeln!(f, " rax: {}", self.rax)?;
        writeln!(f, " rbx: {}", self.rbx)?;
        writeln!(f, " rcx: {}", self.rcx)?;
        writeln!(f, " rdx: {}", self.rdx)?;
        writeln!(f, " rsi: {}", self.rsi)?;
        writeln!(f, " rdi: {}", self.rdi)?;
        writeln!(f, " rbp: {}", self.rbp)?;
        writeln!(f, " rsp: {}", self.rsp)?;
        writeln!(f)?;
        writeln!(f, "{:016x} {}", self.rip.value, instruction)?;

        Ok(())
    }
}

// Happy result :)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct State {
    success: bool, // Will always be true
    pid: u32,
    history: Vec<Regs>,
    stdout: Option<String>,
    stderr: Option<String>,
    exit_reason: Option<String>,
    exit_code: Option<i32>,
}

impl State {
    fn new(pid: u32) -> Self {
        State {
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

// Sad result :(
#[derive(Serialize, Deserialize, Clone, Debug)]
struct Error {
    success: bool, // Will always be false
    error_message: String,
}

impl Error {
    fn new(message: &str) -> Self {
        Error {
            success: false,
            error_message: message.to_string(),
        }
    }

    fn print(&self) {
        // I'm hoping that the to-json part can't fail
        println!("{}", serde_json::to_string_pretty(self).unwrap());
    }

    fn die(message: &str) -> ! { // Return type '!' means it can't return
        Self::new(message).print();
        exit(1);
    }
}

pub fn instrument_binary(binary_path: &str) -> SimpleResult<State> {
    // This spawns the process and calls waitpid(), so it reaches the first
    // system call (execve)
    let child = Command::new(binary_path)
        //.arg(&temp_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn_ptrace()
        .unwrap_or_else(|e| Error::die(&format!("Could not execute testing harness: {}", e)));

    // Get a pid structure
    let pid = Pid::from_raw(child.id() as i32);

    // Find the first breakpiont
    cont(pid, None).unwrap_or_else(|e| Error::die(&format!("Couldn't resume execution: {}", e)));
    //wait().unwrap_or_else(|e| Error::die(&format!("Failed while waiting for process to resume: {}", e)));

    // Step over it - this will perform the call() and move us to the start of
    // the user's code
    //step(pid, None).unwrap_or_else(|e| Error::die(&format!("Failed to step into the code: {}", e)));

    // Build a state then loop, one instruction at a time, till this ends
    let mut state = State::new(child.id());
    loop {
        match wait() {
            Ok(WaitStatus::Exited(_, code)) => {
                state.exit_reason = Some(format!("Process exited cleanly with exit code {}", code));
                state.exit_code = Some(code);
                break;
            }
            Ok(WaitStatus::Stopped(_, sig)) => {
                // Get rip when it crashes
                let regs = Regs::from_pid(pid).unwrap_or_else(|e| Error::die(&format!("Couldn't read registers: {}", e)));
                let rip = regs.rip.value;


                match sig {
                    // Do nothing, this is the happy call
                    Signal::SIGTRAP => {
                        // Get the current state
                        let regs = Regs::from_pid(pid).unwrap_or_else(|e| Error::die(&format!("Couldn't read registers: {}", e)));

                        // No matter what, step past the instruction
                        step(pid, None).unwrap_or_else(|e| Error::die(&format!("Couldn't step through code: {}", e)));

                        // If we get an int3, it means we want to stop logging (ie, continue)
                        if let Some(pointer) = &regs.rip.target {
                            if let Some(instruction) = &pointer.as_instruction {
                                if instruction == "int3" {
                                    // Waiting for the step() to finish before continuing is important
                                    wait().unwrap_or_else(|e| Error::die(&format!("Couldn't step over breakpoint: {}", e)));
                                    cont(pid, None).unwrap_or_else(|e| Error::die(&format!("Couldn't resume execution after breakpoint: {}", e)));
                                    continue;
                                }
                            }
                        }

                        // Since it's not an int3 instruction, we need to log and step
                        //if(regs.rip.value & HIDDEN_MASK) != HIDDEN_ADDR {
                        state.history.push(regs);
                        //}

                        continue;
                    },

                    // Check for the special timeout symbol (since we set alarm() in the harness)
                    Signal::SIGALRM => { state.exit_reason = Some(format!("Execution timed out (SIGALRM) @ 0x{:08x}", rip)); break; },

                    // Try and catch other obvious problems
                    Signal::SIGABRT => { state.exit_reason = Some(format!("Execution crashed with an abort (SIGABRT) @ 0x{:08x}", rip)); break; }
                    Signal::SIGBUS => { state.exit_reason = Some(format!("Execution crashed with a bus error (bad memory access) (SIGBUS) @ 0x{:08x}", rip)); break; }
                    Signal::SIGFPE => { state.exit_reason = Some(format!("Execution crashed with a floating point error (SIGFPE) @ 0x{:08x}", rip)); break; }
                    Signal::SIGILL => { state.exit_reason = Some(format!("Execution crashed with an illegal instruction (SIGILL) @ 0x{:08x}", rip)); break; },
                    Signal::SIGKILL => { state.exit_reason = Some(format!("Execution was killed (SIGKILL) @ 0x{:08x}", rip)); break; },
                    Signal::SIGSEGV => { state.exit_reason = Some(format!("Execution crashed with a segmentation fault (SIGSEGV) @ 0x{:08x}", rip)); break; },
                    Signal::SIGTERM => { state.exit_reason = Some(format!("Execution was terminated (SIGTERM) @ 0x{:08x}", rip)); break; },

                    _ => { state.exit_reason = Some(format!("Execution stopped by unexpected signal: {}", sig)); break; }
                };

            },
            Ok(s) => Error::die(&format!("Unexpected stop reason: {:?}", s)),
            Err(e) => Error::die(&format!("Unexpected wait() error: {:?}", e)),
        };

//if state.history.len() > MAX_INSTRUCTIONS {
//    state.exit_reason = Some(format!("Execution stopped at instruction cap (max instructions: {})", MAX_INSTRUCTIONS));
//    break;
//}
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
    let mut stdout: Vec<u8> = vec![];
    child.stdout
        .unwrap_or_else(|| Error::die(&format!("Couldn't get a handle to stdout")))
        .read_to_end(&mut stdout)
        .unwrap_or_else(|e| Error::die(&format!("Failed while trying to read stdout: {}", e)));

    state.stdout = Some(String::from_utf8_lossy(&stdout).to_string());

    let mut stderr: Vec<u8> = vec![];
    child.stderr
        .unwrap_or_else(|| Error::die(&format!("Couldn't get a handle to stderr")))
        .read_to_end(&mut stderr)
        .unwrap_or_else(|e| Error::die(&format!("Failed while trying to read stderr: {}", e)));
    state.stderr = Some(String::from_utf8_lossy(&stderr).to_string());

    // Send the json to stdout
    println!("{}", serde_json::to_string_pretty(&state).unwrap());

    Ok(state)
}

