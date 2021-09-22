use std::fmt;
use std::collections::HashMap;

use byteorder::{LittleEndian, WriteBytesExt};
use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};
use nix::sys::ptrace::{getregs, read, AddressType};
use nix::unistd::Pid;
use serde::{Serialize, Deserialize};
use simple_error::{bail, SimpleResult};

const SNIPPIT_LENGTH: u64 = 32;
const MINIMUM_VIABLE_STRING: usize = 6;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum AnalyzedValue {
    Constant(u64),
    Pointer(Pointer),
}

impl AnalyzedValue {
    // is_instruction will truncate the data to exactly the length of a single instruction (if possible)
    pub fn new(pid: Pid, value: u64, is_instruction: bool) -> Self {
        // Try and get a pointer
        match Pointer::from_memory(pid, value, is_instruction) {
            Some(p) => AnalyzedValue::Pointer(p),
            None => AnalyzedValue::Constant(value),
        }
    }

    pub fn value(&self) -> u64 {
        match self {
            Self::Constant(v) => *v,
            Self::Pointer(p) => p.value,
        }
    }
}

impl fmt::Display for AnalyzedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Constant(c) => write!(f, "0x{}", c),
            Self::Pointer(p) => write!(f, "{}", p.to_string()),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Pointer {
    // The value
    pub value: u64,

    // The memory as a stream of bytes
    pub memory: Vec<u8>,

    // The decoded instruction, if possible
    pub as_instruction: Option<String>,

    // A decoded string (UTF-8), if possible
    pub as_string: Option<String>,
}

impl Pointer {
    fn from_memory(pid: Pid, addr: u64, exactly_one_instruction: bool) -> Option<Self> {
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
        data.truncate(SNIPPIT_LENGTH as usize);

        // Try and decode from assembly
        let mut decoder = Decoder::with_ip(64, &data, addr as u64, DecoderOptions::NONE);
        let as_instruction = match decoder.can_decode() {
            true => {
                let mut output = String::new();
                let decoded = decoder.decode();

                if exactly_one_instruction {
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

        Some(Pointer {
            value: addr,
            memory: Vec::new(),//data,
            as_instruction: as_instruction,
            as_string: as_string,
        })
    }
}

impl fmt::Display for Pointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let data: Vec<String> = self.memory.iter().map(|b| format!("{:02x}", b)).collect();

        write!(f, "0x{:08x}", self.value)?;

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

pub fn get_registers_from_pid(pid: Pid) -> SimpleResult<HashMap<String, AnalyzedValue>> {
    // Try and get the registers
    let regs = match getregs(pid) {
        Ok(r) => r,
        Err(e) => bail!("Couldn't read registers: {}", e),
    };

    // Analyze and save each one
    Ok(vec![
        ("rip".to_string(), AnalyzedValue::new(pid, regs.rip, true)),
        ("rax".to_string(), AnalyzedValue::new(pid, regs.rax, false)),
        ("rbx".to_string(), AnalyzedValue::new(pid, regs.rbx, false)),
        ("rcx".to_string(), AnalyzedValue::new(pid, regs.rcx, false)),
        ("rdx".to_string(), AnalyzedValue::new(pid, regs.rdx, false)),
        ("rsi".to_string(), AnalyzedValue::new(pid, regs.rsi, false)),
        ("rdi".to_string(), AnalyzedValue::new(pid, regs.rdi, false)),
        ("rbp".to_string(), AnalyzedValue::new(pid, regs.rbp, false)),
        ("rsp".to_string(), AnalyzedValue::new(pid, regs.rsp, false)),
    ].into_iter().collect())
}
