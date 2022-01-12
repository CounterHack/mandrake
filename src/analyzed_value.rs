//! Reads a block of memory and translates it into something useful.
//!
//! Always, we store the [`u64`] value. Then we try to read the memory pointed
//! at by it. We store some amount of memory based on what the caller wants,
//! then try to parse it either as an instruction or a string. That may or
//! may not work, and it may or may not produce valid output - we do what we
//! can!
use std::fmt;

use byteorder::{LittleEndian, WriteBytesExt};
use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};
use nix::sys::ptrace::{read, AddressType};
use nix::unistd::Pid;
use serde::{Serialize, Deserialize};

// We initially read this much so we can look for strings and code
const INITIAL_SNIPPIT_LENGTH: usize = 128;

/// A serializable, analyzed value.
///
/// Be careful changing this! Things that consume Mandrake's output depend on
/// the structure not changing.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AnalyzedValue {
    // The value
    pub value: u64,

    // The memory as a stream of bytes
    pub memory: Option<Vec<u8>>,

    // The decoded instruction, if possible
    pub as_instruction: Option<String>,

    // A decoded string (UTF-8), if possible
    pub as_string: Option<String>,
}

impl AnalyzedValue {
    pub fn new(pid: Pid, value: u64, is_instruction_pointer: bool, snippit_length: usize, minimum_viable_string: usize) -> Self {
        // Figure out the longest value we need
        let bytes_to_get: usize = std::cmp::max(INITIAL_SNIPPIT_LENGTH, snippit_length);

        let mut data = match Self::get_memory(pid, value, bytes_to_get) {
            Some(data) => data,
            None => {
                // If we can't get memory, just return the value
                return AnalyzedValue {
                    value: value,
                    memory: None,
                    as_instruction: None,
                    as_string: None,
                };
            }
        };

        // Try and decode from assembly - decode with the full data length
        let mut decoder = Decoder::with_ip(64, &data, value as u64, DecoderOptions::NONE);
        let as_instruction = match decoder.can_decode() {
            true => {
                let mut output = String::new();
                let decoded = decoder.decode();

                if is_instruction_pointer {
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

        // Try and interpret as a string - this is also done with the full-length value
        let string_data: Vec<u8> = data.clone().into_iter().take_while(|d| *d != 0).collect();
        let as_string = match std::str::from_utf8(&string_data) {
            Ok(s)  => {
                if s.len() > minimum_viable_string {
                    Some(s.to_string())
                } else {
                    None
                }
            },
            Err(_) => None,
        };

        // Truncate it to the actual size they asked for (after checking for instructions)
        data.truncate(snippit_length);

        Self {
            value: value,
            memory: Some(data),
            as_instruction: as_instruction,
            as_string: as_string,
        }
    }

    fn get_memory(pid: Pid, addr: u64, snippit_length: usize) -> Option<Vec<u8>> {
        let mut data: Vec<u8> = vec![];

        for i in 0..((snippit_length + 7) / 8) {
            let this_chunk = match read(pid, (addr as usize + (i * 8)) as AddressType) {
                Ok(chunk) => chunk,
                // If the memory isn't readable, just return None
                Err(_e) => return None,
            };

            // I don't think this can actually fail
            data.write_i64::<LittleEndian>(this_chunk).unwrap();
        }

        Some(data)
    }

}

impl fmt::Display for AnalyzedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08x}", self.value)
    }
}

