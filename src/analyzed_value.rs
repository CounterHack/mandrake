use std::fmt;

use byteorder::{LittleEndian, WriteBytesExt};
use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};
use nix::sys::ptrace::{read, AddressType};
use nix::unistd::Pid;
use serde::{Serialize, Deserialize};

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
        let mut data = match Self::get_memory(pid, value, snippit_length) {
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

        // Truncate it to the actual size they asked for
        data.truncate(snippit_length as usize);

        // Try and decode from assembly
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

        // Try and interpret as a string
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

