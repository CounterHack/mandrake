use std::collections::HashMap;

use lazy_static::lazy_static;
use regex::Regex;
use simple_error::SimpleError;

/// A single syscall parameter
#[derive(Debug)]
pub struct SyscallEntry {
    pub field_type: String,
    pub is_string: bool,
    pub is_pointer: bool,
    pub field_name: String,
    pub is_array: bool,
}

impl SyscallEntry {
    /// Parse a syscall parameter from a string-based definition
    pub fn new(syscall_param: &str) -> Self {
        // Match with everything before the identifier, then the identifier
                            // type  0+ *  identifier     optional []
        let re = Regex::new(r"^(.*?) (\**)([a-zA-Z0-9_-]*)(\[\])?$").unwrap();

        if let Some(out) = re.captures(syscall_param) {
            let out = SyscallEntry {
                field_type:  out.get(1).unwrap().as_str().to_string(),
                is_string:   out.get(1).unwrap().as_str().contains("char"),
                is_pointer:  out.get(2).unwrap().as_str().contains('*'),
                field_name:  out.get(3).unwrap().as_str().to_string(),
                is_array:    match &out.get(4) {
                    Some(a) => a.as_str() == "[]",
                    None    => false,
                },
            };

            out
        } else {
            panic!("Could not parse syscall parameter: {}", syscall_param);
        }
    }
}

/// Defines a syscall.
///
/// This is populated from the `syscalls.csv` file, which is loaded at compile-
/// time. That file, in turn, is based on Ryan Chapman's blog:
///
/// https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
#[derive(Debug)]
pub struct Syscall {
    pub name: String,
    pub rdi: Option<SyscallEntry>,
    pub rsi: Option<SyscallEntry>,
    pub rdx: Option<SyscallEntry>,
    pub r10: Option<SyscallEntry>,
    pub r8:  Option<SyscallEntry>,
    pub r9:  Option<SyscallEntry>,
}

lazy_static! {
    /// Enumerations comment
    pub static ref SYSCALLS: HashMap<u64, Syscall> = {
        let mut out: HashMap<u64, Syscall> = HashMap::new();

        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(false)
            .flexible(true)
            .from_reader(include_str!("./syscalls.csv").as_bytes());

        for result in rdr.records() {
            let record = result.map_err(|e| {
                SimpleError::new(format!("Couldn't read CSV: {}", e))
            }).unwrap();

            let rax: u64 = record.get(0).ok_or(
                SimpleError::new("Error reading the CSV file")
            ).unwrap().parse().map_err(|e| {
                SimpleError::new(format!("Couldn't parse first CSV field as integer: {}", e))
            }).unwrap();

            if out.contains_key(&rax) {
                panic!("Duplicate key in syscall CSV: {}", rax);
            }

            let syscall = Syscall {
                name: record.get(1).unwrap().to_string(),
                rdi: record.get(2).map(|r| SyscallEntry::new(r)),
                rsi: record.get(3).map(|r| SyscallEntry::new(r)),
                rdx: record.get(4).map(|r| SyscallEntry::new(r)),
                r10: record.get(5).map(|r| SyscallEntry::new(r)),
                r8:  record.get(6).map(|r| SyscallEntry::new(r)),
                r9:  record.get(7).map(|r| SyscallEntry::new(r)),
            };

            out.insert(rax, syscall);
        }

        out
    };
}
