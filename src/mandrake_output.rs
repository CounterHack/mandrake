///! Just a simple, serializable data structure that represents the output.

use std::collections::HashMap;

use serde::{Serialize, Deserialize};

use crate::analyzed_value::AnalyzedValue;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MandrakeOutput {
    pub success: bool,
    pub pid: u32,
    pub history: Vec<HashMap<String, AnalyzedValue>>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub exit_reason: Option<String>,
    pub exit_code: Option<i32>,
}

impl MandrakeOutput {
    pub fn new(pid: u32) -> Self {
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
