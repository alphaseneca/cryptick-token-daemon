//! Batch script execution runner for `ykman script`.
//!
//! Executes a file containing lines of ykman commands in sequence,
//! supporting comments (`#`), whitespace, quotes, and positional parameter substitution.

use std::fs;
use std::io::{self, BufRead};

/// Splits a command-line string into tokens, respecting single and double quotes.
pub fn tokenize_line(line: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escaped = false;

    for c in line.chars() {
        if escaped {
            current.push(c);
            escaped = false;
            continue;
        }

        match c {
            '\\' if !in_single_quote => {
                escaped = true;
            }
            '\'' if !in_double_quote => {
                in_single_quote = !in_single_quote;
            }
            '"' if !in_single_quote => {
                in_double_quote = !in_double_quote;
            }
            c if c.is_whitespace() && !in_single_quote && !in_double_quote => {
                if !current.is_empty() {
                    tokens.push(current);
                    current = String::new();
                }
            }
            _ => {
                current.push(c);
            }
        }
    }

    if in_single_quote || in_double_quote {
        return Err("Unmatched quote in command line".to_string());
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    Ok(tokens)
}

/// Substitutes positional `$1`, `$2`, etc. parameters in a command string.
pub fn substitute_args(line: &str, args: &[String]) -> String {
    let mut res = line.to_string();
    for (i, arg) in args.iter().enumerate() {
        let pattern = format!("${}", i + 1);
        res = res.replace(&pattern, arg);
    }
    res
}

/// Reads lines from a file or standard input.
pub fn read_script_lines(path: &str) -> Result<Vec<String>, String> {
    if path == "-" {
        let stdin = io::stdin();
        let lines: Vec<String> = stdin.lock().lines().filter_map(|l| l.ok()).collect();
        Ok(lines)
    } else {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read script file '{path}': {e}"))?;
        Ok(content.lines().map(|s| s.to_string()).collect())
    }
}
